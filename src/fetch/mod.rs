//! Utilities for fetching data from other servers
//!
#![doc = include_str!("../../docs/07_fetching_data.md")]

use crate::{
    config::Data,
    error::{Error, Error::ParseFetchedObject},
    extract_id,
    http_signatures::sign_request,
    reqwest_shim::ResponseExt,
    FEDERATION_CONTENT_TYPE,
};
use bytes::Bytes;
use http::{
    header::{CONTENT_TYPE, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION},
    HeaderMap,
    HeaderValue,
    StatusCode,
};
use serde::de::DeserializeOwned;
use std::sync::atomic::Ordering;
use tracing::info;
use url::Url;

const MAX_ETAG_BYTES: usize = 512;
const MAX_LAST_MODIFIED_BYTES: usize = 128;
const VALID_RESPONSE_CONTENT_TYPES: [&str; 3] = [
    FEDERATION_CONTENT_TYPE,
    r#"application/ld+json; profile="https://www.w3.org/ns/activitystreams""#,
    r#"application/activity+json; charset=utf-8"#,
];

/// Typed wrapper for collection IDs
pub mod collection_id;
/// Typed wrapper for Activitypub Object ID which helps with dereferencing and caching
pub mod object_id;
/// Resolves identifiers of the form `name@example.com`
pub mod webfinger;

/// Validators supplied to a conditional remote-object fetch.
#[derive(Clone, Debug, Default)]
pub struct ConditionalFetchValidators {
    /// Entity tag from the last successful response.
    pub etag: Option<String>,
    /// Last-Modified value from the last successful response.
    pub last_modified: Option<String>,
}

/// Result of fetching a remote object with optional validators.
#[derive(Debug)]
pub enum ConditionalFetchOutcome<Kind> {
    /// A fresh object was returned and passed the normal fetch safety checks.
    Fetched {
        /// Parsed remote object.
        object: Kind,
        /// Final response URL after a validated redirect.
        url: Url,
        /// Bounded ETag returned by the remote server.
        etag: Option<String>,
        /// Bounded Last-Modified value returned by the remote server.
        last_modified: Option<String>,
    },
    /// The remote object has not changed.
    NotModified {
        /// Final response URL after a validated redirect.
        url: Url,
        /// Bounded ETag returned by the remote server.
        etag: Option<String>,
        /// Bounded Last-Modified value returned by the remote server.
        last_modified: Option<String>,
    },
    /// The remote server reports that the object is permanently gone.
    Gone {
        /// Final response URL after a validated redirect.
        url: Url,
    },
}

#[derive(Default)]
struct ConditionalRequestHeaders {
    etag: Option<HeaderValue>,
    last_modified: Option<HeaderValue>,
}

impl TryFrom<&ConditionalFetchValidators> for ConditionalRequestHeaders {
    type Error = Error;

    fn try_from(validators: &ConditionalFetchValidators) -> Result<Self, Self::Error> {
        Ok(Self {
            etag: validators
                .etag
                .as_deref()
                .map(|value| validator_header(value, MAX_ETAG_BYTES, "ETag"))
                .transpose()?,
            last_modified: validators
                .last_modified
                .as_deref()
                .map(|value| validator_header(value, MAX_LAST_MODIFIED_BYTES, "Last-Modified"))
                .transpose()?,
        })
    }
}

/// Response from fetching a remote object
pub struct FetchObjectResponse<Kind> {
    /// The resolved object
    pub object: Kind,
    /// Contains the final URL (different from request URL in case of redirect)
    pub url: Url,
    content_type: Option<HeaderValue>,
    object_id: Option<Url>,
}

/// Fetch a remote object over HTTP and convert to `Kind`.
///
/// [crate::fetch::object_id::ObjectId::dereference] wraps this function to add caching and
/// conversion to database type. Only use this function directly in exceptional cases where that
/// behaviour is undesired.
///
/// Every time an object is fetched via HTTP, [RequestData.request_counter] is incremented by one.
/// If the value exceeds [FederationSettings.http_fetch_limit], the request is aborted with
/// [Error::RequestLimit]. This prevents denial of service attacks where an attack triggers
/// infinite, recursive fetching of data.
///
/// The `Accept` header will be set to the content of [`FEDERATION_CONTENT_TYPE`]. When parsing the
/// response it ensures that it has a valid `Content-Type` header as defined by ActivityPub, to
/// prevent security vulnerabilities like [this one](https://github.com/mastodon/mastodon/security/advisories/GHSA-jhrq-qvrm-qr36).
/// Additionally it checks that the `id` field is identical to the fetch URL (after redirects).
pub async fn fetch_object_http<T: Clone, Kind: DeserializeOwned>(
    url: &Url,
    data: &Data<T>,
) -> Result<FetchObjectResponse<Kind>, Error> {
    static FETCH_CONTENT_TYPE: HeaderValue = HeaderValue::from_static(FEDERATION_CONTENT_TYPE);
    let res = fetch_object_http_with_accept(url, data, &FETCH_CONTENT_TYPE, false).await?;
    match validate_activitypub_fetch_response(&res, data).await? {
        Some(object_id) => Box::pin(fetch_object_http(&object_id, data)).await,
        None => Ok(res),
    }
}

/// Fetch a remote object using bounded HTTP validators and the normal object-fetch safety pipeline.
pub async fn fetch_object_http_conditional<T, Kind>(
    url: &Url,
    validators: &ConditionalFetchValidators,
    data: &Data<T>,
) -> Result<ConditionalFetchOutcome<Kind>, Error>
where
    T: Clone,
    Kind: DeserializeOwned,
{
    static FETCH_CONTENT_TYPE: HeaderValue = HeaderValue::from_static(FEDERATION_CONTENT_TYPE);
    let request_headers = ConditionalRequestHeaders::try_from(validators)?;
    let response =
        fetch_http_response(url, data, &FETCH_CONTENT_TYPE, &request_headers, false).await?;
    let response_url = response.url().clone();
    let status = response.status();

    if status == StatusCode::NOT_MODIFIED {
        let (etag, last_modified) = response_validators(response.headers())?;
        return Ok(ConditionalFetchOutcome::NotModified {
            url: response_url,
            etag,
            last_modified,
        });
    }
    if status == StatusCode::GONE {
        return Ok(ConditionalFetchOutcome::Gone { url: response_url });
    }
    if !status.is_success() {
        if let Err(error) = response.error_for_status_ref() {
            return Err(Error::Reqwest(error));
        }
        return Err(Error::Other(format!(
            "Remote fetch returned non-success status {}",
            status.as_u16()
        )));
    }

    let (etag, last_modified) = response_validators(response.headers())?;
    let fetched = parse_fetch_response(response).await?;
    if validate_activitypub_fetch_response(&fetched, data)
        .await?
        .is_some()
    {
        return Err(Error::FetchWrongId(fetched.url));
    }

    Ok(ConditionalFetchOutcome::Fetched {
        object: fetched.object,
        url: fetched.url,
        etag,
        last_modified,
    })
}

/// Fetch a remote object over HTTP and convert to `Kind`. This function works exactly as
/// [`fetch_object_http`] except that the `Accept` header is specified in `content_type`.
async fn fetch_object_http_with_accept<T: Clone, Kind: DeserializeOwned>(
    url: &Url,
    data: &Data<T>,
    content_type: &HeaderValue,
    recursive: bool,
) -> Result<FetchObjectResponse<Kind>, Error> {
    let response = fetch_http_response(
        url,
        data,
        content_type,
        &ConditionalRequestHeaders::default(),
        recursive,
    )
    .await?;
    if response.status() == StatusCode::GONE {
        return Err(Error::ObjectDeleted(response.url().clone()));
    }
    parse_fetch_response(response).await
}

async fn fetch_http_response<T: Clone>(
    url: &Url,
    data: &Data<T>,
    content_type: &HeaderValue,
    conditional_headers: &ConditionalRequestHeaders,
    recursive: bool,
) -> Result<reqwest::Response, Error> {
    let config = &data.config;
    config.verify_url_valid(url).await?;
    info!("Fetching remote object {}", url.to_string());

    let mut counter = data.request_counter.0.fetch_add(1, Ordering::SeqCst);
    // fetch_add returns old value so we need to increment manually here
    counter += 1;
    if counter > config.http_fetch_limit {
        return Err(Error::RequestLimit);
    }

    let mut req = config
        .client
        .get(url.as_str())
        .header("Accept", content_type)
        .timeout(config.request_timeout);
    if let Some(etag) = conditional_headers.etag.as_ref() {
        req = req.header(IF_NONE_MATCH, etag.clone());
    }
    if let Some(last_modified) = conditional_headers.last_modified.as_ref() {
        req = req.header(IF_MODIFIED_SINCE, last_modified.clone());
    }

    let res = if let Some((actor_id, private_key_pem)) = config.signed_fetch_actor.as_deref() {
        let req = sign_request(
            req,
            actor_id,
            Bytes::new(),
            private_key_pem.clone(),
            data.config.http_signature_compat,
        )
        .await?;
        config.client.execute(req).await?
    } else {
        req.send().await?
    };

    // Allow a single redirect using recursion. Further redirects are ignored.
    let location = res.headers().get(LOCATION).and_then(|l| l.to_str().ok());
    if let (Some(location), false) = (location, recursive) {
        let location = location.parse()?;
        return Box::pin(fetch_http_response(
            &location,
            data,
            content_type,
            conditional_headers,
            true,
        ))
        .await;
    }

    Ok(res)
}

async fn parse_fetch_response<Kind: DeserializeOwned>(
    res: reqwest::Response,
) -> Result<FetchObjectResponse<Kind>, Error> {
    let url = res.url().clone();
    let content_type = res.headers().get(CONTENT_TYPE).cloned();
    let text = res.bytes_limited().await?;
    let object_id = extract_id(&text).ok();

    match sonic_rs::from_slice(&text) {
        Ok(object) => Ok(FetchObjectResponse {
            object,
            url,
            content_type,
            object_id,
        }),
        Err(e) => Err(ParseFetchedObject(
            e,
            url,
            String::from_utf8(Vec::from(text))?,
        )),
    }
}

async fn validate_activitypub_fetch_response<T: Clone, Kind>(
    response: &FetchObjectResponse<Kind>,
    data: &Data<T>,
) -> Result<Option<Url>, Error> {
    let content_type = response
        .content_type
        .as_ref()
        .and_then(|value| Some(value.to_str().ok()?.to_lowercase()))
        .ok_or_else(|| Error::FetchInvalidContentType(response.url.clone()))?;
    if !VALID_RESPONSE_CONTENT_TYPES.contains(&content_type.as_str()) {
        return Err(Error::FetchInvalidContentType(response.url.clone()));
    }

    if response.object_id.as_ref() != Some(&response.url) {
        if let Some(object_id) = response.object_id.as_ref() {
            data.config.verify_url_valid(object_id).await?;
            if object_id.domain() == response.url.domain() {
                return Ok(Some(object_id.clone()));
            }
        }
        return Err(Error::FetchWrongId(response.url.clone()));
    }

    if data.config.is_local_url(&response.url) {
        return Err(Error::NotFound);
    }

    Ok(None)
}

fn validator_header(value: &str, max_bytes: usize, name: &str) -> Result<HeaderValue, Error> {
    if value.len() > max_bytes || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(Error::Other(format!("Invalid {name} validator")));
    }
    HeaderValue::try_from(value).map_err(|_| Error::Other(format!("Invalid {name} validator")))
}

fn response_validators(headers: &HeaderMap) -> Result<(Option<String>, Option<String>), Error> {
    Ok((
        response_validator(headers, ETAG.as_str(), MAX_ETAG_BYTES, "ETag")?,
        response_validator(
            headers,
            LAST_MODIFIED.as_str(),
            MAX_LAST_MODIFIED_BYTES,
            "Last-Modified",
        )?,
    ))
}

fn response_validator(
    headers: &HeaderMap,
    header_name: &str,
    max_bytes: usize,
    display_name: &str,
) -> Result<Option<String>, Error> {
    headers
        .get(header_name)
        .map(|value| {
            let value = value
                .to_str()
                .map_err(|_| Error::Other(format!("Invalid {display_name} validator")))?;
            validator_header(value, max_bytes, display_name)?;
            Ok(value.to_string())
        })
        .transpose()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{
        config::FederationConfig,
        traits::tests::{DbConnection, Person, DB_USER},
    };
    use axum::{
        body::Body,
        extract::State,
        http::{header::HOST, Request},
        response::Response,
        routing::get,
        Router,
    };
    use reqwest::{redirect::Policy, Client};
    use reqwest_middleware::ClientWithMiddleware;
    use serde::Deserialize;
    use std::sync::{Arc, Mutex};
    use tokio::{net::TcpListener, task::JoinHandle};

    const REMOTE_HOST: &str = "remote.test";

    #[derive(Clone, Debug)]
    struct ObservedRequest {
        path: String,
        if_none_match: Option<String>,
        if_modified_since: Option<String>,
        signed: bool,
    }

    #[derive(Clone, Default)]
    struct FetchFixtureState {
        requests: Arc<Mutex<Vec<ObservedRequest>>>,
    }

    struct FetchFixture {
        address: std::net::SocketAddr,
        state: FetchFixtureState,
        server: JoinHandle<()>,
    }

    impl FetchFixture {
        async fn start() -> Self {
            let state = FetchFixtureState::default();
            let app = Router::new()
                .fallback(get(fetch_fixture_handler))
                .with_state(state.clone());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                axum::serve(listener, app.into_make_service()).await;
            });
            Self {
                address,
                state,
                server,
            }
        }

        fn url(&self, path: &str) -> Url {
            Url::parse(&format!(
                "http://{REMOTE_HOST}:{}{path}",
                self.address.port()
            ))
            .unwrap()
        }

        fn local_domain(&self) -> String {
            format!("{REMOTE_HOST}:{}", self.address.port())
        }

        fn requests(&self) -> Vec<ObservedRequest> {
            self.state.requests.lock().unwrap().clone()
        }
    }

    impl Drop for FetchFixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    #[derive(Debug, Deserialize)]
    struct ConditionalPerson {
        id: Url,
    }

    async fn fetch_fixture_handler(
        State(state): State<FetchFixtureState>,
        request: Request<Body>,
    ) -> Response {
        let host = request.headers().get(HOST).unwrap().to_str().unwrap();
        let current_url = format!("http://{host}{}", request.uri());
        let path = request.uri().path().to_string();
        state.requests.lock().unwrap().push(ObservedRequest {
            path: path.clone(),
            if_none_match: request
                .headers()
                .get("if-none-match")
                .map(|value| value.to_str().unwrap().to_string()),
            if_modified_since: request
                .headers()
                .get("if-modified-since")
                .map(|value| value.to_str().unwrap().to_string()),
            signed: request.headers().contains_key("signature"),
        });

        if let Some(status) = path.strip_prefix("/status/") {
            return http::Response::builder()
                .status(status.parse::<u16>().unwrap())
                .body(Body::from("status body"))
                .unwrap();
        }

        let valid_body = format!(r#"{{"id":"{current_url}","type":"Person"}}"#);
        let mut response = http::Response::builder();
        let body = match path.as_str() {
            "/not-modified" => {
                response = response
                    .status(StatusCode::NOT_MODIFIED)
                    .header("etag", r#""actor-v2""#)
                    .header("last-modified", "Wed, 15 Jul 2026 11:00:00 GMT");
                "{not-json".to_string()
            }
            "/gone" => {
                response = response.status(StatusCode::GONE);
                String::new()
            }
            "/redirect" => {
                response = response.status(StatusCode::FOUND).header(
                    LOCATION,
                    format!(
                        "http://{REMOTE_HOST}:{}/redirect-target",
                        request
                            .headers()
                            .get(HOST)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .rsplit_once(':')
                            .unwrap()
                            .1
                    ),
                );
                String::new()
            }
            "/unsafe-redirect" => {
                response = response
                    .status(StatusCode::FOUND)
                    .header(LOCATION, "ftp://unsafe.example/actor");
                String::new()
            }
            "/wrong-id" => {
                response = response.header("content-type", FEDERATION_CONTENT_TYPE);
                r#"{"id":"https://different.example/actor","type":"Person"}"#.to_string()
            }
            "/same-domain-wrong-id" => {
                response = response.header("content-type", FEDERATION_CONTENT_TYPE);
                format!(r#"{{"id":"http://{host}/canonical","type":"Person"}}"#)
            }
            "/bad-content-type" => {
                response = response.header("content-type", "text/plain");
                valid_body
            }
            "/large" => {
                response = response.header("content-type", FEDERATION_CONTENT_TYPE);
                "x".repeat(1024 * 1024 + 1)
            }
            "/returned-etag-too-long" => {
                response = response
                    .header("content-type", FEDERATION_CONTENT_TYPE)
                    .header("etag", "x".repeat(513));
                valid_body
            }
            "/returned-last-modified-too-long" => {
                response = response
                    .header("content-type", FEDERATION_CONTENT_TYPE)
                    .header("last-modified", "x".repeat(129));
                valid_body
            }
            "/returned-etag-control" => {
                response = response
                    .header("content-type", FEDERATION_CONTENT_TYPE)
                    .header("etag", HeaderValue::from_bytes(b"bad\tvalue").unwrap());
                valid_body
            }
            "/returned-last-modified-control" => {
                response = response
                    .header("content-type", FEDERATION_CONTENT_TYPE)
                    .header(
                        "last-modified",
                        HeaderValue::from_bytes(b"bad\tvalue").unwrap(),
                    );
                valid_body
            }
            _ => {
                response = response
                    .header("content-type", FEDERATION_CONTENT_TYPE)
                    .header("etag", r#""actor-v2""#)
                    .header("last-modified", "Wed, 15 Jul 2026 11:00:00 GMT");
                valid_body
            }
        };

        response.body(Body::from(body)).unwrap()
    }

    async fn fetch_test_data(
        fixture: &FetchFixture,
        signed: bool,
        fetch_limit: u32,
        local_domain: Option<String>,
    ) -> Data<DbConnection> {
        let client: ClientWithMiddleware = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .resolve(REMOTE_HOST, fixture.address)
            .build()
            .unwrap()
            .into();
        let mut builder = FederationConfig::builder();
        builder
            .domain(local_domain.unwrap_or_else(|| "local.example".to_string()))
            .app_data(DbConnection)
            .client(client)
            .debug(true)
            .http_fetch_limit(fetch_limit);
        if signed {
            builder.signed_fetch_actor(&*DB_USER);
        }
        builder.build().await.unwrap().to_request_data()
    }

    #[tokio::test]
    async fn test_request_limit() -> Result<(), Error> {
        let config = FederationConfig::builder()
            .domain("example.com")
            .app_data(DbConnection)
            .http_fetch_limit(0)
            .build()
            .await
            .unwrap();
        let data = config.to_request_data();

        let fetch_url = "https://example.net/".to_string();

        let res: Result<FetchObjectResponse<Person>, Error> =
            fetch_object_http(&Url::parse(&fetch_url).map_err(Error::UrlParse)?, &data).await;

        assert_eq!(res.err(), Some(Error::RequestLimit));

        Ok(())
    }

    #[tokio::test]
    async fn conditional_fetch_handles_unsigned_and_signed_success() {
        let fixture = FetchFixture::start().await;

        for signed in [false, true] {
            let data = fetch_test_data(&fixture, signed, 20, None).await;
            let url = fixture.url(&format!("/ok?signed={signed}"));
            let outcome = fetch_object_http_conditional::<_, ConditionalPerson>(
                &url,
                &ConditionalFetchValidators::default(),
                &data,
            )
            .await
            .unwrap();

            match outcome {
                ConditionalFetchOutcome::Fetched {
                    object,
                    url: fetched_url,
                    etag,
                    last_modified,
                } => {
                    assert_eq!(object.id, url);
                    assert_eq!(fetched_url, url);
                    assert_eq!(etag.as_deref(), Some(r#""actor-v2""#));
                    assert_eq!(
                        last_modified.as_deref(),
                        Some("Wed, 15 Jul 2026 11:00:00 GMT")
                    );
                }
                other => panic!("expected fetched outcome, got {other:?}"),
            }
        }

        let requests = fixture.requests();
        assert_eq!(requests.len(), 2);
        assert!(!requests[0].signed);
        assert!(requests[1].signed);
    }

    #[tokio::test]
    async fn conditional_fetch_sends_validators_and_does_not_parse_not_modified_body() {
        let fixture = FetchFixture::start().await;
        let data = fetch_test_data(&fixture, false, 20, None).await;
        let url = fixture.url("/not-modified");
        let outcome = fetch_object_http_conditional::<_, ConditionalPerson>(
            &url,
            &ConditionalFetchValidators {
                etag: Some(r#""actor-v1""#.to_string()),
                last_modified: Some("Wed, 15 Jul 2026 10:00:00 GMT".to_string()),
            },
            &data,
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            ConditionalFetchOutcome::NotModified {
                etag: Some(ref etag),
                last_modified: Some(ref last_modified),
                ..
            } if etag == r#""actor-v2""#
                && last_modified == "Wed, 15 Jul 2026 11:00:00 GMT"
        ));
        let requests = fixture.requests();
        assert_eq!(requests[0].if_none_match.as_deref(), Some(r#""actor-v1""#));
        assert_eq!(
            requests[0].if_modified_since.as_deref(),
            Some("Wed, 15 Jul 2026 10:00:00 GMT")
        );
    }

    #[tokio::test]
    async fn conditional_fetch_maps_gone_and_preserves_non_success_status() {
        let fixture = FetchFixture::start().await;
        let data = fetch_test_data(&fixture, false, 20, None).await;
        let gone_url = fixture.url("/gone");
        let gone = fetch_object_http_conditional::<_, ConditionalPerson>(
            &gone_url,
            &ConditionalFetchValidators::default(),
            &data,
        )
        .await
        .unwrap();
        assert!(matches!(
            gone,
            ConditionalFetchOutcome::Gone { url } if url == gone_url
        ));

        for status in [408_u16, 425, 429, 400, 404, 500, 503] {
            let result = fetch_object_http_conditional::<_, ConditionalPerson>(
                &fixture.url(&format!("/status/{status}")),
                &ConditionalFetchValidators::default(),
                &data,
            )
            .await;
            assert!(matches!(
                result,
                Err(Error::Reqwest(error)) if error.status().map(|value| value.as_u16()) == Some(status)
            ));
        }
    }

    #[tokio::test]
    async fn conditional_fetch_rejects_invalid_request_validators_before_io() {
        let fixture = FetchFixture::start().await;
        let data = fetch_test_data(&fixture, false, 20, None).await;
        let url = fixture.url("/ok");
        let invalid = [
            ConditionalFetchValidators {
                etag: Some("x".repeat(513)),
                last_modified: None,
            },
            ConditionalFetchValidators {
                etag: None,
                last_modified: Some("x".repeat(129)),
            },
            ConditionalFetchValidators {
                etag: Some("bad\nvalue".to_string()),
                last_modified: None,
            },
            ConditionalFetchValidators {
                etag: None,
                last_modified: Some("bad\tvalue".to_string()),
            },
        ];

        for validators in invalid {
            assert!(fetch_object_http_conditional::<_, ConditionalPerson>(
                &url,
                &validators,
                &data
            )
            .await
            .is_err());
        }
        assert!(fixture.requests().is_empty());
    }

    #[tokio::test]
    async fn conditional_fetch_rejects_invalid_returned_validators() {
        let fixture = FetchFixture::start().await;
        let data = fetch_test_data(&fixture, false, 20, None).await;

        for path in [
            "/returned-etag-too-long",
            "/returned-last-modified-too-long",
            "/returned-etag-control",
            "/returned-last-modified-control",
        ] {
            assert!(fetch_object_http_conditional::<_, ConditionalPerson>(
                &fixture.url(path),
                &ConditionalFetchValidators::default(),
                &data,
            )
            .await
            .is_err());
        }
    }

    #[tokio::test]
    async fn conditional_fetch_allows_one_safe_redirect_and_rejects_unsafe_redirect() {
        let fixture = FetchFixture::start().await;
        let data = fetch_test_data(&fixture, false, 20, None).await;
        let redirected = fetch_object_http_conditional::<_, ConditionalPerson>(
            &fixture.url("/redirect"),
            &ConditionalFetchValidators::default(),
            &data,
        )
        .await
        .unwrap();
        assert!(matches!(
            redirected,
            ConditionalFetchOutcome::Fetched { url, .. }
                if url == fixture.url("/redirect-target")
        ));
        assert_eq!(
            fixture
                .requests()
                .iter()
                .map(|request| request.path.as_str())
                .collect::<Vec<_>>(),
            vec!["/redirect", "/redirect-target"]
        );

        let unsafe_result = fetch_object_http_conditional::<_, ConditionalPerson>(
            &fixture.url("/unsafe-redirect"),
            &ConditionalFetchValidators::default(),
            &data,
        )
        .await;
        assert!(matches!(
            unsafe_result,
            Err(Error::UrlVerificationError("Invalid url scheme"))
        ));
    }

    #[tokio::test]
    async fn conditional_fetch_preserves_object_response_safety_checks() {
        let fixture = FetchFixture::start().await;
        let data = fetch_test_data(&fixture, false, 20, None).await;

        let wrong_id = fetch_object_http_conditional::<_, ConditionalPerson>(
            &fixture.url("/wrong-id"),
            &ConditionalFetchValidators::default(),
            &data,
        )
        .await;
        assert!(matches!(wrong_id, Err(Error::FetchWrongId(_))));

        let invalid_content_type = fetch_object_http_conditional::<_, ConditionalPerson>(
            &fixture.url("/bad-content-type"),
            &ConditionalFetchValidators::default(),
            &data,
        )
        .await;
        assert!(matches!(
            invalid_content_type,
            Err(Error::FetchInvalidContentType(_))
        ));

        let oversized = fetch_object_http_conditional::<_, ConditionalPerson>(
            &fixture.url("/large"),
            &ConditionalFetchValidators::default(),
            &data,
        )
        .await;
        assert!(matches!(oversized, Err(Error::ResponseBodyLimit)));
    }

    #[tokio::test]
    async fn conditional_fetch_rejects_same_domain_object_id_mismatch_without_reusing_validators() {
        let fixture = FetchFixture::start().await;
        let data = fetch_test_data(&fixture, false, 20, None).await;
        let result = fetch_object_http_conditional::<_, ConditionalPerson>(
            &fixture.url("/same-domain-wrong-id"),
            &ConditionalFetchValidators {
                etag: Some(r#""alias-v1""#.to_string()),
                last_modified: None,
            },
            &data,
        )
        .await;

        assert!(matches!(result, Err(Error::FetchWrongId(_))));
        assert_eq!(
            fixture
                .requests()
                .iter()
                .map(|request| request.path.as_str())
                .collect::<Vec<_>>(),
            vec!["/same-domain-wrong-id"]
        );
    }

    #[tokio::test]
    async fn conditional_fetch_rejects_local_final_url() {
        let fixture = FetchFixture::start().await;
        let data = fetch_test_data(&fixture, false, 20, Some(fixture.local_domain())).await;
        let result = fetch_object_http_conditional::<_, ConditionalPerson>(
            &fixture.url("/ok"),
            &ConditionalFetchValidators::default(),
            &data,
        )
        .await;

        assert!(matches!(result, Err(Error::NotFound)));
    }

    #[tokio::test]
    async fn conditional_fetch_enforces_per_request_fetch_budget() {
        let fixture = FetchFixture::start().await;
        let data = fetch_test_data(&fixture, false, 1, None).await;
        let url = fixture.url("/ok");

        fetch_object_http_conditional::<_, ConditionalPerson>(
            &url,
            &ConditionalFetchValidators::default(),
            &data,
        )
        .await
        .unwrap();
        let exhausted = fetch_object_http_conditional::<_, ConditionalPerson>(
            &url,
            &ConditionalFetchValidators::default(),
            &data,
        )
        .await;

        assert!(matches!(exhausted, Err(Error::RequestLimit)));
        assert_eq!(fixture.requests().len(), 1);
    }
}
