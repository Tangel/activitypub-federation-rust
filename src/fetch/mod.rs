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
    header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION},
    HeaderValue,
    StatusCode,
};
use serde::de::DeserializeOwned;
use std::sync::atomic::Ordering;
use tracing::info;
use url::Url;

const MAX_CONDITIONAL_VALIDATOR_LENGTH: usize = 512;

/// Typed wrapper for collection IDs
pub mod collection_id;
/// Typed wrapper for Activitypub Object ID which helps with dereferencing and caching
pub mod object_id;
/// Resolves identifiers of the form `name@example.com`
pub mod webfinger;

/// Response from fetching a remote object
pub struct FetchObjectResponse<Kind> {
    /// The resolved object
    pub object: Kind,
    /// Contains the final URL (different from request URL in case of redirect)
    pub url: Url,
    content_type: Option<HeaderValue>,
    object_id: Option<Url>,
}

/// Validators supplied with a conditional ActivityPub fetch.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConditionalRequestValidators {
    etag: Option<HeaderValue>,
    last_modified: Option<HeaderValue>,
}

impl ConditionalRequestValidators {
    /// Construct validated conditional request headers.
    pub fn try_new(etag: Option<&str>, last_modified: Option<&str>) -> Result<Self, Error> {
        Ok(Self {
            etag: etag.map(parse_conditional_validator).transpose()?,
            last_modified: last_modified.map(parse_conditional_validator).transpose()?,
        })
    }
}

fn parse_conditional_validator(value: &str) -> Result<HeaderValue, Error> {
    if value.chars().count() > MAX_CONDITIONAL_VALIDATOR_LENGTH
        || value.chars().any(char::is_control)
    {
        return Err(Error::Other(
            "invalid conditional request validator".to_string(),
        ));
    }
    HeaderValue::from_str(value)
        .map_err(|_| Error::Other("invalid conditional request validator".to_string()))
}

/// Closed result of a conditional ActivityPub fetch.
#[derive(Debug)]
pub enum ConditionalFetchOutcome<Kind> {
    /// The remote object changed and was parsed successfully.
    Modified {
        /// Parsed remote object.
        object: Kind,
        /// Final URL after the optional validated redirect.
        final_url: Url,
        /// Response ETag, when present and valid UTF-8.
        etag: Option<String>,
        /// Response Last-Modified value, when present and valid UTF-8.
        last_modified: Option<String>,
    },
    /// The remote server returned 304 without requiring body parsing.
    NotModified {
        /// Final URL after the optional validated redirect.
        final_url: Url,
        /// Response ETag, when present and valid UTF-8.
        etag: Option<String>,
        /// Response Last-Modified value, when present and valid UTF-8.
        last_modified: Option<String>,
    },
    /// The remote server returned 410 Gone.
    Gone {
        /// Final URL after the optional validated redirect.
        final_url: Url,
    },
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
    if let Some(object_id) = validate_activitypub_response(&res, data).await? {
        return Box::pin(fetch_object_http(&object_id, data)).await;
    }

    Ok(res)
}

/// Fetch an ActivityPub object with optional cache validators through the same security path as
/// [`fetch_object_http`].
pub async fn fetch_object_http_conditional<T: Clone, Kind: DeserializeOwned>(
    url: &Url,
    validators: ConditionalRequestValidators,
    data: &Data<T>,
) -> Result<ConditionalFetchOutcome<Kind>, Error> {
    fetch_object_http_conditional_inner(url, ConditionalFetchMode::Conditional(&validators), data)
        .await
}

#[derive(Clone, Copy)]
enum ConditionalFetchMode<'a> {
    Conditional(&'a ConditionalRequestValidators),
    CanonicalRefetch,
}

impl ConditionalFetchMode<'_> {
    fn validators(&self) -> Option<&ConditionalRequestValidators> {
        match self {
            Self::Conditional(validators) => Some(validators),
            Self::CanonicalRefetch => None,
        }
    }

    fn accepts_not_modified(&self) -> bool {
        matches!(self, Self::Conditional(_))
    }
}

async fn fetch_object_http_conditional_inner<T: Clone, Kind: DeserializeOwned>(
    url: &Url,
    mode: ConditionalFetchMode<'_>,
    data: &Data<T>,
) -> Result<ConditionalFetchOutcome<Kind>, Error> {
    static FETCH_CONTENT_TYPE: HeaderValue = HeaderValue::from_static(FEDERATION_CONTENT_TYPE);
    let response =
        fetch_object_http_response(url, data, &FETCH_CONTENT_TYPE, mode.validators(), false)
            .await?;
    let final_url = response.url().clone();

    match response.status() {
        StatusCode::OK => {}
        StatusCode::NOT_MODIFIED => {
            validate_final_remote_url(&final_url, data)?;
            if !mode.accepts_not_modified() {
                return Err(unexpected_response_status(&response));
            }
            return Ok(ConditionalFetchOutcome::NotModified {
                final_url,
                etag: response_header_value(response.headers().get(ETAG)),
                last_modified: response_header_value(response.headers().get(LAST_MODIFIED)),
            });
        }
        StatusCode::GONE => {
            validate_final_remote_url(&final_url, data)?;
            return Ok(ConditionalFetchOutcome::Gone { final_url });
        }
        _ => return Err(unexpected_response_status(&response)),
    }

    let etag = response_header_value(response.headers().get(ETAG));
    let last_modified = response_header_value(response.headers().get(LAST_MODIFIED));
    let res = parse_fetch_object_response(response).await?;
    if let Some(object_id) = validate_activitypub_response(&res, data).await? {
        return Box::pin(fetch_object_http_conditional_inner(
            &object_id,
            ConditionalFetchMode::CanonicalRefetch,
            data,
        ))
        .await;
    }

    Ok(ConditionalFetchOutcome::Modified {
        object: res.object,
        final_url: res.url,
        etag,
        last_modified,
    })
}

fn response_header_value(value: Option<&HeaderValue>) -> Option<String> {
    value
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

fn unexpected_response_status(response: &reqwest::Response) -> Error {
    match response.error_for_status_ref() {
        Ok(_) => Error::Other(format!(
            "unexpected object fetch status {}",
            response.status()
        )),
        Err(error) => error.into(),
    }
}

async fn validate_activitypub_response<T: Clone, Kind>(
    res: &FetchObjectResponse<Kind>,
    data: &Data<T>,
) -> Result<Option<Url>, Error> {
    const VALID_RESPONSE_CONTENT_TYPES: [&str; 3] = [
        FEDERATION_CONTENT_TYPE,
        r#"application/ld+json; profile="https://www.w3.org/ns/activitystreams""#,
        r#"application/activity+json; charset=utf-8"#,
    ];

    let content_type = res
        .content_type
        .as_ref()
        .and_then(|content_type| Some(content_type.to_str().ok()?.to_lowercase()))
        .ok_or_else(|| Error::FetchInvalidContentType(res.url.clone()))?;
    if !VALID_RESPONSE_CONTENT_TYPES.contains(&content_type.as_str()) {
        return Err(Error::FetchInvalidContentType(res.url.clone()));
    }

    if res.object_id.as_ref() != Some(&res.url) {
        if let Some(res_object_id) = &res.object_id {
            data.config.verify_url_valid(res_object_id).await?;
            if res_object_id.domain() == res.url.domain() {
                return Ok(Some(res_object_id.clone()));
            }
        }
        return Err(Error::FetchWrongId(res.url.clone()));
    }

    validate_final_remote_url(&res.url, data)?;

    Ok(None)
}

fn validate_final_remote_url<T: Clone>(url: &Url, data: &Data<T>) -> Result<(), Error> {
    if data.config.is_local_url(url) {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// Fetch a remote object over HTTP and convert to `Kind`. This function works exactly as
/// [`fetch_object_http`] except that the `Accept` header is specified in `content_type`.
async fn fetch_object_http_with_accept<T: Clone, Kind: DeserializeOwned>(
    url: &Url,
    data: &Data<T>,
    content_type: &HeaderValue,
    recursive: bool,
) -> Result<FetchObjectResponse<Kind>, Error> {
    let response = fetch_object_http_response(url, data, content_type, None, recursive).await?;
    if response.status() == StatusCode::GONE {
        let final_url = response.url().clone();
        validate_final_remote_url(&final_url, data)?;
        return Err(Error::ObjectDeleted(final_url));
    }
    parse_fetch_object_response(response).await
}

async fn fetch_object_http_response<T: Clone>(
    url: &Url,
    data: &Data<T>,
    content_type: &HeaderValue,
    validators: Option<&ConditionalRequestValidators>,
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
    if let Some(validators) = validators {
        if let Some(etag) = &validators.etag {
            req = req.header(IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = &validators.last_modified {
            req = req.header(IF_MODIFIED_SINCE, last_modified);
        }
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
        return Box::pin(fetch_object_http_response(
            &location,
            data,
            content_type,
            validators,
            true,
        ))
        .await;
    }

    Ok(res)
}

async fn parse_fetch_object_response<Kind: DeserializeOwned>(
    response: reqwest::Response,
) -> Result<FetchObjectResponse<Kind>, Error> {
    let url = response.url().clone();
    let content_type = response.headers().get("Content-Type").cloned();
    let text = response.bytes_limited().await?;
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{
        config::{FederationConfig, UrlVerifier},
        traits::tests::{DbConnection, Person, DB_USER},
    };
    use axum::{
        body::Body,
        extract::State,
        http::Request,
        response::{IntoResponse, Response},
        Router,
    };
    use http::{
        header::{HOST, IF_MODIFIED_SINCE, IF_NONE_MATCH},
        HeaderMap,
        Uri,
    };
    use serde::Deserialize;
    use std::{
        future::Future,
        pin::Pin,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::task::JoinHandle;

    const LAST_MODIFIED: &str = "Sat, 18 Jul 2026 00:00:00 GMT";

    #[derive(Debug, Deserialize, PartialEq)]
    struct TestActorKind {
        id: Url,
    }

    #[derive(Clone)]
    struct RecordedRequest {
        path: String,
        headers: HeaderMap,
    }

    #[derive(Clone, Default)]
    struct FetchFixtureState {
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
    }

    struct FetchFixture {
        base_url: Url,
        state: FetchFixtureState,
        task: JoinHandle<()>,
    }

    impl FetchFixture {
        async fn spawn() -> Self {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let state = FetchFixtureState::default();
            let app = Router::new()
                .fallback(fetch_fixture_handler)
                .with_state(state.clone());
            let task = tokio::spawn(async move {
                let never = axum::serve(listener, app).await;
                match never {}
            });

            Self {
                base_url: Url::parse(&format!("http://localhost:{}", address.port())).unwrap(),
                state,
                task,
            }
        }

        fn url(&self, path: &str) -> Url {
            self.base_url.join(path).unwrap()
        }

        fn requests(&self) -> Vec<RecordedRequest> {
            self.state.requests.lock().unwrap().clone()
        }
    }

    impl Drop for FetchFixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn fixture_request_url(headers: &HeaderMap, uri: &Uri) -> Url {
        let host = headers.get(HOST).unwrap().to_str().unwrap();
        Url::parse(&format!("http://{host}{}", uri.path())).unwrap()
    }

    async fn fetch_fixture_handler(
        State(state): State<FetchFixtureState>,
        request: Request<Body>,
    ) -> Response {
        let path = request.uri().path().to_string();
        let request_url = fixture_request_url(request.headers(), request.uri());
        state.requests.lock().unwrap().push(RecordedRequest {
            path: path.clone(),
            headers: request.headers().clone(),
        });

        match path.as_str() {
            "/alias" => (
                StatusCode::OK,
                [
                    ("content-type", crate::FEDERATION_CONTENT_TYPE),
                    ("etag", "\"alias-v2\""),
                    ("last-modified", LAST_MODIFIED),
                ],
                format!(r#"{{"id":"{}"}}"#, request_url.join("/canonical").unwrap()),
            )
                .into_response(),
            "/canonical" => {
                if request.headers().get(IF_NONE_MATCH)
                    == Some(&HeaderValue::from_static("\"alias-v1\""))
                    || request.headers().get(IF_MODIFIED_SINCE)
                        == Some(&HeaderValue::from_static(LAST_MODIFIED))
                {
                    (
                        StatusCode::NOT_MODIFIED,
                        [("etag", "\"canonical-v1\"")],
                        "{this is intentionally not json",
                    )
                        .into_response()
                } else {
                    (
                        StatusCode::OK,
                        [
                            ("content-type", crate::FEDERATION_CONTENT_TYPE),
                            ("etag", "\"canonical-v1\""),
                        ],
                        format!(r#"{{"id":"{request_url}"}}"#),
                    )
                        .into_response()
                }
            }
            "/alias-to-always-not-modified" => (
                StatusCode::OK,
                [("content-type", crate::FEDERATION_CONTENT_TYPE)],
                format!(
                    r#"{{"id":"{}"}}"#,
                    request_url.join("/canonical-always-not-modified").unwrap()
                ),
            )
                .into_response(),
            "/alias-to-canonical-wrong-id" => (
                StatusCode::OK,
                [("content-type", crate::FEDERATION_CONTENT_TYPE)],
                format!(
                    r#"{{"id":"{}"}}"#,
                    request_url.join("/canonical-wrong-id").unwrap()
                ),
            )
                .into_response(),
            "/canonical-wrong-id" => (
                StatusCode::OK,
                [("content-type", crate::FEDERATION_CONTENT_TYPE)],
                r#"{"id":"https://other.example/canonical"}"#,
            )
                .into_response(),
            "/canonical-always-not-modified" => (
                StatusCode::NOT_MODIFIED,
                [("etag", "\"canonical-v1\"")],
                "{this is intentionally not json",
            )
                .into_response(),
            "/not-modified" => (
                StatusCode::NOT_MODIFIED,
                [("etag", "\"actor-v3\""), ("last-modified", LAST_MODIFIED)],
                "{this is intentionally not json",
            )
                .into_response(),
            "/redirect" => {
                let location = request_url.join("/final").unwrap().to_string();
                (StatusCode::FOUND, [("location", location)]).into_response()
            }
            "/final" => (
                StatusCode::OK,
                [
                    ("content-type", crate::FEDERATION_CONTENT_TYPE),
                    ("etag", "\"actor-v3\""),
                    ("last-modified", LAST_MODIFIED),
                ],
                format!(r#"{{"id":"{request_url}"}}"#),
            )
                .into_response(),
            "/gone" => (StatusCode::GONE, "{this is intentionally not json").into_response(),
            "/wrong-content-type" => (
                StatusCode::OK,
                [("content-type", "text/html")],
                format!(r#"{{"id":"{request_url}"}}"#),
            )
                .into_response(),
            "/wrong-id" => (
                StatusCode::OK,
                [("content-type", crate::FEDERATION_CONTENT_TYPE)],
                r#"{"id":"https://other.example/actor"}"#,
            )
                .into_response(),
            "/not-found-valid" => (
                StatusCode::NOT_FOUND,
                [("content-type", crate::FEDERATION_CONTENT_TYPE)],
                format!(r#"{{"id":"{request_url}"}}"#),
            )
                .into_response(),
            "/redirect-without-location-valid" => (
                StatusCode::FOUND,
                [("content-type", crate::FEDERATION_CONTENT_TYPE)],
                format!(r#"{{"id":"{request_url}"}}"#),
            )
                .into_response(),
            "/server-error-valid" => (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("content-type", crate::FEDERATION_CONTENT_TYPE)],
                format!(r#"{{"id":"{request_url}"}}"#),
            )
                .into_response(),
            "/oversized" => (
                StatusCode::OK,
                [("content-type", crate::FEDERATION_CONTENT_TYPE)],
                vec![b'x'; 1024 * 1024 + 1],
            )
                .into_response(),
            "/slow" => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                (
                    StatusCode::OK,
                    [("content-type", crate::FEDERATION_CONTENT_TYPE)],
                    format!(r#"{{"id":"{request_url}"}}"#),
                )
                    .into_response()
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }

    #[derive(Clone)]
    struct RecordingUrlVerifier {
        urls: Arc<Mutex<Vec<Url>>>,
    }

    impl UrlVerifier for RecordingUrlVerifier {
        fn verify(
            &self,
            url: &Url,
        ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>> {
            self.urls.lock().unwrap().push(url.clone());
            Box::pin(async { Ok(()) })
        }
    }

    #[derive(Clone)]
    struct RejectingUrlVerifier;

    impl UrlVerifier for RejectingUrlVerifier {
        fn verify(
            &self,
            url: &Url,
        ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>> {
            let domain = url.domain().unwrap_or_default().to_string();
            Box::pin(async move { Err(Error::DomainResolveError(domain)) })
        }
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

    #[test]
    fn conditional_fetch_validators_reject_controls_and_values_over_512_bytes() {
        assert!(ConditionalRequestValidators::try_new(Some("bad\nvalue"), None).is_err());
        assert!(ConditionalRequestValidators::try_new(None, Some("bad\tvalue")).is_err());
        assert!(ConditionalRequestValidators::try_new(Some(&"x".repeat(513)), None).is_err());
        assert!(ConditionalRequestValidators::try_new(Some(&"x".repeat(512)), None).is_ok());
    }

    #[tokio::test]
    async fn conditional_fetch_canonical_refetch_clears_alias_validators_and_validates_body(
    ) -> Result<(), Error> {
        let server = FetchFixture::spawn().await;
        let data = FederationConfig::builder()
            .domain("local.example")
            .app_data(())
            .debug(true)
            .build()
            .await
            .unwrap()
            .to_request_data();
        let validators =
            ConditionalRequestValidators::try_new(Some("\"alias-v1\""), Some(LAST_MODIFIED))?;
        let canonical_url = server.url("/canonical");

        let outcome = fetch_object_http_conditional::<_, TestActorKind>(
            &server.url("/alias"),
            validators,
            &data,
        )
        .await?;
        let ConditionalFetchOutcome::Modified {
            object,
            final_url,
            etag,
            ..
        } = outcome
        else {
            panic!("canonical refetch must return a verified modified object");
        };

        assert_eq!(object.id, canonical_url);
        assert_eq!(final_url, canonical_url);
        assert_eq!(etag.as_deref(), Some("\"canonical-v1\""));
        let requests = server.requests();
        assert_eq!(
            requests
                .iter()
                .map(|request| request.path.as_str())
                .collect::<Vec<_>>(),
            vec!["/alias", "/canonical"]
        );
        assert_eq!(
            requests[0].headers.get(IF_NONE_MATCH).unwrap(),
            "\"alias-v1\""
        );
        assert_eq!(
            requests[0].headers.get(IF_MODIFIED_SINCE).unwrap(),
            LAST_MODIFIED
        );
        assert!(!requests[1].headers.contains_key(IF_NONE_MATCH));
        assert!(!requests[1].headers.contains_key(IF_MODIFIED_SINCE));

        Ok(())
    }

    #[tokio::test]
    async fn conditional_fetch_canonical_refetch_rejects_unconditional_not_modified() {
        let server = FetchFixture::spawn().await;
        let data = FederationConfig::builder()
            .domain("local.example")
            .app_data(())
            .debug(true)
            .build()
            .await
            .unwrap()
            .to_request_data();

        let error = fetch_object_http_conditional::<_, TestActorKind>(
            &server.url("/alias-to-always-not-modified"),
            ConditionalRequestValidators::default(),
            &data,
        )
        .await
        .unwrap_err();

        assert!(matches!(error, Error::Other(_)));
    }

    #[tokio::test]
    async fn conditional_fetch_canonical_refetch_enforces_exact_id() {
        let server = FetchFixture::spawn().await;
        let data = FederationConfig::builder()
            .domain("local.example")
            .app_data(())
            .debug(true)
            .build()
            .await
            .unwrap()
            .to_request_data();

        let error = fetch_object_http_conditional::<_, TestActorKind>(
            &server.url("/alias-to-canonical-wrong-id"),
            ConditionalRequestValidators::default(),
            &data,
        )
        .await
        .unwrap_err();

        assert!(matches!(error, Error::FetchWrongId(_)));
        assert_eq!(
            server
                .requests()
                .iter()
                .map(|request| request.path.as_str())
                .collect::<Vec<_>>(),
            vec!["/alias-to-canonical-wrong-id", "/canonical-wrong-id"]
        );
    }

    #[tokio::test]
    async fn conditional_fetch_rejects_shaped_error_status_404() {
        let server = FetchFixture::spawn().await;
        let data = FederationConfig::builder()
            .domain("local.example")
            .app_data(())
            .debug(true)
            .build()
            .await
            .unwrap()
            .to_request_data();

        let error = fetch_object_http_conditional::<_, TestActorKind>(
            &server.url("/not-found-valid"),
            ConditionalRequestValidators::default(),
            &data,
        )
        .await
        .unwrap_err();

        assert!(matches!(error, Error::Reqwest(_)));
    }

    #[tokio::test]
    async fn conditional_fetch_rejects_shaped_error_status_302_without_location() {
        let server = FetchFixture::spawn().await;
        let data = FederationConfig::builder()
            .domain("local.example")
            .app_data(())
            .debug(true)
            .build()
            .await
            .unwrap()
            .to_request_data();

        let error = fetch_object_http_conditional::<_, TestActorKind>(
            &server.url("/redirect-without-location-valid"),
            ConditionalRequestValidators::default(),
            &data,
        )
        .await
        .unwrap_err();

        assert!(matches!(error, Error::Other(_)));
    }

    #[tokio::test]
    async fn conditional_fetch_rejects_shaped_error_status_500() {
        let server = FetchFixture::spawn().await;
        let data = FederationConfig::builder()
            .domain("local.example")
            .app_data(())
            .debug(true)
            .build()
            .await
            .unwrap()
            .to_request_data();

        let error = fetch_object_http_conditional::<_, TestActorKind>(
            &server.url("/server-error-valid"),
            ConditionalRequestValidators::default(),
            &data,
        )
        .await
        .unwrap_err();

        assert!(matches!(error, Error::Reqwest(_)));
    }

    #[tokio::test]
    async fn normal_and_conditional_fetch_reject_local_gone_before_status_mapping() {
        let server = FetchFixture::spawn().await;
        let local_domain = format!(
            "{}:{}",
            server.base_url.host_str().unwrap(),
            server.base_url.port().unwrap()
        );
        let data = FederationConfig::builder()
            .domain(local_domain)
            .app_data(())
            .debug(true)
            .build()
            .await
            .unwrap()
            .to_request_data();
        let gone_url = server.url("/gone");

        let conditional_error = fetch_object_http_conditional::<_, TestActorKind>(
            &gone_url,
            ConditionalRequestValidators::default(),
            &data,
        )
        .await
        .unwrap_err();
        assert_eq!(conditional_error, Error::NotFound);

        let normal_error = match fetch_object_http::<_, TestActorKind>(&gone_url, &data).await {
            Ok(_) => panic!("normal fetch must reject a local gone response"),
            Err(error) => error,
        };
        assert_eq!(normal_error, Error::NotFound);
    }

    #[tokio::test]
    async fn conditional_fetch_reuses_headers_signing_redirect_and_closed_outcomes(
    ) -> Result<(), Error> {
        let server = FetchFixture::spawn().await;
        let verified_urls = Arc::new(Mutex::new(Vec::new()));
        let data = FederationConfig::builder()
            .domain("local.example")
            .app_data(())
            .debug(true)
            .url_verifier(Box::new(RecordingUrlVerifier {
                urls: verified_urls.clone(),
            }))
            .signed_fetch_actor(&*DB_USER)
            .build()
            .await
            .unwrap()
            .to_request_data();
        let validators =
            ConditionalRequestValidators::try_new(Some("\"actor-v2\""), Some(LAST_MODIFIED))?;

        let not_modified_url = server.url("/not-modified");
        let not_modified = fetch_object_http_conditional::<_, TestActorKind>(
            &not_modified_url,
            validators.clone(),
            &data,
        )
        .await?;
        let ConditionalFetchOutcome::NotModified {
            final_url,
            etag,
            last_modified,
        } = not_modified
        else {
            panic!("expected not-modified outcome");
        };
        assert_eq!(final_url, not_modified_url);
        assert_eq!(etag.as_deref(), Some("\"actor-v3\""));
        assert_eq!(last_modified.as_deref(), Some(LAST_MODIFIED));

        let redirect_url = server.url("/redirect");
        let final_url = server.url("/final");
        let modified = fetch_object_http_conditional::<_, TestActorKind>(
            &redirect_url,
            validators.clone(),
            &data,
        )
        .await?;
        let ConditionalFetchOutcome::Modified {
            object,
            final_url: modified_final_url,
            etag,
            last_modified,
        } = modified
        else {
            panic!("expected modified outcome");
        };
        assert_eq!(object.id, final_url);
        assert_eq!(modified_final_url, final_url);
        assert_eq!(etag.as_deref(), Some("\"actor-v3\""));
        assert_eq!(last_modified.as_deref(), Some(LAST_MODIFIED));

        let gone_url = server.url("/gone");
        let gone =
            fetch_object_http_conditional::<_, TestActorKind>(&gone_url, validators, &data).await?;
        let ConditionalFetchOutcome::Gone {
            final_url: gone_final_url,
        } = gone
        else {
            panic!("expected gone outcome");
        };
        assert_eq!(gone_final_url, gone_url);

        assert_eq!(data.request_count(), 4);
        let requests = server.requests();
        assert_eq!(requests.len(), 4);
        assert_eq!(
            requests
                .iter()
                .map(|request| request.path.as_str())
                .collect::<Vec<_>>(),
            vec!["/not-modified", "/redirect", "/final", "/gone"]
        );
        for request in &requests {
            assert_eq!(request.headers.get(IF_NONE_MATCH).unwrap(), "\"actor-v2\"");
            assert_eq!(
                request.headers.get(IF_MODIFIED_SINCE).unwrap(),
                LAST_MODIFIED
            );
            assert!(request.headers.contains_key("signature"));
        }
        assert_eq!(
            verified_urls.lock().unwrap().as_slice(),
            [not_modified_url, redirect_url, final_url, gone_url]
        );

        Ok(())
    }

    #[tokio::test]
    async fn conditional_fetch_enforces_content_type_and_exact_final_id() {
        let server = FetchFixture::spawn().await;
        let data = FederationConfig::builder()
            .domain("local.example")
            .app_data(())
            .debug(true)
            .build()
            .await
            .unwrap()
            .to_request_data();

        let content_type_error = fetch_object_http_conditional::<_, TestActorKind>(
            &server.url("/wrong-content-type"),
            ConditionalRequestValidators::default(),
            &data,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            content_type_error,
            Error::FetchInvalidContentType(_)
        ));

        let wrong_id_error = fetch_object_http_conditional::<_, TestActorKind>(
            &server.url("/wrong-id"),
            ConditionalRequestValidators::default(),
            &data,
        )
        .await
        .unwrap_err();
        assert!(matches!(wrong_id_error, Error::FetchWrongId(_)));
    }

    #[tokio::test]
    async fn conditional_fetch_rejects_local_final_url_before_closed_outcome() {
        let server = FetchFixture::spawn().await;
        let local_domain = format!(
            "{}:{}",
            server.base_url.host_str().unwrap(),
            server.base_url.port().unwrap()
        );
        let data = FederationConfig::builder()
            .domain(local_domain)
            .app_data(())
            .debug(true)
            .build()
            .await
            .unwrap()
            .to_request_data();

        let error = fetch_object_http_conditional::<_, TestActorKind>(
            &server.url("/not-modified"),
            ConditionalRequestValidators::default(),
            &data,
        )
        .await
        .unwrap_err();

        assert_eq!(error, Error::NotFound);
    }

    #[tokio::test]
    async fn conditional_fetch_runs_url_dns_ip_safety_before_request() -> Result<(), Error> {
        let rejected_data = FederationConfig::builder()
            .domain("local.example")
            .app_data(())
            .debug(true)
            .url_verifier(Box::new(RejectingUrlVerifier))
            .build()
            .await
            .unwrap()
            .to_request_data();
        let rejected = fetch_object_http_conditional::<_, TestActorKind>(
            &Url::parse("https://blocked.example/actor")?,
            ConditionalRequestValidators::default(),
            &rejected_data,
        )
        .await
        .unwrap_err();
        assert!(matches!(rejected, Error::DomainResolveError(_)));
        assert_eq!(rejected_data.request_count(), 0);

        let ip_data = FederationConfig::builder()
            .domain("local.example")
            .app_data(())
            .allow_http_urls(true)
            .build()
            .await
            .unwrap()
            .to_request_data();
        let rejected_ip = fetch_object_http_conditional::<_, TestActorKind>(
            &Url::parse("http://127.0.0.1/actor")?,
            ConditionalRequestValidators::default(),
            &ip_data,
        )
        .await
        .unwrap_err();
        assert!(matches!(rejected_ip, Error::UrlVerificationError(_)));
        assert_eq!(ip_data.request_count(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn conditional_fetch_enforces_request_limit_timeout_and_body_bound() -> Result<(), Error>
    {
        let limited_data = FederationConfig::builder()
            .domain("local.example")
            .app_data(())
            .debug(true)
            .http_fetch_limit(0)
            .build()
            .await
            .unwrap()
            .to_request_data();
        let limited = fetch_object_http_conditional::<_, TestActorKind>(
            &Url::parse("https://remote.example/actor")?,
            ConditionalRequestValidators::default(),
            &limited_data,
        )
        .await
        .unwrap_err();
        assert_eq!(limited, Error::RequestLimit);

        let server = FetchFixture::spawn().await;
        let timed_data = FederationConfig::builder()
            .domain("local.example")
            .app_data(())
            .debug(true)
            .request_timeout(Duration::from_millis(20))
            .build()
            .await
            .unwrap()
            .to_request_data();
        let timeout = fetch_object_http_conditional::<_, TestActorKind>(
            &server.url("/slow"),
            ConditionalRequestValidators::default(),
            &timed_data,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            timeout,
            Error::ReqwestMiddleware(_) | Error::Reqwest(_)
        ));

        let bounded_data = FederationConfig::builder()
            .domain("local.example")
            .app_data(())
            .debug(true)
            .build()
            .await
            .unwrap()
            .to_request_data();
        let oversized = fetch_object_http_conditional::<_, TestActorKind>(
            &server.url("/oversized"),
            ConditionalRequestValidators::default(),
            &bounded_data,
        )
        .await
        .unwrap_err();
        assert_eq!(oversized, Error::ResponseBodyLimit);

        Ok(())
    }
}
