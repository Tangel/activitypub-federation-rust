//! Queue for signing and sending outgoing activities with retry
//!
#![doc = include_str!("../docs/09_sending_activities.md")]

use crate::{
    config::Data,
    error::Error,
    http_signatures::sign_request,
    reqwest_shim::ResponseExt,
    traits::{Activity, Actor},
    FEDERATION_CONTENT_TYPE,
};
use bytes::Bytes;
use futures::StreamExt;
use http::StatusCode;
use httpdate::{fmt_http_date, parse_http_date};
use itertools::Itertools;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, LOCATION, RETRY_AFTER},
    Request,
    Response,
};
use reqwest_middleware::ClientWithMiddleware;
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use serde::Serialize;
use std::{
    fmt::{Debug, Display},
    time::{Duration, Instant, SystemTime},
};
use tracing::{debug, warn};
use url::Url;

const MAX_RESPONSE_DETAIL_BYTES: usize = 1024;
const MAX_RETRY_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// Result of exactly one attempt to deliver an activity to a remote inbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    /// The remote inbox accepted the activity with a successful response.
    Delivered {
        /// Successful HTTP response status.
        status: StatusCode,
    },
    /// The remote inbox requested a redirect. Redirects are never followed automatically.
    Redirect {
        /// Redirect HTTP response status.
        status: StatusCode,
        /// Resolved Location URL, if the response included a valid value.
        location: Option<Url>,
        /// Sanitized and bounded response body detail.
        detail: Option<String>,
    },
    /// The delivery may succeed if retried later.
    Retryable {
        /// Retryable HTTP response status.
        status: Option<StatusCode>,
        /// Server-requested delay, capped at 24 hours.
        retry_after: Option<Duration>,
        /// Sanitized and bounded response body detail.
        detail: Option<String>,
    },
    /// The remote inbox permanently rejected the activity.
    Terminal {
        /// Terminal HTTP response status.
        status: Option<StatusCode>,
        /// Sanitized and bounded response body detail.
        detail: Option<String>,
    },
    /// The request could not be signed or executed.
    TransportFailure {
        /// Sanitized and bounded signing or transport error detail.
        detail: String,
    },
}

#[derive(Clone, Debug)]
/// All info needed to sign and send one activity to one inbox. You should generally use
/// [[crate::activity_queue::queue_activity]] unless you want implement your own queue.
pub struct SendActivityTask {
    pub(crate) actor_id: Url,
    pub(crate) activity_id: Url,
    pub(crate) activity: Bytes,
    pub(crate) inbox: Url,
    pub(crate) private_key: RsaPrivateKey,
    pub(crate) http_signature_compat: bool,
}

impl Display for SendActivityTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} to {}", self.activity_id, self.inbox)
    }
}

impl SendActivityTask {
    /// Prepare an activity for sending
    ///
    /// - `activity`: The activity to be sent, gets converted to json
    /// - `inboxes`: List of remote actor inboxes that should receive the activity. Ignores local actor
    ///   inboxes. Should be built by calling [crate::traits::Actor::shared_inbox_or_inbox]
    ///   for each target actor.
    pub async fn prepare<A, Datatype, ActorType>(
        activity: &A,
        actor: &ActorType,
        inboxes: Vec<Url>,
        data: &Data<Datatype>,
    ) -> Result<Vec<SendActivityTask>, Error>
    where
        A: Activity + Serialize + Debug,
        Datatype: Clone,
        ActorType: Actor,
    {
        build_tasks(activity, actor, inboxes, data).await
    }

    /// convert a sendactivitydata to a request, signing and sending it
    pub async fn sign_and_send<Datatype: Clone>(&self, data: &Data<Datatype>) -> Result<(), Error> {
        self.sign_and_send_internal(&data.config.client, data.config.request_timeout)
            .await
    }

    /// Attempt to deliver this activity exactly once without following redirects or retrying.
    pub async fn send_once<Datatype: Clone>(&self, data: &Data<Datatype>) -> SendOutcome {
        self.send_once_internal(
            data.config.one_shot_client.client(),
            data.config.request_timeout,
        )
        .await
    }

    /// Activity identifier used for durable-delivery tracing.
    pub fn activity_id(&self) -> &Url {
        &self.activity_id
    }

    /// Remote inbox targeted by this delivery task.
    pub fn inbox(&self) -> &Url {
        &self.inbox
    }

    pub(crate) async fn sign_and_send_internal(
        &self,
        client: &ClientWithMiddleware,
        timeout: Duration,
    ) -> Result<(), Error> {
        self.send_once_internal(client, timeout)
            .await
            .into_legacy_result(self)
    }

    async fn send_once_internal(
        &self,
        client: &ClientWithMiddleware,
        timeout: Duration,
    ) -> SendOutcome {
        debug!("Sending {} to {}", self.activity_id, self.inbox,);
        let request = match self.build_signed_request(client, timeout).await {
            Ok(request) => request,
            Err(error) => return SendOutcome::transport_failure(error),
        };

        // Send the activity, and log a warning if its too slow.
        let now = Instant::now();
        let response = match client.execute(request).await {
            Ok(response) => response,
            Err(error) => return SendOutcome::transport_failure(error),
        };
        let elapsed = now.elapsed().as_secs();
        if elapsed > 10 {
            warn!(
                "Sending activity {} to {} took {}s",
                self.activity_id, self.inbox, elapsed
            );
        }
        Self::classify_response(response).await
    }

    async fn build_signed_request(
        &self,
        client: &ClientWithMiddleware,
        timeout: Duration,
    ) -> Result<Request, Error> {
        let request_builder = client
            .post(self.inbox.to_string())
            .timeout(timeout)
            .headers(generate_request_headers(&self.inbox));
        sign_request(
            request_builder,
            &self.actor_id,
            self.activity.clone(),
            self.private_key.clone(),
            self.http_signature_compat,
        )
        .await
    }

    /// Based on the HTTP status code determines if an activity was delivered successfully. In that case
    /// Ok is returned. Otherwise it returns Err and the activity send should be retried later.
    ///
    /// Equivalent code in mastodon: https://github.com/mastodon/mastodon/blob/v4.2.8/app/helpers/jsonld_helper.rb#L215-L217
    async fn handle_response(&self, response: Response) -> Result<(), Error> {
        Self::classify_response(response)
            .await
            .into_legacy_result(self)
    }

    async fn classify_response(response: Response) -> SendOutcome {
        let status = response.status();
        if status.is_success() {
            return SendOutcome::Delivered { status };
        }

        let response_url = response.url().clone();
        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| response_url.join(value).ok());
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_retry_after);
        let detail = response.text_limited().await.map_or_else(
            |error| Some(bounded_detail(&error.to_string())),
            |detail| optional_bounded_detail(&detail),
        );

        if status.is_redirection() {
            SendOutcome::Redirect {
                status,
                location,
                detail,
            }
        } else if matches!(
            status,
            StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY | StatusCode::TOO_MANY_REQUESTS
        ) || status.is_server_error()
        {
            SendOutcome::Retryable {
                status: Some(status),
                retry_after,
                detail,
            }
        } else {
            SendOutcome::Terminal {
                status: Some(status),
                detail,
            }
        }
    }
}

impl SendOutcome {
    fn transport_failure(error: impl Display) -> Self {
        Self::TransportFailure {
            detail: bounded_detail(&error.to_string()),
        }
    }

    fn into_legacy_result(self, task: &SendActivityTask) -> Result<(), Error> {
        match self {
            Self::Delivered { .. } => {
                debug!("Activity {task} delivered successfully");
                Ok(())
            }
            Self::Terminal { detail, .. } => {
                debug!(
                    "Activity {task} was rejected, aborting: {}",
                    detail.as_deref().unwrap_or_default()
                );
                Ok(())
            }
            Self::Redirect { status, detail, .. } => Err(Error::Other(format!(
                "Activity {task} failure with status {status}: {}",
                detail.as_deref().unwrap_or_default()
            ))),
            Self::Retryable { status, detail, .. } => Err(Error::Other(format!(
                "Activity {task} failure with status {}: {}",
                status.map_or_else(|| "unknown".to_owned(), |status| status.to_string()),
                detail.as_deref().unwrap_or_default()
            ))),
            Self::TransportFailure { detail } => Err(Error::Other(format!(
                "Activity {task} transport failure: {detail}",
            ))),
        }
    }
}

fn parse_retry_after(value: &str) -> Option<Duration> {
    let duration = value.parse::<u64>().map(Duration::from_secs).or_else(|_| {
        parse_http_date(value).map(|retry_at| {
            retry_at
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO)
        })
    });
    duration.ok().map(|duration| duration.min(MAX_RETRY_AFTER))
}

fn bounded_detail(detail: &str) -> String {
    let sanitized: String = detail
        .chars()
        .filter(|character| !character.is_ascii_control())
        .collect();
    if sanitized.len() <= MAX_RESPONSE_DETAIL_BYTES {
        return sanitized;
    }

    let mut boundary = MAX_RESPONSE_DETAIL_BYTES;
    while !sanitized.is_char_boundary(boundary) {
        boundary -= 1;
    }
    sanitized[..boundary].to_owned()
}

fn optional_bounded_detail(detail: &str) -> Option<String> {
    let detail = bounded_detail(detail);
    (!detail.is_empty()).then_some(detail)
}

pub(crate) async fn build_tasks<A, Datatype, ActorType>(
    activity: &A,
    actor: &ActorType,
    inboxes: Vec<Url>,
    data: &Data<Datatype>,
) -> Result<Vec<SendActivityTask>, Error>
where
    A: Activity + Serialize + Debug,
    Datatype: Clone,
    ActorType: Actor,
{
    let config = &data.config;
    let actor_id = activity.actor();
    let activity_id = activity.id();
    let activity_serialized: Bytes = sonic_rs::to_vec(activity)
        .map_err(|e| Error::SerializeOutgoingActivity(e, format!("{:?}", activity)))?
        .into();
    let private_key = get_pkey_cached(data, actor).await?;

    Ok(futures::stream::iter(
        inboxes
            .into_iter()
            .unique()
            .filter(|i| !config.is_local_url(i)),
    )
    .filter_map(|inbox| async {
        if let Err(err) = config.verify_url_valid(&inbox).await {
            debug!("inbox url invalid, skipping: {inbox}: {err}");
            return None;
        };
        Some(SendActivityTask {
            actor_id: actor_id.clone(),
            activity_id: activity_id.clone(),
            inbox,
            activity: activity_serialized.clone(),
            private_key: private_key.clone(),
            http_signature_compat: config.http_signature_compat,
        })
    })
    .collect()
    .await)
}

pub(crate) async fn get_pkey_cached<ActorType>(
    data: &Data<impl Clone>,
    actor: &ActorType,
) -> Result<RsaPrivateKey, Error>
where
    ActorType: Actor,
{
    let actor_id = actor.id();
    // PKey is internally like an Arc<>, so cloning is ok
    data.config
        .actor_pkey_cache
        .try_get_with_by_ref(actor_id, async {
            let private_key_pem = actor.private_key_pem().ok_or_else(|| {
                Error::Other(format!(
                    "Actor {actor_id} does not contain a private key for signing"
                ))
            })?;

            // This is a mostly expensive blocking call, we don't want to tie up other tasks while this is happening
            let pkey = tokio::task::spawn_blocking(move || {
                RsaPrivateKey::from_pkcs8_pem(&private_key_pem).map_err(|err| {
                    Error::Other(format!("Could not create private key from PEM data:{err}"))
                })
            })
            .await
            .map_err(|err| Error::Other(format!("Error joining: {err}")))??;
            std::result::Result::<RsaPrivateKey, Error>::Ok(pkey)
        })
        .await
        .map_err(|e| Error::Other(format!("cloned error: {e}")))
}

pub(crate) fn generate_request_headers(inbox_url: &Url) -> HeaderMap {
    let mut host = inbox_url.domain().expect("read inbox domain").to_string();
    if let Some(port) = inbox_url.port() {
        host = format!("{}:{}", host, port);
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static(FEDERATION_CONTENT_TYPE),
    );
    headers.insert(
        HeaderName::from_static("host"),
        HeaderValue::from_str(&host).expect("Hostname is valid"),
    );
    headers.insert(
        "date",
        HeaderValue::from_str(&fmt_http_date(SystemTime::now())).expect("Date is valid"),
    );
    headers
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{
        config::{FederationConfig, OneShotClient},
        http_signatures::generate_actor_keypair,
    };
    use reqwest::{redirect::Policy, Client};
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Instant,
    };
    use tracing::info;

    // This will periodically send back internal errors to test the retry
    async fn dodgy_handler(headers: HeaderMap, body: Bytes) -> Result<(), StatusCode> {
        debug!("Headers:{:?}", headers);
        debug!("Body len:{}", body.len());
        Ok(())
    }

    async fn test_server() {
        use axum::{routing::post, Router};

        // We should break every now and then ;)
        let state = Arc::new(AtomicUsize::new(0));

        let app = Router::new()
            .route("/", post(dodgy_handler))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("0.0.0.0:8001").await.unwrap();
        axum::serve(listener, app.into_make_service()).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    // Sends 100 messages
    async fn test_activity_sending() -> anyhow::Result<()> {
        let num_messages: usize = 100;

        tokio::spawn(test_server());

        /*
        // uncomment for debug logs & stats
        use tracing::log::LevelFilter;

        env_logger::builder()
            .filter_level(LevelFilter::Warn)
            .filter_module("activitypub_federation", LevelFilter::Info)
            .format_timestamp(None)
            .init();

        */
        let keypair = generate_actor_keypair().unwrap();

        let message = SendActivityTask {
            actor_id: "http://localhost:8001".parse().unwrap(),
            activity_id: "http://localhost:8001/activity".parse().unwrap(),
            activity: "{}".into(),
            inbox: "http://localhost:8001".parse().unwrap(),
            private_key: keypair.private_key().unwrap(),
            http_signature_compat: true,
        };
        let data = FederationConfig::builder()
            .app_data(())
            .domain("localhost")
            .build()
            .await?
            .to_request_data();

        let start = Instant::now();

        for _ in 0..num_messages {
            message.clone().sign_and_send(&data).await?;
        }

        info!("Queue Sent: {:?}", start.elapsed());
        Ok(())
    }

    #[tokio::test]
    async fn classifies_http_responses_into_send_outcomes() {
        let res = |status, headers: &[(&str, &str)], body: Vec<u8>| {
            let mut response = http::Response::builder().status(status);
            for (name, value) in headers {
                response = response.header(*name, *value);
            }
            response.body(body).unwrap().into()
        };

        let ok = SendActivityTask::classify_response(res(StatusCode::OK, &[], vec![])).await;
        assert!(matches!(
            ok,
            SendOutcome::Delivered {
                status: StatusCode::OK
            }
        ));

        let redirect = SendActivityTask::classify_response(res(
            StatusCode::MOVED_PERMANENTLY,
            &[("location", "https://example.com/inbox")],
            b"moved".to_vec(),
        ))
        .await;
        assert!(matches!(
            redirect,
            SendOutcome::Redirect {
                status: StatusCode::MOVED_PERMANENTLY,
                location: Some(ref location),
                detail: Some(ref detail),
            } if location == &Url::parse("https://example.com/inbox").unwrap()
                && detail == "moved"
        ));

        let redirect_without_location =
            SendActivityTask::classify_response(res(StatusCode::MOVED_PERMANENTLY, &[], vec![]))
                .await;
        assert!(matches!(
            redirect_without_location,
            SendOutcome::Redirect { location: None, .. }
        ));

        for status in [
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::TOO_EARLY,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            let retryable = SendActivityTask::classify_response(res(status, &[], vec![])).await;
            assert!(
                matches!(retryable, SendOutcome::Retryable { status: Some(actual), detail: None, .. } if actual == status)
            );
        }

        let limited = SendActivityTask::classify_response(res(
            StatusCode::TOO_MANY_REQUESTS,
            &[("retry-after", "90000")],
            b"slow down".to_vec(),
        ))
        .await;
        assert!(matches!(
            limited,
            SendOutcome::Retryable {
                status: Some(StatusCode::TOO_MANY_REQUESTS),
                retry_after: Some(duration),
                detail: Some(ref detail),
            } if duration == Duration::from_secs(24 * 60 * 60) && detail == "slow down"
        ));

        let retry_date = fmt_http_date(SystemTime::now() + Duration::from_secs(48 * 60 * 60));
        let limited_by_date = SendActivityTask::classify_response(res(
            StatusCode::TOO_MANY_REQUESTS,
            &[("retry-after", &retry_date)],
            vec![],
        ))
        .await;
        assert!(matches!(
            limited_by_date,
            SendOutcome::Retryable {
                retry_after: Some(duration),
                ..
            } if duration == Duration::from_secs(24 * 60 * 60)
        ));

        for status in [StatusCode::BAD_REQUEST, StatusCode::GONE] {
            let terminal = SendActivityTask::classify_response(res(status, &[], vec![])).await;
            assert!(
                matches!(terminal, SendOutcome::Terminal { status: Some(actual), detail: None } if actual == status)
            );
        }

        let bad_request = SendActivityTask::classify_response(res(
            StatusCode::BAD_REQUEST,
            &[],
            b"bad request".to_vec(),
        ))
        .await;
        assert!(matches!(bad_request, SendOutcome::Terminal { .. }));

        let oversized = SendActivityTask::classify_response(res(
            StatusCode::INTERNAL_SERVER_ERROR,
            &[],
            format!("{}\0\nend", "é".repeat(700)).into_bytes(),
        ))
        .await;
        let detail = match oversized {
            SendOutcome::Retryable {
                detail: Some(detail),
                ..
            } => detail,
            outcome => panic!("expected retryable outcome, got {outcome:?}"),
        };
        assert!(detail.len() <= 1024);
        assert!(detail.is_char_boundary(detail.len()));
        assert!(!detail.chars().any(char::is_control));
    }

    #[tokio::test]
    async fn oversized_response_body_preserves_redirect_classification() {
        let response = http::Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .body(vec![b'x'; 1024 * 1024 + 1])
            .unwrap()
            .into();

        let outcome = SendActivityTask::classify_response(response).await;

        assert!(matches!(
            outcome,
            SendOutcome::Redirect {
                status: StatusCode::MOVED_PERMANENTLY,
                detail: Some(ref detail),
                ..
            } if detail.len() <= MAX_RESPONSE_DETAIL_BYTES
        ));
    }

    #[tokio::test]
    async fn invalid_utf8_response_body_preserves_status_classification() {
        let res = |status| {
            http::Response::builder()
                .status(status)
                .body(vec![0xff])
                .unwrap()
                .into()
        };

        let retryable =
            SendActivityTask::classify_response(res(StatusCode::INTERNAL_SERVER_ERROR)).await;
        assert!(matches!(
            retryable,
            SendOutcome::Retryable {
                status: Some(StatusCode::INTERNAL_SERVER_ERROR),
                detail: Some(ref detail),
                ..
            } if detail.len() <= MAX_RESPONSE_DETAIL_BYTES
        ));

        let terminal = SendActivityTask::classify_response(res(StatusCode::BAD_REQUEST)).await;
        assert!(matches!(
            terminal,
            SendOutcome::Terminal {
                status: Some(StatusCode::BAD_REQUEST),
                detail: Some(ref detail),
            } if detail.len() <= MAX_RESPONSE_DETAIL_BYTES
        ));
    }

    #[tokio::test]
    async fn send_once_returns_redirect_without_following_it() {
        use axum::{extract::State, response::Redirect, routing::post, Router};

        #[derive(Clone)]
        struct Counts {
            redirect: Arc<AtomicUsize>,
            target: Arc<AtomicUsize>,
        }

        async fn redirect_handler(State(counts): State<Counts>) -> Redirect {
            counts.redirect.fetch_add(1, Ordering::SeqCst);
            Redirect::permanent("/target")
        }

        async fn target_handler(State(counts): State<Counts>) {
            counts.target.fetch_add(1, Ordering::SeqCst);
        }

        let counts = Counts {
            redirect: Arc::new(AtomicUsize::new(0)),
            target: Arc::new(AtomicUsize::new(0)),
        };
        let app = Router::new()
            .route("/redirect", post(redirect_handler))
            .route("/target", post(target_handler))
            .with_state(counts.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service()).await;
        });

        let one_shot_client =
            OneShotClient::from_builder(Client::builder().redirect(Policy::limited(10))).unwrap();
        let data = FederationConfig::builder()
            .app_data(())
            .domain("localhost")
            .one_shot_client(one_shot_client)
            .build()
            .await
            .unwrap()
            .to_request_data();
        let keypair = generate_actor_keypair().unwrap();
        let message = SendActivityTask {
            actor_id: format!("http://localhost:{}/actor", address.port())
                .parse()
                .unwrap(),
            activity_id: format!("http://localhost:{}/activity", address.port())
                .parse()
                .unwrap(),
            activity: "{}".into(),
            inbox: format!("http://localhost:{}/redirect", address.port())
                .parse()
                .unwrap(),
            private_key: keypair.private_key().unwrap(),
            http_signature_compat: true,
        };

        let outcome = message.send_once(&data).await;
        let expected_location: Url = format!("http://localhost:{}/target", address.port())
            .parse()
            .unwrap();
        assert!(matches!(
            outcome,
            SendOutcome::Redirect {
                location: Some(location),
                ..
            } if location == expected_location
        ));
        assert_eq!(counts.redirect.load(Ordering::SeqCst), 1);
        assert_eq!(counts.target.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn send_once_classifies_transport_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let data = FederationConfig::builder()
            .app_data(())
            .domain("localhost")
            .build()
            .await
            .unwrap()
            .to_request_data();
        let keypair = generate_actor_keypair().unwrap();
        let message = SendActivityTask {
            actor_id: format!("http://localhost:{}/actor", address.port())
                .parse()
                .unwrap(),
            activity_id: format!("http://localhost:{}/activity", address.port())
                .parse()
                .unwrap(),
            activity: "{}".into(),
            inbox: format!("http://localhost:{}/inbox", address.port())
                .parse()
                .unwrap(),
            private_key: keypair.private_key().unwrap(),
            http_signature_compat: true,
        };

        let outcome = message.send_once(&data).await;
        assert!(matches!(outcome, SendOutcome::TransportFailure { .. }));
    }

    #[tokio::test]
    async fn legacy_send_maps_transport_failure_to_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let keypair = generate_actor_keypair().unwrap();
        let message = SendActivityTask {
            actor_id: format!("http://localhost:{}/actor", address.port())
                .parse()
                .unwrap(),
            activity_id: format!("http://localhost:{}/activity", address.port())
                .parse()
                .unwrap(),
            activity: "{}".into(),
            inbox: format!("http://localhost:{}/inbox", address.port())
                .parse()
                .unwrap(),
            private_key: keypair.private_key().unwrap(),
            http_signature_compat: true,
        };
        let client: ClientWithMiddleware = Client::builder().build().unwrap().into();

        assert!(message
            .sign_and_send_internal(&client, Duration::from_secs(1))
            .await
            .is_err());
    }

    #[test]
    fn exposes_only_delivery_trace_identifiers() {
        let keypair = generate_actor_keypair().unwrap();
        let message = SendActivityTask {
            actor_id: "http://localhost:8001".parse().unwrap(),
            activity_id: "http://localhost:8001/activity".parse().unwrap(),
            activity: "{}".into(),
            inbox: "http://localhost:8001/inbox".parse().unwrap(),
            private_key: keypair.private_key().unwrap(),
            http_signature_compat: true,
        };

        assert_eq!(
            message.activity_id().as_str(),
            "http://localhost:8001/activity"
        );
        assert_eq!(message.inbox().as_str(), "http://localhost:8001/inbox");
    }

    #[tokio::test]
    async fn legacy_response_mapping_preserves_queue_behavior() {
        let keypair = generate_actor_keypair().unwrap();
        let message = SendActivityTask {
            actor_id: "http://localhost:8001".parse().unwrap(),
            activity_id: "http://localhost:8001/activity".parse().unwrap(),
            activity: "{}".into(),
            inbox: "http://localhost:8001".parse().unwrap(),
            private_key: keypair.private_key().unwrap(),
            http_signature_compat: true,
        };
        let res = |status| {
            http::Response::builder()
                .status(status)
                .body(vec![])
                .unwrap()
                .into()
        };

        assert!(message.handle_response(res(StatusCode::OK)).await.is_ok());
        assert!(message
            .handle_response(res(StatusCode::BAD_REQUEST))
            .await
            .is_ok());

        assert!(message
            .handle_response(res(StatusCode::MOVED_PERMANENTLY))
            .await
            .is_err());
        assert!(message
            .handle_response(res(StatusCode::REQUEST_TIMEOUT))
            .await
            .is_err());
        assert!(message
            .handle_response(res(StatusCode::TOO_MANY_REQUESTS))
            .await
            .is_err());
        assert!(message
            .handle_response(res(StatusCode::INTERNAL_SERVER_ERROR))
            .await
            .is_err());
    }
}
