//! Handles incoming activities, verifying HTTP signatures and other checks
//!
#![doc = include_str!("../../docs/08_receiving_activities.md")]

use crate::{
    config::Data,
    error::Error,
    http_signatures::{verify_actor_key_id, verify_body_hash, verify_signature},
    parse_received_activity,
    traits::{Activity, Actor, Object},
};
use axum::{
    body::Body,
    extract::FromRequest,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};
use http::{HeaderMap, Method, Uri};
use serde::de::DeserializeOwned;

const INBOX_BODY_LIMIT: usize = 1024 * 1024;
const BODY_LENGTH_LIMIT_ERROR: &str = "length limit exceeded";

/// Handles incoming activities, verifying HTTP signatures and other checks
pub async fn receive_activity<A, ActorT, Datatype>(
    activity_data: ActivityData,
    data: &Data<Datatype>,
) -> Result<(), <A as Activity>::Error>
where
    A: Activity<DataType = Datatype> + DeserializeOwned + Send + 'static,
    ActorT: Object<DataType = Datatype> + Actor + Send + Sync + 'static,
    for<'de2> <ActorT as Object>::Kind: serde::Deserialize<'de2>,
    <A as Activity>::Error: From<Error> + From<<ActorT as Object>::Error>,
    <ActorT as Object>::Error: From<Error>,
    Datatype: Clone,
{
    let (activity, actor) =
        parse_received_activity::<A, ActorT, _>(&activity_data.body, data).await?;

    verify_body_hash(activity_data.headers.get("digest"), &activity_data.body)?;
    let verified_signature = verify_signature(
        &activity_data.headers,
        &activity_data.method,
        &activity_data.uri,
        actor.public_key_pem(),
    )?;
    verify_actor_key_id(&actor, &verified_signature.key_id)?;

    activity.verify(data).await?;
    activity.receive(data).await?;
    Ok(())
}

/// Contains all data that is necessary to receive an activity from an HTTP request
#[allow(dead_code)]
#[derive(Debug)]
pub struct ActivityData {
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Vec<u8>,
}

impl<S> FromRequest<S> for ActivityData
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        #[allow(unused_mut)]
        let (mut parts, body) = req.into_parts();

        // take the full URI to handle nested routers
        // OriginalUri::from_request_parts has an Infallible error type
        #[cfg(feature = "axum-original-uri")]
        let uri = {
            use axum::extract::{FromRequestParts, OriginalUri};
            OriginalUri::from_request_parts(&mut parts, _state)
                .await
                .expect("infallible")
                .0
        };
        #[cfg(not(feature = "axum-original-uri"))]
        let uri = parts.uri;

        // this wont work if the body is an long running stream
        let bytes = axum::body::to_bytes(body, INBOX_BODY_LIMIT)
            .await
            .map_err(|err| {
                let status = if is_body_length_limit_error(&err) {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                };
                (status, err.to_string()).into_response()
            })?;

        Ok(Self {
            headers: parts.headers,
            method: parts.method,
            uri,
            body: bytes.to_vec(),
        })
    }
}

fn is_body_length_limit_error(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(err);
    while let Some(err) = current {
        if err.to_string() == BODY_LENGTH_LIMIT_ERROR {
            return true;
        }
        current = err.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{ActivityData, INBOX_BODY_LIMIT};
    use axum::{
        body::Body,
        extract::FromRequest,
        http::{Request, StatusCode},
    };

    fn request_with_body_size(size: usize) -> Request<Body> {
        Request::new(Body::from(vec![0; size]))
    }

    #[test]
    fn receive_activity_runs_protocol_checks_before_business_verify() {
        let source = include_str!("inbox.rs");
        let digest_index = source
            .find("verify_body_hash(")
            .expect("receive_activity should verify Digest body hash");
        let signature_index = source
            .find("verify_signature(")
            .expect("receive_activity should verify HTTP Signature");
        let binding_index = source
            .find("verify_actor_key_id(")
            .expect("receive_activity should bind key id to actor");
        let business_index = source
            .find("activity.verify(data).await?")
            .expect("receive_activity should still call business verify");

        assert!(digest_index < business_index);
        assert!(signature_index < business_index);
        assert!(binding_index < business_index);
    }

    #[tokio::test]
    async fn body_at_limit_is_accepted() {
        let activity_data =
            match ActivityData::from_request(request_with_body_size(INBOX_BODY_LIMIT), &()).await {
                Ok(activity_data) => activity_data,
                Err(response) => panic!(
                    "expected body at limit to be accepted, got {}",
                    response.status()
                ),
            };

        assert_eq!(activity_data.body.len(), INBOX_BODY_LIMIT);
    }

    #[tokio::test]
    async fn body_over_limit_is_rejected_with_payload_too_large() {
        let response =
            match ActivityData::from_request(request_with_body_size(INBOX_BODY_LIMIT + 1), &())
                .await
            {
                Ok(_) => panic!("expected body over limit to be rejected"),
                Err(response) => response,
            };

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[cfg(feature = "axum-original-uri")]
    #[tokio::test]
    async fn activity_data_uses_original_uri_under_nested_router() {
        use axum::{extract::OriginalUri, http::Uri};

        let request = Request::builder()
            .method("POST")
            .uri("/activitypub/inbox")
            .extension(OriginalUri(Uri::from_static("/api/activitypub/inbox")))
            .body(Body::from("{}"))
            .unwrap();

        let activity_data = ActivityData::from_request(request, &()).await.unwrap();

        assert_eq!(activity_data.uri.path(), "/api/activitypub/inbox");
    }
}
