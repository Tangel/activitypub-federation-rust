//! Handles incoming activities, verifying HTTP signatures and other checks
//!
#![doc = include_str!("../../docs/08_receiving_activities.md")]

use crate::{
    config::Data,
    error::Error,
    extract_id,
    fetch::object_id::ObjectId,
    http_signatures::{verify_actor_key_id, verify_body_hash, verify_signature},
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
use std::error::Error as StdError;
use url::Url;

const INBOX_BODY_LIMIT: usize = 1024 * 1024;
const BODY_LENGTH_LIMIT_ERROR: &str = "length limit exceeded";

/// Classification for failures returned by [`verify_activity`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationFailureClass {
    /// The activity body or its protocol identifiers are malformed.
    MalformedInput,
    /// The request body does not match its Digest header.
    Digest,
    /// The HTTP Signature is malformed, stale, or cryptographically invalid.
    Signature,
    /// The verified signing key does not belong to the activity Actor.
    ActorKeyMismatch,
    /// The activity Actor could not be fetched.
    ActorFetch,
    /// The activity Actor was fetched as a deleted object.
    DeletedActor,
    /// Application-specific activity verification rejected the activity.
    BusinessVerification,
    /// The actor fetch request limit was reached.
    RequestLimit,
}

/// Structured failure from protocol and business verification.
#[derive(Debug)]
pub struct VerificationFailure<E> {
    /// Stable classification of the verification stage which failed.
    pub class: VerificationFailureClass,
    /// Parsed activity Actor id, when available.
    pub actor_id: Option<Url>,
    /// Parsed HTTP Signature key id, when available.
    pub key_id: Option<Url>,
    /// Original error returned by the existing activity handler contract.
    pub source: E,
}

/// An activity which passed protocol and application-specific verification.
#[derive(Debug)]
pub struct VerifiedActivity<A, ActorT> {
    /// Parsed activity, not yet passed to [`Activity::receive`].
    pub activity: A,
    /// Resolved Actor used for signature verification.
    pub actor: ActorT,
    /// Actor id declared by the activity.
    pub actor_id: Url,
    /// Key id from the verified HTTP Signature.
    pub key_id: Url,
    /// Original bounded request body.
    pub body: Vec<u8>,
    /// Parsed activity id.
    pub activity_id: Url,
}

/// Verifies an incoming activity without invoking [`Activity::receive`].
pub async fn verify_activity<A, ActorT, Datatype>(
    activity_data: ActivityData,
    data: &Data<Datatype>,
) -> Result<VerifiedActivity<A, ActorT>, VerificationFailure<<A as Activity>::Error>>
where
    A: Activity<DataType = Datatype> + DeserializeOwned + Send + 'static,
    ActorT: Object<DataType = Datatype> + Actor + Send + Sync + 'static,
    for<'de2> <ActorT as Object>::Kind: serde::Deserialize<'de2>,
    <A as Activity>::Error: From<Error> + From<<ActorT as Object>::Error>,
    <ActorT as Object>::Error: From<Error> + StdError + 'static,
    Datatype: Clone,
{
    verify_activity_core(activity_data, data, |source: &<ActorT as Object>::Error| {
        classify_actor_fetch_failure(source as &(dyn StdError + 'static))
    })
    .await
}

async fn verify_activity_core<A, ActorT, Datatype, ClassifyActorFetchFailure>(
    activity_data: ActivityData,
    data: &Data<Datatype>,
    classify_actor_fetch_failure: ClassifyActorFetchFailure,
) -> Result<VerifiedActivity<A, ActorT>, VerificationFailure<<A as Activity>::Error>>
where
    A: Activity<DataType = Datatype> + DeserializeOwned + Send + 'static,
    ActorT: Object<DataType = Datatype> + Actor + Send + Sync + 'static,
    for<'de2> <ActorT as Object>::Kind: serde::Deserialize<'de2>,
    <A as Activity>::Error: From<Error> + From<<ActorT as Object>::Error>,
    <ActorT as Object>::Error: From<Error>,
    Datatype: Clone,
    ClassifyActorFetchFailure: FnOnce(&<ActorT as Object>::Error) -> VerificationFailureClass,
{
    let ActivityData {
        headers,
        method,
        uri,
        body,
    } = activity_data;
    let activity: A = sonic_rs::from_slice(&body).map_err(|err| VerificationFailure {
        class: VerificationFailureClass::MalformedInput,
        actor_id: None,
        key_id: None,
        source: Error::ParseReceivedActivity {
            err,
            id: extract_id(&body).ok(),
        }
        .into(),
    })?;
    let activity_id = activity.id().clone();
    let actor_id = activity.actor().clone();

    data.config
        .verify_url_and_domain(&activity)
        .await
        .map_err(|source| VerificationFailure {
            class: VerificationFailureClass::MalformedInput,
            actor_id: Some(actor_id.clone()),
            key_id: None,
            source: source.into(),
        })?;

    let actor = ObjectId::<ActorT>::from(actor_id.clone())
        .dereference(data)
        .await
        .map_err(|source| {
            let class = classify_actor_fetch_failure(&source);
            VerificationFailure {
                class,
                actor_id: Some(actor_id.clone()),
                key_id: None,
                source: source.into(),
            }
        })?;

    verify_body_hash(headers.get("digest"), &body).map_err(|source| VerificationFailure {
        class: VerificationFailureClass::Digest,
        actor_id: Some(actor_id.clone()),
        key_id: None,
        source: source.into(),
    })?;

    let verified_signature = verify_signature(&headers, &method, &uri, actor.public_key_pem())
        .map_err(|failure| VerificationFailure {
            class: VerificationFailureClass::Signature,
            actor_id: Some(actor_id.clone()),
            key_id: failure.key_id,
            source: failure.source.into(),
        })?;

    verify_actor_key_id(&actor, &verified_signature.key_id).map_err(|source| {
        VerificationFailure {
            class: VerificationFailureClass::ActorKeyMismatch,
            actor_id: Some(actor_id.clone()),
            key_id: Some(verified_signature.key_id.clone()),
            source: source.into(),
        }
    })?;

    activity
        .verify(data)
        .await
        .map_err(|source| VerificationFailure {
            class: VerificationFailureClass::BusinessVerification,
            actor_id: Some(actor_id.clone()),
            key_id: Some(verified_signature.key_id.clone()),
            source,
        })?;

    Ok(VerifiedActivity {
        activity,
        actor,
        actor_id,
        key_id: verified_signature.key_id,
        body,
        activity_id,
    })
}

fn classify_actor_fetch_failure(source: &(dyn StdError + 'static)) -> VerificationFailureClass {
    let mut current = Some(source);
    while let Some(error) = current {
        match error.downcast_ref::<Error>() {
            Some(Error::ObjectDeleted(_)) => return VerificationFailureClass::DeletedActor,
            Some(Error::RequestLimit) => return VerificationFailureClass::RequestLimit,
            _ => current = error.source(),
        }
    }
    VerificationFailureClass::ActorFetch
}

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
    let verified = verify_activity_core::<A, ActorT, Datatype, _>(activity_data, data, |_| {
        VerificationFailureClass::ActorFetch
    })
    .await
    .map_err(|failure| failure.source)?;
    verified.activity.receive(data).await?;
    Ok(())
}

/// Contains all data that is necessary to receive an activity from an HTTP request
#[allow(dead_code)]
#[derive(Clone, Debug)]
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
    use super::{
        receive_activity,
        verify_activity,
        ActivityData,
        VerificationFailureClass,
        INBOX_BODY_LIMIT,
    };
    use crate::{
        activity_sending::generate_request_headers,
        config::{Data, FederationConfig},
        error::Error,
        http_signatures::{sign_request, test::test_keypair},
        traits::{Activity, Actor, Object},
    };
    use axum::{
        body::Body,
        extract::FromRequest,
        http::{Request, StatusCode},
    };
    use bytes::Bytes;
    use http::{HeaderValue, Method, Uri};
    use reqwest::Client;
    use reqwest_middleware::ClientWithMiddleware;
    use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
    use serde::{Deserialize, Serialize};
    use std::{
        str::FromStr,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };
    use url::Url;

    const ACTOR_ID: &str = "https://example.com/u/alice";
    const ACTIVITY_ID: &str = "https://example.com/activities/1";
    const INBOX_URL: &str = "https://local.example/inbox";

    #[derive(Clone)]
    struct TestState {
        actor: TestActor,
        actor_fetch_failure: Option<ActorFetchFailure>,
        reject_business_verify: bool,
        receive_calls: Arc<AtomicUsize>,
    }

    #[derive(Clone, Copy)]
    enum ActorFetchFailure {
        Deleted,
        RequestLimit,
    }

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error("federation error: {0}")]
        Federation(#[from] Error),
        #[error("business verification rejected")]
        BusinessVerification,
        #[error("legacy actor error")]
        LegacyActor,
    }

    #[derive(Debug)]
    struct LegacyActorError;

    impl From<Error> for LegacyActorError {
        fn from(_: Error) -> Self {
            Self
        }
    }

    impl From<LegacyActorError> for TestError {
        fn from(_: LegacyActorError) -> Self {
            Self::LegacyActor
        }
    }

    #[derive(Clone, Debug)]
    struct TestActor {
        id: Url,
        public_key: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    struct TestActorJson {
        id: Url,
    }

    impl Object for TestActor {
        type DataType = TestState;
        type Kind = TestActorJson;
        type Error = TestError;

        fn id(&self) -> &Url {
            &self.id
        }

        async fn read_from_id(
            _object_id: Url,
            data: &Data<Self::DataType>,
        ) -> Result<Option<Self>, Self::Error> {
            match data.app_data().actor_fetch_failure {
                Some(ActorFetchFailure::Deleted) => {
                    return Err(Error::ObjectDeleted(data.app_data().actor.id.clone()).into());
                }
                Some(ActorFetchFailure::RequestLimit) => {
                    return Err(Error::RequestLimit.into());
                }
                None => {}
            }
            Ok(Some(data.app_data().actor.clone()))
        }

        async fn into_json(self, _data: &Data<Self::DataType>) -> Result<Self::Kind, Self::Error> {
            Ok(TestActorJson { id: self.id })
        }

        async fn verify(
            _json: &Self::Kind,
            _expected_domain: &Url,
            _data: &Data<Self::DataType>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn from_json(
            json: Self::Kind,
            data: &Data<Self::DataType>,
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                id: json.id,
                public_key: data.app_data().actor.public_key.clone(),
            })
        }
    }

    impl Actor for TestActor {
        fn public_key_pem(&self) -> &str {
            &self.public_key
        }

        fn private_key_pem(&self) -> Option<String> {
            None
        }

        fn inbox(&self) -> Url {
            Url::parse(INBOX_URL).unwrap()
        }
    }

    #[derive(Clone, Debug)]
    struct LegacyActor(TestActor);

    impl Object for LegacyActor {
        type DataType = TestState;
        type Kind = TestActorJson;
        type Error = LegacyActorError;

        fn id(&self) -> &Url {
            self.0.id()
        }

        async fn read_from_id(
            _object_id: Url,
            data: &Data<Self::DataType>,
        ) -> Result<Option<Self>, Self::Error> {
            Ok(Some(Self(data.app_data().actor.clone())))
        }

        async fn into_json(self, _data: &Data<Self::DataType>) -> Result<Self::Kind, Self::Error> {
            Ok(TestActorJson {
                id: self.0.id().clone(),
            })
        }

        async fn verify(
            _json: &Self::Kind,
            _expected_domain: &Url,
            _data: &Data<Self::DataType>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn from_json(
            json: Self::Kind,
            data: &Data<Self::DataType>,
        ) -> Result<Self, Self::Error> {
            Ok(Self(TestActor {
                id: json.id,
                public_key: data.app_data().actor.public_key.clone(),
            }))
        }
    }

    impl Actor for LegacyActor {
        fn public_key_pem(&self) -> &str {
            self.0.public_key_pem()
        }

        fn private_key_pem(&self) -> Option<String> {
            None
        }

        fn inbox(&self) -> Url {
            self.0.inbox()
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    struct TestActivity {
        actor: Url,
        id: Url,
        #[serde(rename = "type")]
        kind: String,
    }

    impl Activity for TestActivity {
        type DataType = TestState;
        type Error = TestError;

        fn id(&self) -> &Url {
            &self.id
        }

        fn actor(&self) -> &Url {
            &self.actor
        }

        async fn verify(&self, data: &Data<Self::DataType>) -> Result<(), Self::Error> {
            if data.app_data().reject_business_verify {
                return Err(TestError::BusinessVerification);
            }
            Ok(())
        }

        async fn receive(self, data: &Data<Self::DataType>) -> Result<(), Self::Error> {
            data.app_data().receive_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn activity_body() -> Vec<u8> {
        format!(r#"{{"actor":"{ACTOR_ID}","id":"{ACTIVITY_ID}","type":"Create"}}"#).into_bytes()
    }

    async fn test_data(actor_id: &str, reject_business_verify: bool) -> Data<TestState> {
        test_data_with_actor_failure(actor_id, reject_business_verify, None).await
    }

    async fn test_data_with_actor_failure(
        actor_id: &str,
        reject_business_verify: bool,
        actor_fetch_failure: Option<ActorFetchFailure>,
    ) -> Data<TestState> {
        let state = TestState {
            actor: TestActor {
                id: Url::parse(actor_id).unwrap(),
                public_key: test_keypair().public_key,
            },
            actor_fetch_failure,
            reject_business_verify,
            receive_calls: Arc::new(AtomicUsize::new(0)),
        };
        FederationConfig::builder()
            .domain("local.example")
            .app_data(state)
            .debug(true)
            .build()
            .await
            .unwrap()
            .to_request_data()
    }

    async fn signed_activity_data(body: Vec<u8>) -> ActivityData {
        let inbox_url = Url::parse(INBOX_URL).unwrap();
        let request_builder = ClientWithMiddleware::from(Client::new())
            .post(inbox_url.to_string())
            .headers(generate_request_headers(&inbox_url));
        let request = sign_request(
            request_builder,
            &Url::parse(ACTOR_ID).unwrap(),
            Bytes::from(body.clone()),
            RsaPrivateKey::from_pkcs8_pem(&test_keypair().private_key).unwrap(),
            false,
        )
        .await
        .unwrap();

        ActivityData {
            headers: request.headers().clone(),
            method: request.method().clone(),
            uri: Uri::from_str(request.url().as_str()).unwrap(),
            body,
        }
    }

    fn request_with_body_size(size: usize) -> Request<Body> {
        Request::new(Body::from(vec![0; size]))
    }

    #[tokio::test]
    async fn verify_activity_classifies_malformed_json() {
        let data = test_data(ACTOR_ID, false).await;
        let activity_data = ActivityData {
            headers: Default::default(),
            method: Method::POST,
            uri: Uri::from_static("/inbox"),
            body: b"{".to_vec(),
        };

        let failure = verify_activity::<TestActivity, TestActor, TestState>(activity_data, &data)
            .await
            .unwrap_err();

        assert_eq!(failure.class, VerificationFailureClass::MalformedInput);
        assert!(failure.actor_id.is_none());
        assert!(failure.key_id.is_none());
    }

    #[tokio::test]
    async fn verify_activity_classifies_bad_digest() {
        let data = test_data(ACTOR_ID, false).await;
        let mut activity_data = signed_activity_data(activity_body()).await;
        activity_data.headers.insert(
            "digest",
            HeaderValue::from_static("SHA-256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        );

        let failure = verify_activity::<TestActivity, TestActor, TestState>(activity_data, &data)
            .await
            .unwrap_err();

        assert_eq!(failure.class, VerificationFailureClass::Digest);
        assert_eq!(failure.actor_id.as_ref().unwrap().as_str(), ACTOR_ID);
        assert!(failure.key_id.is_none());
    }

    #[tokio::test]
    async fn invalid_signature_retains_actor_and_key_ids() {
        let data = test_data(ACTOR_ID, false).await;
        let mut activity_data = signed_activity_data(activity_body()).await;
        let signature = activity_data.headers.get("signature").unwrap().as_bytes();
        let mut tampered = signature.to_vec();
        let signature_value_start = signature
            .windows(b"signature=\"".len())
            .position(|window| window == b"signature=\"")
            .unwrap()
            + b"signature=\"".len();
        tampered[signature_value_start] = if tampered[signature_value_start] == b'A' {
            b'B'
        } else {
            b'A'
        };
        activity_data
            .headers
            .insert("signature", HeaderValue::from_bytes(&tampered).unwrap());

        let failure = verify_activity::<TestActivity, TestActor, TestState>(activity_data, &data)
            .await
            .unwrap_err();

        assert_eq!(failure.class, VerificationFailureClass::Signature);
        assert_eq!(failure.actor_id.as_ref().unwrap().as_str(), ACTOR_ID);
        assert_eq!(
            failure.key_id.as_ref().unwrap().as_str(),
            "https://example.com/u/alice#main-key"
        );
    }

    #[tokio::test]
    async fn verify_activity_classifies_actor_key_mismatch() {
        let data = test_data("https://example.com/u/bob", false).await;
        let activity_data = signed_activity_data(activity_body()).await;

        let failure = verify_activity::<TestActivity, TestActor, TestState>(activity_data, &data)
            .await
            .unwrap_err();

        assert_eq!(failure.class, VerificationFailureClass::ActorKeyMismatch);
        assert_eq!(failure.actor_id.as_ref().unwrap().as_str(), ACTOR_ID);
        assert_eq!(
            failure.key_id.as_ref().unwrap().as_str(),
            "https://example.com/u/alice#main-key"
        );
    }

    #[tokio::test]
    async fn verify_activity_classifies_wrapped_deleted_actor() {
        let data =
            test_data_with_actor_failure(ACTOR_ID, false, Some(ActorFetchFailure::Deleted)).await;
        let activity_data = signed_activity_data(activity_body()).await;

        let failure = verify_activity::<TestActivity, TestActor, TestState>(activity_data, &data)
            .await
            .unwrap_err();

        assert_eq!(failure.class, VerificationFailureClass::DeletedActor);
    }

    #[tokio::test]
    async fn verify_activity_classifies_wrapped_request_limit() {
        let data =
            test_data_with_actor_failure(ACTOR_ID, false, Some(ActorFetchFailure::RequestLimit))
                .await;
        let activity_data = signed_activity_data(activity_body()).await;

        let failure = verify_activity::<TestActivity, TestActor, TestState>(activity_data, &data)
            .await
            .unwrap_err();

        assert_eq!(failure.class, VerificationFailureClass::RequestLimit);
    }

    #[tokio::test]
    async fn verify_activity_classifies_business_verify_rejection() {
        let data = test_data(ACTOR_ID, true).await;
        let activity_data = signed_activity_data(activity_body()).await;

        let failure = verify_activity::<TestActivity, TestActor, TestState>(activity_data, &data)
            .await
            .unwrap_err();

        assert_eq!(
            failure.class,
            VerificationFailureClass::BusinessVerification
        );
        assert_eq!(data.app_data().receive_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn verify_only_has_no_effect_and_receive_runs_once() {
        let data = test_data(ACTOR_ID, false).await;
        let verified = verify_activity::<TestActivity, TestActor, TestState>(
            signed_activity_data(activity_body()).await,
            &data,
        )
        .await
        .unwrap();

        assert_eq!(data.app_data().receive_calls.load(Ordering::SeqCst), 0);
        assert_eq!(verified.activity.id().as_str(), ACTIVITY_ID);
        assert_eq!(verified.actor.id().as_str(), ACTOR_ID);
        assert_eq!(verified.activity_id.as_str(), ACTIVITY_ID);
        assert_eq!(verified.actor_id.as_str(), ACTOR_ID);
        assert_eq!(
            verified.key_id.as_str(),
            "https://example.com/u/alice#main-key"
        );
        assert_eq!(verified.body, activity_body());

        receive_activity::<TestActivity, TestActor, TestState>(
            signed_activity_data(activity_body()).await,
            &data,
        )
        .await
        .unwrap();

        assert_eq!(data.app_data().receive_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn replayable_activity_data_supports_two_complete_verifications_without_receiving() {
        let data = test_data(ACTOR_ID, false).await;
        let activity_data = signed_activity_data(activity_body()).await;

        let first =
            verify_activity::<TestActivity, TestActor, TestState>(activity_data.clone(), &data)
                .await
                .unwrap();
        let second = verify_activity::<TestActivity, TestActor, TestState>(activity_data, &data)
            .await
            .unwrap();

        assert_eq!(first.body, second.body);
        assert_eq!(first.activity_id, second.activity_id);
        assert_eq!(first.actor_id, second.actor_id);
        assert_eq!(first.key_id, second.key_id);
        assert_eq!(data.app_data().receive_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn receive_activity_accepts_legacy_actor_error_without_std_error() {
        let data = test_data(ACTOR_ID, false).await;

        receive_activity::<TestActivity, LegacyActor, TestState>(
            signed_activity_data(activity_body()).await,
            &data,
        )
        .await
        .unwrap();

        assert_eq!(data.app_data().receive_calls.load(Ordering::SeqCst), 1);
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
