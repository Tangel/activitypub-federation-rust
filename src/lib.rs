#![doc = include_str!("../docs/01_intro.md")]
#![doc = include_str!("../docs/02_overview.md")]
#![doc = include_str!("../docs/03_federating_users.md")]
#![doc = include_str!("../docs/04_federating_posts.md")]
#![doc = include_str!("../docs/05_configuration.md")]
#![doc = include_str!("../docs/06_http_endpoints_axum.md")]
#![doc = include_str!("../docs/07_fetching_data.md")]
#![doc = include_str!("../docs/08_receiving_activities.md")]
#![doc = include_str!("../docs/09_sending_activities.md")]
#![doc = include_str!("../docs/10_fetching_objects_with_unknown_type.md")]
#![deny(missing_docs)]

pub mod activity_queue;
pub mod activity_sending;
#[cfg(feature = "axum")]
pub mod axum;
pub mod config;
pub mod error;
pub mod fetch;
pub mod http_signatures;
pub mod protocol;
pub(crate) mod reqwest_shim;
pub mod traits;
mod utils;

pub use activity_queue::{
    activity_queue_snapshot,
    wait_for_activity_queue_idle,
    QueueDrainOutcome,
    QueueSnapshot,
};
pub use activitystreams_kinds as kinds;

use serde::Deserialize;
use url::Url;

/// Mime type for Activitypub data, used for `Accept` and `Content-Type` HTTP headers
pub const FEDERATION_CONTENT_TYPE: &str = "application/activity+json";

/// Attempt to parse id field from serialized json
pub(crate) fn extract_id(data: &[u8]) -> sonic_rs::Result<Url> {
    #[derive(Deserialize)]
    struct Id {
        id: Url,
    }
    Ok(sonic_rs::from_slice::<Id>(data)?.id)
}
