#![allow(clippy::unwrap_used)]

use crate::{
    instance::{listen, new_instance},
    objects::post::DbPost,
    utils::generate_object_id,
};
use error::Error;
use tokio::try_join;
use tracing::log::{info, LevelFilter};

mod activities;
mod axum;
mod error;
mod instance;
mod objects;
mod utils;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::builder()
        .filter_level(LevelFilter::Warn)
        .filter_module("activitypub_federation", LevelFilter::Info)
        .filter_module("local_federation", LevelFilter::Info)
        .format_timestamp(None)
        .init();

    info!("Start local federation example with axum");

    let (alpha, beta) = try_join!(
        new_instance("localhost:8001", "alpha".to_string()),
        new_instance("localhost:8002", "beta".to_string())
    )?;
    listen(&alpha)?;
    listen(&beta)?;
    info!("Local instances started");

    info!("Alpha user follows beta user via webfinger");
    alpha
        .local_user()
        .follow("beta@localhost:8002", &alpha.to_request_data())
        .await?;
    assert_eq!(
        beta.local_user().followers(),
        &vec![alpha.local_user().ap_id.inner().clone()]
    );
    info!("Follow was successful");

    info!("Beta sends a post to its followers");
    let sent_post = DbPost::new("Hello world!".to_string(), beta.local_user().ap_id)?;
    beta.local_user()
        .post(sent_post.clone(), &beta.to_request_data())
        .await?;
    let received_post = alpha.posts.lock().unwrap().first().cloned().unwrap();
    info!("Alpha received post: {}", received_post.text);

    // assert that alpha received the post
    assert_eq!(received_post.text, sent_post.text);
    assert_eq!(received_post.ap_id.inner(), sent_post.ap_id.inner());
    assert_eq!(received_post.creator.inner(), sent_post.creator.inner());
    info!("Test completed");
    Ok(())
}
