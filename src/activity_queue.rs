//! Queue for signing and sending outgoing activities with retry
//!
#![doc = include_str!("../docs/09_sending_activities.md")]

use crate::{
    activity_sending::{build_tasks, SendActivityTask},
    config::Data,
    error::Error,
    traits::{Activity, Actor},
};

use futures_core::Future;

use reqwest_middleware::ClientWithMiddleware;
use serde::Serialize;
use std::{
    fmt::{Debug, Display},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    sync::mpsc::{unbounded_channel, UnboundedSender},
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use tracing::{info, warn};
use url::Url;

/// Read-only, best-effort snapshot of activity queue counters.
///
/// Each field is loaded independently with relaxed atomic ordering. The resulting snapshot is
/// observational rather than atomic or linearizable, so fields can reflect different moments
/// while workers transition between counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QueueSnapshot {
    /// Activities waiting to be processed by a worker.
    pub pending: usize,
    /// Activities currently being processed by a worker.
    pub running: usize,
    /// Activities waiting in or running from the retry queue.
    pub retries: usize,
    /// Activities which exhausted all retries during the current hour.
    pub dead_last_hour: usize,
    /// Activities completed successfully during the current hour.
    pub completed_last_hour: usize,
}

impl QueueSnapshot {
    pub(crate) fn is_idle(self) -> bool {
        self.pending == 0 && self.running == 0 && self.retries == 0
    }
}

/// Result of waiting for the activity queue to become idle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueDrainOutcome {
    /// The queue became idle before the deadline.
    Idle(QueueSnapshot),
    /// The deadline elapsed while work was still active.
    DeadlineExceeded(QueueSnapshot),
}

/// Return a read-only snapshot of the activity queue counters.
///
/// Counter fields are loaded independently with relaxed ordering, so this is a best-effort,
/// non-linearizable observation. See [`QueueSnapshot`] for details.
///
/// If the queue has not been initialized, this returns an idle default snapshot.
pub fn activity_queue_snapshot<T: Clone>(data: &Data<T>) -> QueueSnapshot {
    data.activity_queue_snapshot()
}

/// Wait until the activity queue is idle or the deadline is reached.
///
/// The deadline takes priority over idle state. Idle is returned only after two consecutive idle
/// snapshots separated by the 25 ms polling interval.
///
/// This only observes queue counters and does not stop workers or alter queue state.
pub async fn wait_for_activity_queue_idle<T: Clone>(
    data: &Data<T>,
    deadline: Instant,
) -> QueueDrainOutcome {
    data.wait_for_activity_queue_idle(deadline).await
}

/// Send a new activity to the given inboxes with automatic retry on failure. Alternatively you
/// can implement your own queue and then send activities using [[crate::activity_sending::SendActivityTask]].
///
/// - `activity`: The activity to be sent, gets converted to json
/// - `private_key`: Private key belonging to the actor who sends the activity, for signing HTTP
///   signature. Generated with [crate::http_signatures::generate_actor_keypair].
/// - `inboxes`: List of remote actor inboxes that should receive the activity. Ignores local actor
///   inboxes. Should be built by calling [crate::traits::Actor::shared_inbox_or_inbox]
///   for each target actor.
pub async fn queue_activity<A, Datatype, ActorType>(
    activity: &A,
    actor: &ActorType,
    inboxes: Vec<Url>,
    data: &Data<Datatype>,
) -> Result<(), Error>
where
    A: Activity + Serialize + Debug,
    Datatype: Clone,
    ActorType: Actor,
{
    let config = &data.config;
    let tasks = build_tasks(activity, actor, inboxes, data).await?;

    for task in tasks {
        // Don't use the activity queue if this is in debug mode, send and wait directly
        if config.debug {
            if let Err(err) = sign_and_send(
                &task,
                &config.client,
                config.request_timeout,
                Default::default(),
            )
            .await
            {
                warn!("{err}");
            }
        } else {
            // This field is only optional to make builder work, its always present at this point
            let activity_queue = config
                .activity_queue
                .as_ref()
                .expect("Config has activity queue");
            activity_queue.queue(task).await?;
            let stats = activity_queue.get_stats();
            let running = stats.running.load(Ordering::Relaxed);
            if running == config.queue_worker_count && config.queue_worker_count != 0 {
                warn!("Reached max number of send activity workers ({}). Consider increasing worker count to avoid federation delays", config.queue_worker_count);
                warn!("{:?}", stats);
            } else {
                info!("{:?}", stats);
            }
        }
    }
    Ok(())
}

async fn sign_and_send(
    task: &SendActivityTask,
    client: &ClientWithMiddleware,
    timeout: Duration,
    retry_strategy: RetryStrategy,
) -> Result<(), Error> {
    retry(
        || task.sign_and_send_internal(client, timeout),
        retry_strategy,
    )
    .await
}

/// A simple activity queue which spawns tokio workers to send out requests
/// When creating a queue, it will spawn a task per worker thread
/// Uses an unbounded mpsc queue for communication (i.e, all messages are in memory)
pub(crate) struct ActivityQueue {
    // Stats shared between the queue and workers
    stats: Arc<Stats>,
    sender: UnboundedSender<SendActivityTask>,
    sender_task: JoinHandle<()>,
    retry_sender_task: JoinHandle<()>,
}

/// Simple stat counter to show where we're up to with sending messages
/// This is a lock-free way to share things between tasks
/// When reading these values it's possible (but extremely unlikely) to get stale data if a worker task is in the middle of transitioning
#[derive(Default)]
pub(crate) struct Stats {
    pending: AtomicUsize,
    running: AtomicUsize,
    retries: AtomicUsize,
    dead_last_hour: AtomicUsize,
    completed_last_hour: AtomicUsize,
}

impl Stats {
    fn snapshot(&self) -> QueueSnapshot {
        QueueSnapshot {
            pending: self.pending.load(Ordering::Relaxed),
            running: self.running.load(Ordering::Relaxed),
            retries: self.retries.load(Ordering::Relaxed),
            dead_last_hour: self.dead_last_hour.load(Ordering::Relaxed),
            completed_last_hour: self.completed_last_hour.load(Ordering::Relaxed),
        }
    }
}

impl Debug for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Activity queue stats: pending: {}, running: {}, retries: {}, dead: {}, complete: {}",
            self.pending.load(Ordering::Relaxed),
            self.running.load(Ordering::Relaxed),
            self.retries.load(Ordering::Relaxed),
            self.dead_last_hour.load(Ordering::Relaxed),
            self.completed_last_hour.load(Ordering::Relaxed)
        )
    }
}

#[derive(Clone, Copy, Default)]
struct RetryStrategy {
    /// Amount of time in seconds to back off
    backoff: usize,
    /// Amount of times to retry
    retries: usize,
    /// If this particular request has already been retried, you can add an offset here to increment the count to start
    offset: usize,
    /// Number of seconds to sleep before trying
    initial_sleep: usize,
}

/// A tokio spawned worker which is responsible for submitting requests to federated servers
/// This will retry up to one time with the same signature, and if it fails, will move it to the retry queue.
/// We need to retry activity sending in case the target instances is temporarily unreachable.
/// In this case, the task is stored and resent when the instance is hopefully back up. This
/// list shows the retry intervals, and which events of the target instance can be covered:
/// - 60s (one minute, service restart) -- happens in the worker w/ same signature
/// - 60min (one hour, instance maintenance) --- happens in the retry worker
/// - 60h (2.5 days, major incident with rebuild from backup) --- happens in the retry worker
async fn worker(
    client: ClientWithMiddleware,
    timeout: Duration,
    message: SendActivityTask,
    retry_queue: UnboundedSender<SendActivityTask>,
    stats: Arc<Stats>,
    strategy: RetryStrategy,
) {
    stats.pending.fetch_sub(1, Ordering::Relaxed);
    stats.running.fetch_add(1, Ordering::Relaxed);

    let outcome = sign_and_send(&message, &client, timeout, strategy).await;

    // "Running" has finished, check the outcome
    stats.running.fetch_sub(1, Ordering::Relaxed);

    match outcome {
        Ok(_) => {
            stats.completed_last_hour.fetch_add(1, Ordering::Relaxed);
        }
        Err(_err) => {
            stats.retries.fetch_add(1, Ordering::Relaxed);
            warn!(
                "Sending activity {} to {} to the retry queue to be tried again later",
                message.activity_id, message.inbox
            );
            // Send to the retry queue.  Ignoring whether it succeeds or not
            retry_queue.send(message).ok();
        }
    }
}

async fn retry_worker(
    client: ClientWithMiddleware,
    timeout: Duration,
    message: SendActivityTask,
    stats: Arc<Stats>,
    strategy: RetryStrategy,
) {
    // Because the times are pretty extravagant between retries, we have to re-sign each time
    let outcome = retry(
        || {
            sign_and_send(
                &message,
                &client,
                timeout,
                RetryStrategy {
                    backoff: 0,
                    retries: 0,
                    offset: 0,
                    initial_sleep: 0,
                },
            )
        },
        strategy,
    )
    .await;

    stats.retries.fetch_sub(1, Ordering::Relaxed);

    match outcome {
        Ok(_) => {
            stats.completed_last_hour.fetch_add(1, Ordering::Relaxed);
        }
        Err(_err) => {
            stats.dead_last_hour.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl ActivityQueue {
    fn new(
        client: ClientWithMiddleware,
        worker_count: usize,
        retry_count: usize,
        timeout: Duration,
        backoff: usize, // This should be 60 seconds by default or 1 second in tests
    ) -> Self {
        let stats: Arc<Stats> = Default::default();

        // This task clears the dead/completed stats every hour
        let hour_stats = stats.clone();
        tokio::spawn(async move {
            let duration = Duration::from_secs(3600);
            loop {
                tokio::time::sleep(duration).await;
                hour_stats.completed_last_hour.store(0, Ordering::Relaxed);
                hour_stats.dead_last_hour.store(0, Ordering::Relaxed);
            }
        });

        let (retry_sender, mut retry_receiver) = unbounded_channel();
        let retry_stats = stats.clone();
        let retry_client = client.clone();

        // The "fast path" retry
        // The backoff should be < 5 mins for this to work otherwise signatures may expire
        // This strategy is the one that is used with the *same* signature
        let strategy = RetryStrategy {
            backoff,
            retries: 1,
            offset: 0,
            initial_sleep: 0,
        };

        // The "retry path" strategy
        // After the fast path fails, a task will sleep up to backoff ^ 2 and then retry again
        let retry_strategy = RetryStrategy {
            backoff,
            retries: 3,
            offset: 2,
            initial_sleep: backoff.pow(2), // wait 60 mins before even trying
        };

        let retry_sender_task = tokio::spawn(async move {
            let mut join_set = JoinSet::new();

            while let Some(message) = retry_receiver.recv().await {
                let retry_task = retry_worker(
                    retry_client.clone(),
                    timeout,
                    message,
                    retry_stats.clone(),
                    retry_strategy,
                );

                if retry_count > 0 {
                    // If we're over the limit of retries, wait for them to finish before spawning
                    while join_set.len() >= retry_count {
                        join_set.join_next().await;
                    }

                    join_set.spawn(retry_task);
                } else {
                    // If the retry worker count is `0` then just spawn and don't use the join_set
                    tokio::spawn(retry_task);
                }
            }

            while !join_set.is_empty() {
                join_set.join_next().await;
            }
        });

        let (sender, mut receiver) = unbounded_channel();

        let sender_stats = stats.clone();

        let sender_task = tokio::spawn(async move {
            let mut join_set = JoinSet::new();

            while let Some(message) = receiver.recv().await {
                let task = worker(
                    client.clone(),
                    timeout,
                    message,
                    retry_sender.clone(),
                    sender_stats.clone(),
                    strategy,
                );

                if worker_count > 0 {
                    // If we're over the limit of workers, wait for them to finish before spawning
                    while join_set.len() >= worker_count {
                        join_set.join_next().await;
                    }

                    join_set.spawn(task);
                } else {
                    // If the worker count is `0` then just spawn and don't use the join_set
                    tokio::spawn(task);
                }
            }

            drop(retry_sender);

            while !join_set.is_empty() {
                join_set.join_next().await;
            }
        });

        Self {
            stats,
            sender,
            sender_task,
            retry_sender_task,
        }
    }

    async fn queue(&self, message: SendActivityTask) -> Result<(), Error> {
        self.stats.pending.fetch_add(1, Ordering::Relaxed);
        self.sender
            .send(message)
            .map_err(|e| Error::ActivityQueueError(e.0.activity_id))?;

        Ok(())
    }

    fn get_stats(&self) -> &Stats {
        &self.stats
    }

    pub(crate) fn snapshot(&self) -> QueueSnapshot {
        self.stats.snapshot()
    }

    #[allow(unused)]
    // Drops all the senders and shuts down the workers
    pub(crate) async fn shutdown(self, wait_for_retries: bool) -> Result<Arc<Stats>, Error> {
        drop(self.sender);

        self.sender_task.await?;

        if wait_for_retries {
            self.retry_sender_task.await?;
        }

        Ok(self.stats)
    }
}

/// Creates an activity queue using tokio spawned tasks
/// Note: requires a tokio runtime
pub(crate) fn create_activity_queue(
    client: ClientWithMiddleware,
    worker_count: usize,
    retry_count: usize,
    request_timeout: Duration,
) -> ActivityQueue {
    ActivityQueue::new(client, worker_count, retry_count, request_timeout, 60)
}

/// Retries a future action factory function up to `amount` times with an exponential backoff timer between tries
async fn retry<T, E: Display + Debug, F: Future<Output = Result<T, E>>, A: FnMut() -> F>(
    mut action: A,
    strategy: RetryStrategy,
) -> Result<T, E> {
    let mut count = strategy.offset;

    // Do an initial sleep if it's called for
    if strategy.initial_sleep > 0 {
        let sleep_dur = Duration::from_secs(strategy.initial_sleep as u64);
        tokio::time::sleep(sleep_dur).await;
    }

    loop {
        match action().await {
            Ok(val) => return Ok(val),
            Err(err) => {
                if count < strategy.retries {
                    count += 1;

                    let sleep_amt = strategy.backoff.pow(count as u32) as u64;
                    let sleep_dur = Duration::from_secs(sleep_amt);
                    warn!("{err:?}.  Sleeping for {sleep_dur:?} and trying again");
                    tokio::time::sleep(sleep_dur).await;
                    continue;
                } else {
                    return Err(err);
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{config::FederationConfig, http_signatures::generate_actor_keypair};
    use axum::{extract::State, routing::post, Router};
    use bytes::Bytes;
    use http::{HeaderMap, StatusCode};
    use std::time::Instant;
    use tokio::{
        sync::{Notify, Semaphore},
        time::{timeout, Duration as TokioDuration, Instant as TokioInstant},
    };
    use tracing::debug;

    async fn observation_data() -> Data<()> {
        FederationConfig::builder()
            .domain("example.com")
            .app_data(())
            .build()
            .await
            .unwrap()
            .to_request_data()
    }

    #[derive(Clone)]
    struct BlockingHandlerState {
        started: Arc<AtomicUsize>,
        started_notify: Arc<Notify>,
        release: Arc<Semaphore>,
    }

    async fn blocking_handler(State(state): State<BlockingHandlerState>) {
        state.started.fetch_add(1, Ordering::Relaxed);
        state.started_notify.notify_waiters();
        state.release.acquire().await.unwrap().forget();
    }

    async fn blocking_test_server() -> (
        Url,
        ClientWithMiddleware,
        BlockingHandlerState,
        JoinHandle<()>,
    ) {
        let state = BlockingHandlerState {
            started: Arc::new(AtomicUsize::new(0)),
            started_notify: Arc::new(Notify::new()),
            release: Arc::new(Semaphore::new(0)),
        };
        let app = Router::new()
            .route("/", post(blocking_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .resolve("queue.test", address)
            .build()
            .unwrap()
            .into();
        let server = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service()).await;
        });

        (
            format!("http://queue.test:{}/", address.port())
                .parse()
                .unwrap(),
            client,
            state,
            server,
        )
    }

    async fn blocking_observation_data(
        client: ClientWithMiddleware,
        worker_count: usize,
    ) -> Data<()> {
        FederationConfig::builder()
            .domain("example.com")
            .app_data(())
            .client(client)
            .queue_worker_count(worker_count)
            .build()
            .await
            .unwrap()
            .to_request_data()
    }

    async fn wait_for_handler_starts(state: &BlockingHandlerState, expected: usize) {
        timeout(TokioDuration::from_millis(250), async {
            loop {
                let notified = state.started_notify.notified();
                if state.started.load(Ordering::Relaxed) >= expected {
                    return;
                }
                notified.await;
            }
        })
        .await
        .unwrap();
    }

    fn queue_task(inbox: &Url) -> SendActivityTask {
        let keypair = generate_actor_keypair().unwrap();
        SendActivityTask {
            actor_id: inbox.clone(),
            activity_id: inbox.join("activity").unwrap(),
            activity: "{}".into(),
            inbox: inbox.clone(),
            private_key: keypair.private_key().unwrap(),
            http_signature_compat: true,
        }
    }

    #[tokio::test]
    async fn queue_snapshot_reports_idle_and_counter_transitions() {
        let data = observation_data().await;
        assert_eq!(activity_queue_snapshot(&data), QueueSnapshot::default());

        let queue = data.config.activity_queue.as_ref().unwrap();
        queue.stats.pending.store(2, Ordering::Relaxed);
        queue.stats.running.store(3, Ordering::Relaxed);
        queue.stats.retries.store(4, Ordering::Relaxed);
        queue.stats.dead_last_hour.store(5, Ordering::Relaxed);
        queue.stats.completed_last_hour.store(6, Ordering::Relaxed);

        assert_eq!(
            activity_queue_snapshot(&data),
            QueueSnapshot {
                pending: 2,
                running: 3,
                retries: 4,
                dead_last_hour: 5,
                completed_last_hour: 6,
            }
        );
    }

    #[tokio::test]
    async fn wait_for_queue_idle_requires_stable_initial_idle_observation() {
        let data = observation_data().await;
        let started = TokioInstant::now();

        assert_eq!(
            wait_for_activity_queue_idle(&data, started + TokioDuration::from_millis(100),).await,
            QueueDrainOutcome::Idle(QueueSnapshot::default())
        );
        assert!(started.elapsed() >= TokioDuration::from_millis(25));
    }

    #[tokio::test]
    async fn wait_for_queue_idle_prioritizes_an_already_expired_deadline() {
        let data = observation_data().await;

        assert_eq!(
            wait_for_activity_queue_idle(
                &data,
                TokioInstant::now() - TokioDuration::from_millis(1),
            )
            .await,
            QueueDrainOutcome::DeadlineExceeded(QueueSnapshot::default())
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn queue_snapshot_observes_real_pending_and_running_work() {
        let (inbox, client, state, server) = blocking_test_server().await;
        let data = blocking_observation_data(client, 1).await;
        let queue = data.config.activity_queue.as_ref().unwrap();

        queue.queue(queue_task(&inbox)).await.unwrap();
        wait_for_handler_starts(&state, 1).await;
        assert_eq!(
            activity_queue_snapshot(&data),
            QueueSnapshot {
                running: 1,
                ..QueueSnapshot::default()
            }
        );

        queue.queue(queue_task(&inbox)).await.unwrap();
        assert_eq!(
            activity_queue_snapshot(&data),
            QueueSnapshot {
                pending: 1,
                running: 1,
                ..QueueSnapshot::default()
            }
        );

        state.release.add_permits(2);
        assert!(matches!(
            wait_for_activity_queue_idle(
                &data,
                TokioInstant::now() + TokioDuration::from_millis(500),
            )
            .await,
            QueueDrainOutcome::Idle(_)
        ));
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wait_for_queue_idle_expires_while_real_handler_is_blocked() {
        let (inbox, client, state, server) = blocking_test_server().await;
        let data = blocking_observation_data(client, 0).await;
        let queue = data.config.activity_queue.as_ref().unwrap();

        queue.queue(queue_task(&inbox)).await.unwrap();
        wait_for_handler_starts(&state, 1).await;

        assert_eq!(
            wait_for_activity_queue_idle(
                &data,
                TokioInstant::now() + TokioDuration::from_millis(30),
            )
            .await,
            QueueDrainOutcome::DeadlineExceeded(QueueSnapshot {
                running: 1,
                ..QueueSnapshot::default()
            })
        );

        state.release.add_permits(1);
        server.abort();
    }

    // This will periodically send back internal errors to test the retry
    async fn dodgy_handler(
        State(state): State<Arc<AtomicUsize>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<(), StatusCode> {
        debug!("Headers:{:?}", headers);
        debug!("Body len:{}", body.len());

        if state.fetch_add(1, Ordering::Relaxed) % 20 == 0 {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        Ok(())
    }

    async fn test_server() {
        use axum::{routing::post, Router};

        // We should break every now and then ;)
        let state = Arc::new(AtomicUsize::new(0));

        let app = Router::new()
            .route("/", post(dodgy_handler))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("0.0.0.0:8002").await.unwrap();
        axum::serve(listener, app.into_make_service()).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    // Queues 100 messages and then asserts that the worker runs them
    async fn test_activity_queue_workers() {
        let num_workers = 64;
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

        let activity_queue = ActivityQueue::new(
            reqwest::Client::default().into(),
            num_workers,
            num_workers,
            Duration::from_secs(10),
            1,
        );

        let keypair = generate_actor_keypair().unwrap();

        let message = SendActivityTask {
            actor_id: "http://localhost:8002".parse().unwrap(),
            activity_id: "http://localhost:8002/activity".parse().unwrap(),
            activity: "{}".into(),
            inbox: "http://localhost:8002".parse().unwrap(),
            private_key: keypair.private_key().unwrap(),
            http_signature_compat: true,
        };

        let start = Instant::now();

        for _ in 0..num_messages {
            activity_queue.queue(message.clone()).await.unwrap();
        }

        info!("Queue Sent: {:?}", start.elapsed());

        let stats = activity_queue.shutdown(true).await.unwrap();

        info!(
            "Queue Finished.  Num msgs: {}, Time {:?}, msg/s: {:0.0}",
            num_messages,
            start.elapsed(),
            num_messages as f64 / start.elapsed().as_secs_f64()
        );

        assert_eq!(
            stats.completed_last_hour.load(Ordering::Relaxed),
            num_messages
        );
    }
}
