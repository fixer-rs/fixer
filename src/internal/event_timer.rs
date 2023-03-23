use crate::internal::switching_sleep::ASwitchingSleep;
use defer_lite::defer;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::Duration;
use wg::AsyncWaitGroup;

type EventTimerFunc = Arc<dyn Fn() -> () + Send + Sync>;

pub struct EventTimer {
    timer: ASwitchingSleep,
    done: mpsc::UnboundedSender<()>,
    wg: AsyncWaitGroup,
}

impl EventTimer {
    pub fn new(task: Arc<dyn Fn() -> () + Send + Sync>) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel();

        let t = EventTimer {
            timer: ASwitchingSleep::new(Duration::from_secs(1)),
            done: tx,
            wg: AsyncWaitGroup::new(),
        };

        let mut timer = t.timer.clone();
        let wg_done = t.wg.add(1);

        tokio::spawn(async move {
            defer! {
                wg_done.done()
            };
            loop {
                tokio::select! {
                    Some(_) = rx.recv() => {
                        timer.stop().await;
                        return
                    }
                    () = &mut timer => {task()}
                }
            }
        });
        t
    }

    pub async fn stop(&self) {
        // no need to close self.done as Rust automatically close channel after all sender is closed.
        self.wg.wait().await;
    }

    pub async fn reset(&self, timeout: Duration) {
        self.timer.reset(timeout).await;
    }
}
