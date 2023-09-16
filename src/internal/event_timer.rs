use crate::internal::switching_sleep::ASwitchingSleep;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Duration;

type EventTimerFunc = Arc<dyn Fn() + Send + Sync>;

pub struct EventTimer {
    timer: ASwitchingSleep,
    done: mpsc::UnboundedSender<()>,
    wg: Option<JoinHandle<()>>,
}

impl EventTimer {
    pub fn new(task: EventTimerFunc) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut t = EventTimer {
            timer: ASwitchingSleep::new(Duration::from_secs(1)),
            done: tx,
            wg: None,
        };

        let mut timer = t.timer.clone();

        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(_) = rx.recv() => {
                        timer.stop().await;
                        rx.close();
                        return
                    }
                    () = &mut timer => {
                        task();
                    }
                }
            }
        });

        t.wg = Some(join);
        t
    }

    pub async fn stop(&mut self) {
        let _ = self.done.send(());
        let wg = self.wg.take();
        let _ = wg.unwrap().await;
    }

    pub async fn reset(&self, timeout: Duration) {
        self.timer.reset(timeout).await;
    }
}
