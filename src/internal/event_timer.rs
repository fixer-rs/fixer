use crate::internal::switching_sleep::ASwitchingSleep;
use tokio::sync::broadcast;
use tokio::time::Duration;

type EventTimerFunc = fn();

pub struct EventTimer {
    f: EventTimerFunc,
    timer: ASwitchingSleep,
    done_sender: broadcast::Sender<()>,
}

impl EventTimer {
    pub fn new(task: EventTimerFunc) -> Self {
        let (tx, mut rx) = broadcast::channel(1);

        let t = EventTimer {
            f: task,
            timer: ASwitchingSleep::new(Duration::from_secs(1)),
            done_sender: tx,
        };

        let mut timer = t.timer.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Ok(_) = rx.recv() => {
                        timer.stop().await;
                    },

                    () = &mut timer => {(t.f)()}
                }
            }
        });
        t
    }

    pub async fn stop(&mut self) {
        let _ = self.done_sender.send(());
    }

    pub async fn reset(&mut self, timeout: Duration) {
        self.timer.reset(timeout).await;
    }
}
