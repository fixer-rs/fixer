use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    sync::{RwLock, broadcast},
    time::{Duration, Sleep, sleep},
};

/// The [`!Sync`][trait@std::marker::Sync] one.
#[derive(Debug)]
pub struct SwitchingSleep {
    period: Duration,
    tx: broadcast::Sender<()>,
    rx: broadcast::Receiver<()>,
    sleeper: Option<Pin<Box<Sleep>>>,
}

impl Unpin for SwitchingSleep {}

impl SwitchingSleep {
    /// Create a new [`SwitchingSleep`] and doesn't start the timer.
    pub fn new(period: Duration) -> Self {
        let (tx, rx) = broadcast::channel(10);

        Self {
            period,
            tx,
            rx,
            sleeper: None,
        }
    }

    /// Create a new [`SwitchingSleep`] and start the timer.
    pub fn new_start(period: Duration) -> Self {
        let mut me = Self::new(period);
        me.start();
        me
    }

    /// Start the timer. Reset if already started.
    pub fn start(&mut self) {
        if !self.is_elapsed() {
            self.stop();

            self.sleeper = Some(Box::pin(sleep(self.period)));
            self.tx.send(()).unwrap();
        }
    }

    /// Stop the timer. It does nothing if already stopped.
    pub fn stop(&mut self) {
        if !self.is_elapsed() && self.sleeper.take().is_some() {
            self.tx.send(()).unwrap();
        }
    }

    /// Reset the timer with new duration.
    pub fn reset(&mut self, period: Duration) {
        if !self.is_elapsed() {
            self.stop();
            self.period = period;
            self.sleeper = Some(Box::pin(sleep(self.period)));
            self.tx.send(()).unwrap();
        }
    }

    /// Check if the timer (if any) is elapsed.
    pub fn is_elapsed(&self) -> bool {
        self.sleeper.is_some() && self.sleeper.as_ref().unwrap().is_elapsed()
    }
}

impl Future for SwitchingSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<<Self as Future>::Output> {
        let me = self.get_mut();

        if me.is_elapsed() {
            return Poll::Ready(());
        }

        let sleeper = me.sleeper.as_mut().map(|sleeper| sleeper.as_mut().poll(cx));

        let recv = me.rx.recv();
        tokio::pin!(recv);
        let _ = recv.poll(cx);

        if let Some(Poll::Ready(())) = sleeper {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// The [`Sync`][trait@std::marker::Sync] one.
#[derive(Debug)]
pub struct ASwitchingSleep(Arc<RwLock<SwitchingSleep>>);

impl ASwitchingSleep {
    /// Create a new [`ASwitchingSleep`] and doesn't start the timer.
    pub fn new(period: Duration) -> Self {
        Self(Arc::new(RwLock::new(SwitchingSleep::new(period))))
    }

    /// Create a new [`ASwitchingSleep`] and start the timer.
    pub async fn new_start(period: Duration) -> Self {
        let me = Self::new(period);
        me.start().await;
        me
    }

    /// Start the timer. Reset if already started.
    pub async fn start(&self) {
        let mut inner = self.0.write().await;
        inner.start();
    }

    /// Stop the timer. It does nothing if already stopped.
    pub async fn stop(&self) {
        let mut inner = self.0.write().await;
        inner.stop();
    }

    /// Reset the timer with new duration.
    pub async fn reset(&self, period: Duration) {
        let mut inner = self.0.write().await;
        inner.reset(period);
    }

    /// Check if the timer (if any) is elapsed.
    pub async fn is_elapsed(&self) -> bool {
        let inner = self.0.read().await;
        inner.is_elapsed()
    }
}

impl Unpin for ASwitchingSleep {}

impl Clone for ASwitchingSleep {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Future for ASwitchingSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<<Self as Future>::Output> {
        let me = self.get_mut();

        let write_fut = me.0.write();
        tokio::pin!(write_fut);

        match write_fut.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(mut guard) => Pin::new(&mut *guard).poll(cx),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio::{
        select,
        time::{Duration, Instant, sleep},
    };

    #[tokio::test]
    #[allow(clippy::never_loop)]
    async fn it_works() {
        let mut sleeper = ASwitchingSleep::new(Duration::from_secs(3));

        let start = Instant::now();

        let mut task = {
            let sleeper = sleeper.clone();
            tokio::task::spawn(async move {
                sleep(Duration::from_secs(5)).await;

                assert!(!sleeper.is_elapsed().await);

                sleeper.start().await;

                sleep(Duration::from_secs(2)).await;

                assert!(!sleeper.is_elapsed().await);

                sleeper.stop().await;

                sleep(Duration::from_secs(2)).await;

                assert!(!sleeper.is_elapsed().await);

                sleeper.start().await;

                sleep(Duration::from_secs(2)).await;

                assert!(!sleeper.is_elapsed().await);
            })
        };

        loop {
            select! {
                _ = &mut task => {
                    loop {
                        select! {
                            () = &mut sleeper => {
                                break;
                            }
                        }
                    }
                    break;
                },
                () = &mut sleeper => break,
            }
        }

        let stop = Instant::now();
        let diff = stop - start;

        assert!(sleeper.is_elapsed().await);
        assert_eq!(diff.as_secs(), 12);
    }
}
