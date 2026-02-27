use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::time::{Duration, Instant, Sleep, sleep};

/// A simple, single-owner async timer for the session run loop.
///
/// Wraps a `tokio::time::Sleep` future. When armed via `reset()`, it resolves
/// after the given duration. When disarmed (default or after `stop()`), it
/// never resolves. Auto-disarms after firing.
pub struct EventTimer {
    inner: Option<Pin<Box<Sleep>>>,
}

impl EventTimer {
    /// Create a new disarmed timer.
    pub fn new() -> Self {
        Self { inner: None }
    }

    /// Arm the timer. If already armed, resets to the new deadline.
    pub fn reset(&mut self, duration: Duration) {
        match &mut self.inner {
            Some(sleep) => sleep.as_mut().reset(Instant::now() + duration),
            None => self.inner = Some(Box::pin(sleep(duration))),
        }
    }

    /// Disarm the timer. It will never fire until `reset()` is called again.
    pub fn stop(&mut self) {
        self.inner = None;
    }
}

impl Default for EventTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl Future for EventTimer {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        match &mut self.inner {
            Some(sleep) => {
                let result = sleep.as_mut().poll(cx);
                if result.is_ready() {
                    self.inner = None;
                }
                result
            }
            None => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_disarmed_never_fires() {
        let mut timer = EventTimer::new();

        tokio::select! {
            () = &mut timer => panic!("disarmed timer should never fire"),
            () = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }

    #[tokio::test]
    async fn test_arm_and_fire() {
        let mut timer = EventTimer::new();
        timer.reset(Duration::from_millis(30));

        tokio::select! {
            () = &mut timer => {}
            () = tokio::time::sleep(Duration::from_secs(1)) => panic!("timer should have fired"),
        }
    }

    #[tokio::test]
    async fn test_auto_disarm_after_fire() {
        let mut timer = EventTimer::new();
        timer.reset(Duration::from_millis(10));

        // Wait for it to fire.
        tokio::time::sleep(Duration::from_millis(30)).await;
        tokio::select! {
            () = &mut timer => {}
            () = tokio::time::sleep(Duration::from_millis(10)) => panic!("timer should have fired"),
        }

        // After firing, it should be disarmed and never fire again.
        tokio::select! {
            () = &mut timer => panic!("timer should be disarmed after firing"),
            () = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }

    #[tokio::test]
    async fn test_reset_extends_deadline() {
        let mut timer = EventTimer::new();
        timer.reset(Duration::from_millis(50));

        // Wait 20ms, then reset to 80ms from now.
        tokio::time::sleep(Duration::from_millis(20)).await;
        timer.reset(Duration::from_millis(80));

        // At 70ms total, the original deadline would have passed, but the reset one hasn't.
        tokio::select! {
            () = &mut timer => panic!("timer fired too early after reset"),
            () = tokio::time::sleep(Duration::from_millis(50)) => {}
        }

        // The reset deadline (80ms from the reset point) should fire.
        tokio::select! {
            () = &mut timer => {}
            () = tokio::time::sleep(Duration::from_secs(1)) => panic!("timer should have fired"),
        }
    }

    #[tokio::test]
    async fn test_stop_disarms() {
        let mut timer = EventTimer::new();
        timer.reset(Duration::from_millis(30));
        timer.stop();

        tokio::select! {
            () = &mut timer => panic!("stopped timer should not fire"),
            () = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }

    #[tokio::test]
    async fn test_stop_then_reset() {
        let mut timer = EventTimer::new();
        timer.reset(Duration::from_millis(50));
        timer.stop();
        timer.reset(Duration::from_millis(30));

        tokio::select! {
            () = &mut timer => {}
            () = tokio::time::sleep(Duration::from_secs(1)) => panic!("re-armed timer should fire"),
        }
    }
}
