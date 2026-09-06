//! Daemon-wide event bus. `/events` streams subscribe to the broadcast side;
//! every subsystem (containers, images, networks, volumes, daemon) publishes.

use ingot_api::EventMessage;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<EventMessage>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(64));
        Self { tx }
    }

    /// Publish an event; drops silently if no subscribers or the buffer is full.
    pub fn publish(&self, ev: EventMessage) {
        let _ = self.tx.send(ev);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EventMessage> {
        self.tx.subscribe()
    }
}
