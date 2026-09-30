//! Sistema de logging estruturado com integração para a GUI.

pub mod buffer;

pub use buffer::{sanitize_log_message, LogEntry, LogLevel, MemoryLogBuffer};

use std::sync::Arc;
use tracing_subscriber::{layer::Context, Layer};

/// Camada personalizada do Tracing que alimenta o `MemoryLogBuffer` da aplicação.
pub struct MemoryLayer {
    buffer: Arc<MemoryLogBuffer>,
}

impl MemoryLayer {
    pub fn new(buffer: Arc<MemoryLogBuffer>) -> Self {
        Self { buffer }
    }
}

impl<S> Layer<S> for MemoryLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();

        let level = match *metadata.level() {
            tracing::Level::ERROR => LogLevel::Error,
            tracing::Level::WARN => LogLevel::Warn,
            tracing::Level::INFO => LogLevel::Info,
            tracing::Level::DEBUG => LogLevel::Debug,
            tracing::Level::TRACE => LogLevel::Trace,
        };

        struct MessageVisitor(String);
        impl tracing::field::Visit for MessageVisitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{:?}", value);
                    // Remove aspas adicionadas pelo format!("{:?}", ...)
                    if self.0.starts_with('"') && self.0.ends_with('"') && self.0.len() >= 2 {
                        self.0 = self.0[1..self.0.len() - 1].to_string();
                    }
                } else {
                    if !self.0.is_empty() {
                        self.0.push(' ');
                    }
                    self.0.push_str(&format!("{}={:?}", field.name(), value));
                }
            }

            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "message" {
                    self.0 = value.to_string();
                } else {
                    if !self.0.is_empty() {
                        self.0.push(' ');
                    }
                    self.0.push_str(&format!("{}={}", field.name(), value));
                }
            }
        }

        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);

        self.buffer.push(LogEntry::new(
            level,
            metadata.target(),
            visitor.0,
        ));
    }
}
