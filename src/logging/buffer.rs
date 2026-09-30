//! Buffer de logs técnicos em memória para exibição em tempo real na interface gráfica.
//!
//! Implementa sanitização para impedir vazamento de senhas, PINs ou chaves privadas.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

/// Nível de criticidade do log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "TRACE"),
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
        }
    }
}

/// Registro individual de log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub target: String,
    pub message: String,
}

impl LogEntry {
    pub fn new(level: LogLevel, target: impl Into<String>, message: impl Into<String>) -> Self {
        let msg = sanitize_log_message(&message.into());
        Self {
            timestamp: Utc::now(),
            level,
            target: target.into(),
            message: msg,
        }
    }
}

/// Sanitiza mensagens de log garantindo que termos sensíveis sejam mascarados.
pub fn sanitize_log_message(msg: &str) -> String {
    let prefixes = ["senha=", "password=", "pin=", "PIN="];
    let words: Vec<&str> = msg.split_whitespace().collect();
    let mut result = Vec::new();

    for word in words {
        let mut sanitized = word.to_string();
        for prefix in &prefixes {
            if let Some(idx) = sanitized.to_lowercase().find(&prefix.to_lowercase()) {
                sanitized = format!("{}{}[REDACTED]", &sanitized[..idx], prefix);
                break;
            }
        }
        if sanitized.contains("private_key") {
            sanitized = sanitized.replace("private_key", "[PRIVATE_KEY_MASKED]");
        }
        result.push(sanitized);
    }

    result.join(" ")
}

/// Buffer thread-safe armazenado em memória com limite configurável.
#[derive(Debug, Clone)]
pub struct MemoryLogBuffer {
    entries: Arc<Mutex<Vec<LogEntry>>>,
    max_capacity: usize,
}

impl Default for MemoryLogBuffer {
    fn default() -> Self {
        Self::new(2000)
    }
}

impl MemoryLogBuffer {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::with_capacity(max_capacity.min(256)))),
            max_capacity,
        }
    }

    /// Adiciona uma nova entrada no buffer respeitando a capacidade máxima.
    pub fn push(&self, entry: LogEntry) {
        if let Ok(mut lock) = self.entries.lock() {
            if lock.len() >= self.max_capacity {
                lock.remove(0);
            }
            lock.push(entry);
        }
    }

    /// Retorna uma cópia das entradas filtradas por nível mínimo e busca textual.
    pub fn get_filtered(&self, min_level: LogLevel, search_query: &str) -> Vec<LogEntry> {
        let Ok(lock) = self.entries.lock() else {
            return Vec::new();
        };

        let query = search_query.trim().to_lowercase();
        lock.iter()
            .filter(|e| e.level >= min_level)
            .filter(|e| {
                if query.is_empty() {
                    true
                } else {
                    e.message.to_lowercase().contains(&query)
                        || e.target.to_lowercase().contains(&query)
                }
            })
            .cloned()
            .collect()
    }

    /// Limpa todo o buffer de logs.
    pub fn clear(&self) {
        if let Ok(mut lock) = self.entries.lock() {
            lock.clear();
        }
    }

    /// Exporta os logs como texto formatado para suporte técnico.
    pub fn export_text(&self) -> String {
        let Ok(lock) = self.entries.lock() else {
            return String::new();
        };

        let mut out = String::new();
        for entry in lock.iter() {
            out.push_str(&format!(
                "[{}] [{:<5}] [{}] {}\n",
                entry.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
                entry.level,
                entry.target,
                entry.message
            ));
        }
        out
    }
}
