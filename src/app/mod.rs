//! Camada de aplicação e orquestração.

pub mod commands;
pub mod state;

pub use commands::{AppCommand, AppEvent};
pub use state::{AppConfig, AppState, DetailTab, PasswordPrompt, ThemeMode};
