use chrono::Utc;
use serde::{Deserialize, Serialize};

pub use crate::error::AppError;

pub const CURRENT_FORMAT_VERSION: &str = "1.0.0";

/// Standard API response envelope wrapping all CLI outputs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub command: String,
    pub target: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

impl<T: Serialize> ApiResponse<T> {
    /// Constructs a successful response envelope.
    pub fn success(command: impl Into<String>, target: impl Into<String>, data: T) -> Self {
        Self {
            success: true,
            command: command.into(),
            target: target.into(),
            timestamp: Utc::now().to_rfc3339(),
            format_version: Some(CURRENT_FORMAT_VERSION.to_string()),
            summary: None,
            data: Some(data),
            warnings: Vec::new(),
            error: None,
        }
    }

    /// Attaches a summary string.
    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    /// Attaches a warning.
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    /// Attaches multiple warnings.
    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
    }

    /// Serializes response to formatted JSON string.
    pub fn to_json(&self, pretty: bool) -> Result<String, serde_json::Error> {
        if pretty {
            serde_json::to_string_pretty(self)
        } else {
            serde_json::to_string(self)
        }
    }
}

impl ApiResponse<serde_json::Value> {
    /// Constructs an error response envelope.
    pub fn error(command: impl Into<String>, target: impl Into<String>, error: ApiError) -> Self {
        Self {
            success: false,
            command: command.into(),
            target: target.into(),
            timestamp: Utc::now().to_rfc3339(),
            format_version: Some(CURRENT_FORMAT_VERSION.to_string()),
            summary: None,
            data: None,
            warnings: Vec::new(),
            error: Some(error),
        }
    }
}

/// Detailed error payload for failed operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

impl ApiError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            category: None,
            exit_code: None,
            details: None,
            suggestion: None,
        }
    }

    pub fn with_details(code: impl Into<String>, message: impl Into<String>, details: serde_json::Value) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            category: None,
            exit_code: None,
            details: Some(details),
            suggestion: None,
        }
    }

    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    pub fn with_exit_code(mut self, exit_code: u8) -> Self {
        self.exit_code = Some(exit_code);
        self
    }

    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }
}
