//! Shared types for examples.

#![allow(dead_code)]

use policy_rs::proto::tero::policy::v1::LogField;
use policy_rs::{LogFieldSelector, Matchable, Transformable};
use std::collections::HashMap;

/// A simple log record for demonstration.
#[derive(Debug, Clone)]
pub struct LogRecord {
    pub body: Option<String>,
    pub severity: Option<String>,
    pub attributes: HashMap<String, String>,
    pub resource_attributes: HashMap<String, String>,
}

impl LogRecord {
    pub fn new(body: &str, severity: &str) -> Self {
        Self {
            body: Some(body.to_string()),
            severity: Some(severity.to_string()),
            attributes: HashMap::new(),
            resource_attributes: HashMap::new(),
        }
    }

    pub fn with_attr(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_resource_attr(mut self, key: &str, value: &str) -> Self {
        self.resource_attributes
            .insert(key.to_string(), value.to_string());
        self
    }
}

impl Matchable for LogRecord {
    fn get_field(&self, field: &LogFieldSelector) -> Option<&str> {
        match field {
            LogFieldSelector::Simple(log_field) => match log_field {
                LogField::Body => self.body.as_deref(),
                LogField::SeverityText => self.severity.as_deref(),
                _ => None,
            },
            LogFieldSelector::LogAttribute(key) => self.attributes.get(key).map(|s| s.as_str()),
            LogFieldSelector::ResourceAttribute(key) => {
                self.resource_attributes.get(key).map(|s| s.as_str())
            }
            LogFieldSelector::ScopeAttribute(_) => None,
        }
    }
}

impl Transformable for LogRecord {
    fn remove_field(&mut self, field: &LogFieldSelector) -> bool {
        match field {
            LogFieldSelector::Simple(log_field) => match log_field {
                LogField::Body => self.body.take().is_some(),
                LogField::SeverityText => self.severity.take().is_some(),
                _ => false,
            },
            LogFieldSelector::LogAttribute(key) => self.attributes.remove(key).is_some(),
            LogFieldSelector::ResourceAttribute(key) => {
                self.resource_attributes.remove(key).is_some()
            }
            LogFieldSelector::ScopeAttribute(_) => false,
        }
    }

    fn redact_field(&mut self, field: &LogFieldSelector, replacement: &str) -> bool {
        match field {
            LogFieldSelector::Simple(log_field) => match log_field {
                LogField::Body => {
                    if self.body.is_some() {
                        self.body = Some(replacement.to_string());
                        true
                    } else {
                        false
                    }
                }
                LogField::SeverityText => {
                    if self.severity.is_some() {
                        self.severity = Some(replacement.to_string());
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            },
            LogFieldSelector::LogAttribute(key) => {
                if self.attributes.contains_key(key) {
                    self.attributes.insert(key.clone(), replacement.to_string());
                    true
                } else {
                    false
                }
            }
            LogFieldSelector::ResourceAttribute(key) => {
                if self.resource_attributes.contains_key(key) {
                    self.resource_attributes
                        .insert(key.clone(), replacement.to_string());
                    true
                } else {
                    false
                }
            }
            LogFieldSelector::ScopeAttribute(_) => false,
        }
    }

    fn rename_field(&mut self, from: &LogFieldSelector, to: &str, upsert: bool) -> bool {
        if !upsert && self.attributes.contains_key(to) {
            return false;
        }
        let value = match from {
            LogFieldSelector::Simple(log_field) => match log_field {
                LogField::Body => self.body.take(),
                LogField::SeverityText => self.severity.take(),
                _ => None,
            },
            LogFieldSelector::LogAttribute(key) => self.attributes.remove(key),
            LogFieldSelector::ResourceAttribute(key) => self.resource_attributes.remove(key),
            LogFieldSelector::ScopeAttribute(_) => None,
        };
        if let Some(v) = value {
            self.attributes.insert(to.to_string(), v);
            true
        } else {
            false
        }
    }

    fn add_field(&mut self, field: &LogFieldSelector, value: &str, upsert: bool) -> bool {
        match field {
            LogFieldSelector::Simple(log_field) => match log_field {
                LogField::Body => {
                    if !upsert && self.body.is_some() {
                        return false;
                    }
                    self.body = Some(value.to_string());
                    true
                }
                LogField::SeverityText => {
                    if !upsert && self.severity.is_some() {
                        return false;
                    }
                    self.severity = Some(value.to_string());
                    true
                }
                _ => false,
            },
            LogFieldSelector::LogAttribute(key) => {
                if !upsert && self.attributes.contains_key(key) {
                    return false;
                }
                self.attributes.insert(key.clone(), value.to_string());
                true
            }
            LogFieldSelector::ResourceAttribute(key) => {
                if !upsert && self.resource_attributes.contains_key(key) {
                    return false;
                }
                self.resource_attributes
                    .insert(key.clone(), value.to_string());
                true
            }
            LogFieldSelector::ScopeAttribute(_) => false,
        }
    }
}

/// Helper to print a log record's current state.
pub fn print_log(log: &LogRecord) {
    println!("  Body: {:?}", log.body);
    println!("  Severity: {:?}", log.severity);
    if !log.attributes.is_empty() {
        println!("  Attributes:");
        for (k, v) in &log.attributes {
            println!("    {}: {}", k, v);
        }
    }
    if !log.resource_attributes.is_empty() {
        println!("  Resource Attributes:");
        for (k, v) in &log.resource_attributes {
            println!("    {}: {}", k, v);
        }
    }
}
