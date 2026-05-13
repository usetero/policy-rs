//! Shared types for examples.

#![allow(dead_code)]

use policy_rs::proto::tero::policy::v1::{LogField, MetricField, MetricType, TraceField};
use policy_rs::{
    LogFieldSelector, LogSignal, Matchable, MetricFieldSelector, MetricSignal, TraceFieldSelector,
    TraceSignal, Transformable,
};
use std::borrow::Cow;
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
    type Signal = LogSignal;

    fn get_field(&self, field: &LogFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            LogFieldSelector::Simple(log_field) => match log_field {
                LogField::Body => self.body.as_deref().map(Cow::Borrowed),
                LogField::SeverityText => self.severity.as_deref().map(Cow::Borrowed),
                _ => None,
            },
            LogFieldSelector::LogAttribute(path) => path
                .first()
                .and_then(|key| self.attributes.get(key))
                .map(|s| Cow::Borrowed(s.as_str())),
            LogFieldSelector::ResourceAttribute(path) => path
                .first()
                .and_then(|key| self.resource_attributes.get(key))
                .map(|s| Cow::Borrowed(s.as_str())),
            LogFieldSelector::ScopeAttribute(_) => None,
        }
    }
}

impl Transformable for LogRecord {
    fn set_field(&mut self, field: &LogFieldSelector, value: &str) {
        match field {
            LogFieldSelector::Simple(log_field) => match log_field {
                LogField::Body => self.body = Some(value.to_string()),
                LogField::SeverityText => self.severity = Some(value.to_string()),
                _ => {}
            },
            LogFieldSelector::LogAttribute(path) => {
                if let Some(key) = path.first() {
                    self.attributes.insert(key.clone(), value.to_string());
                }
            }
            LogFieldSelector::ResourceAttribute(path) => {
                if let Some(key) = path.first() {
                    self.resource_attributes
                        .insert(key.clone(), value.to_string());
                }
            }
            LogFieldSelector::ScopeAttribute(_) => {}
        }
    }

    fn delete_field(&mut self, field: &LogFieldSelector) -> bool {
        match field {
            LogFieldSelector::Simple(log_field) => match log_field {
                LogField::Body => self.body.take().is_some(),
                LogField::SeverityText => self.severity.take().is_some(),
                _ => false,
            },
            LogFieldSelector::LogAttribute(path) => path
                .first()
                .and_then(|key| self.attributes.remove(key))
                .is_some(),
            LogFieldSelector::ResourceAttribute(path) => path
                .first()
                .and_then(|key| self.resource_attributes.remove(key))
                .is_some(),
            LogFieldSelector::ScopeAttribute(_) => false,
        }
    }

    fn move_field(&mut self, from: &LogFieldSelector, to: &LogFieldSelector) {
        let value = match from {
            LogFieldSelector::Simple(log_field) => match log_field {
                LogField::Body => self.body.take(),
                LogField::SeverityText => self.severity.take(),
                _ => None,
            },
            LogFieldSelector::LogAttribute(path) => {
                path.first().and_then(|key| self.attributes.remove(key))
            }
            LogFieldSelector::ResourceAttribute(path) => path
                .first()
                .and_then(|key| self.resource_attributes.remove(key)),
            LogFieldSelector::ScopeAttribute(_) => None,
        };
        let Some(v) = value else {
            return;
        };
        match to {
            LogFieldSelector::LogAttribute(path) => {
                if let Some(key) = path.first() {
                    self.attributes.insert(key.clone(), v);
                }
            }
            LogFieldSelector::ResourceAttribute(path) => {
                if let Some(key) = path.first() {
                    self.resource_attributes.insert(key.clone(), v);
                }
            }
            _ => {}
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

/// A simple metric record for demonstration.
#[derive(Debug, Clone)]
pub struct MetricRecord {
    pub name: String,
    pub metric_type: Option<MetricType>,
    pub datapoint_attributes: HashMap<String, String>,
    pub resource_attributes: HashMap<String, String>,
}

impl MetricRecord {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            metric_type: None,
            datapoint_attributes: HashMap::new(),
            resource_attributes: HashMap::new(),
        }
    }

    pub fn with_type(mut self, t: MetricType) -> Self {
        self.metric_type = Some(t);
        self
    }

    pub fn with_datapoint_attr(mut self, key: &str, value: &str) -> Self {
        self.datapoint_attributes
            .insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_resource_attr(mut self, key: &str, value: &str) -> Self {
        self.resource_attributes
            .insert(key.to_string(), value.to_string());
        self
    }
}

impl Matchable for MetricRecord {
    type Signal = MetricSignal;

    fn get_field(&self, field: &MetricFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            MetricFieldSelector::Simple(MetricField::Name) => Some(Cow::Borrowed(&self.name)),
            MetricFieldSelector::Simple(_) => None,
            MetricFieldSelector::DatapointAttribute(path) => path
                .first()
                .and_then(|key| self.datapoint_attributes.get(key))
                .map(|s| Cow::Borrowed(s.as_str())),
            MetricFieldSelector::ResourceAttribute(path) => path
                .first()
                .and_then(|key| self.resource_attributes.get(key))
                .map(|s| Cow::Borrowed(s.as_str())),
            MetricFieldSelector::Type => self
                .metric_type
                .as_ref()
                .map(|t| Cow::Borrowed(t.as_str_name())),
            _ => None,
        }
    }
}

/// A simple span record for demonstration.
#[derive(Debug, Clone)]
pub struct SpanRecord {
    pub name: String,
    pub trace_id: String,
    pub span_id: String,
    pub tracestate: String,
    pub span_kind: Option<String>,
    pub span_status: Option<String>,
    pub attributes: HashMap<String, String>,
    pub resource_attributes: HashMap<String, String>,
    pub th_value: Option<String>,
}

impl SpanRecord {
    pub fn new(name: &str, trace_id: &str) -> Self {
        Self {
            name: name.to_string(),
            trace_id: trace_id.to_string(),
            span_id: "0000000000000001".to_string(),
            tracestate: String::new(),
            span_kind: None,
            span_status: None,
            attributes: HashMap::new(),
            resource_attributes: HashMap::new(),
            th_value: None,
        }
    }

    pub fn with_span_kind(mut self, kind: &str) -> Self {
        self.span_kind = Some(kind.to_string());
        self
    }

    pub fn with_span_status(mut self, status: &str) -> Self {
        self.span_status = Some(status.to_string());
        self
    }

    pub fn with_tracestate(mut self, ts: &str) -> Self {
        self.tracestate = ts.to_string();
        self
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

impl Matchable for SpanRecord {
    type Signal = TraceSignal;

    fn get_field(&self, field: &TraceFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            TraceFieldSelector::Simple(trace_field) => match trace_field {
                TraceField::Name => Some(Cow::Borrowed(&self.name)),
                TraceField::TraceId => Some(Cow::Borrowed(&self.trace_id)),
                TraceField::SpanId => Some(Cow::Borrowed(&self.span_id)),
                TraceField::TraceState => {
                    if self.tracestate.is_empty() {
                        None
                    } else {
                        Some(Cow::Borrowed(&self.tracestate))
                    }
                }
                _ => None,
            },
            TraceFieldSelector::SpanAttribute(path) => path
                .first()
                .and_then(|key| self.attributes.get(key))
                .map(|s| Cow::Borrowed(s.as_str())),
            TraceFieldSelector::ResourceAttribute(path) => path
                .first()
                .and_then(|key| self.resource_attributes.get(key))
                .map(|s| Cow::Borrowed(s.as_str())),
            TraceFieldSelector::SpanKind => self.span_kind.as_deref().map(Cow::Borrowed),
            TraceFieldSelector::SpanStatus => self.span_status.as_deref().map(Cow::Borrowed),
            _ => None,
        }
    }
}

impl Transformable for SpanRecord {
    fn set_field(&mut self, field: &TraceFieldSelector, value: &str) {
        if matches!(field, TraceFieldSelector::SamplingThreshold) {
            self.th_value = Some(value.to_string());
        }
    }

    fn delete_field(&mut self, _field: &TraceFieldSelector) -> bool {
        false
    }

    fn move_field(&mut self, _from: &TraceFieldSelector, _to: &TraceFieldSelector) {}
}

/// Helper to print a span record's current state.
pub fn print_span(span: &SpanRecord) {
    println!("  Name: {}", span.name);
    println!("  TraceID: {}", span.trace_id);
    if let Some(kind) = &span.span_kind {
        println!("  Kind: {}", kind);
    }
    if let Some(status) = &span.span_status {
        println!("  Status: {}", status);
    }
    if !span.tracestate.is_empty() {
        println!("  Tracestate: {}", span.tracestate);
    }
    if let Some(th) = &span.th_value {
        println!("  Sampling TH: {}", th);
    }
    if !span.attributes.is_empty() {
        println!("  Attributes:");
        for (k, v) in &span.attributes {
            println!("    {}: {}", k, v);
        }
    }
}
