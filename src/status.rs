// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! The `status` command and the main menu's status display.

use crate::prelude::*;
use crate::services::Service;
use crate::{elastic, evebox, housekeeper, suricata};

#[derive(Debug, Clone, Copy)]
enum Level {
    Info,
    Warn,
    Debug,
}

/// One line of the status display.
struct Line {
    level: Level,
    label: &'static str,
    state: String,
}

impl Line {
    fn new(level: Level, label: &'static str, state: impl Into<String>) -> Self {
        Self {
            level,
            label,
            state: state.into(),
        }
    }

    /// A line for an enabled service, with `suffix` appended to the
    /// state, typically the version.
    fn running(label: &'static str, running: bool, suffix: &str) -> Self {
        if running {
            Self::new(Level::Info, label, format!("running{suffix}"))
        } else {
            Self::new(Level::Warn, label, format!("not running{suffix}"))
        }
    }

    fn disabled(label: &'static str) -> Self {
        Self::new(Level::Debug, label, "not enabled")
    }

    fn log(&self) {
        let (label, state) = (self.label, &self.state);
        match self.level {
            Level::Info => info!("{label:-13}: {state}"),
            Level::Warn => warn!("{label:-13}: {state}"),
            Level::Debug => debug!("{label:-13}: {state}"),
        }
    }
}

/// Looks up EveBox versions for the status display. The server and
/// agent share an image, so the image version is only queried once
/// if neither is running.
#[derive(Default)]
struct EveBoxVersions {
    image: Option<String>,
}

impl EveBoxVersions {
    /// The version suffix for a status line, empty if unknown.
    fn suffix(&mut self, context: &Context, running: bool, container_name: &str) -> String {
        let version = if running {
            evebox::running_version(context, container_name)
        } else if let Some(version) = &self.image {
            Ok(Some(version.clone()))
        } else {
            let version = evebox::image_version(context);
            if let Ok(Some(version)) = &version {
                self.image = Some(version.clone());
            }
            version
        };
        match version {
            Ok(Some(version)) => format!(" ({version})"),
            Ok(None) => String::new(),
            Err(err) => {
                debug!("Failed to determine the EveBox version: {err}");
                String::new()
            }
        }
    }
}

fn suricata_status_line(context: &Context) -> Line {
    let running = context
        .manager
        .is_running(&suricata::container_name(context));
    let version = if running {
        suricata::running_version(context)
    } else {
        suricata::image_version(context)
    };
    let version = match version {
        Ok(Some(version)) if !suricata::version_is_supported(&version) => {
            format!(" ({version}, unsupported)")
        }
        Ok(Some(version)) => format!(" ({version})"),
        Ok(None) => String::new(),
        Err(err) => {
            debug!("Failed to determine the Suricata version: {err}");
            String::new()
        }
    };
    Line::running("Suricata", running, &version)
}

fn rules_status_line(context: &Context) -> Line {
    match suricata::last_rule_update(context) {
        Some(updated) => Line::new(Level::Info, "Rules", format!("updated {updated}")),
        None => Line::new(Level::Warn, "Rules", "never updated"),
    }
}

fn evebox_status_line(context: &Context, versions: &mut EveBoxVersions, service: Service) -> Line {
    let label = evebox_status_label(service);
    let container_name = service.container_name(context);
    let running = context.manager.is_running(&container_name);
    let mut suffix = versions.suffix(context, running, &container_name);
    if running && service == Service::EveBoxServer {
        suffix.push(' ');
        suffix.push_str(&guess_evebox_url(context));
    }
    Line::running(label, running, &suffix)
}

fn evebox_status_label(service: Service) -> &'static str {
    match service {
        Service::EveBoxServer => "EveBox Server",
        Service::EveBoxAgent => "EveBox Agent",
        _ => unreachable!("not an EveBox service: {service:?}"),
    }
}

pub(crate) fn log_status(context: &Context) {
    let config = &context.config;
    let mut lines = vec![];

    if config.suricata.enabled {
        lines.push(suricata_status_line(context));
        lines.push(rules_status_line(context));
    } else {
        lines.push(Line::disabled("Suricata"));
    }

    let mut versions = EveBoxVersions::default();
    for service in [Service::EveBoxServer, Service::EveBoxAgent] {
        if service.enabled(config) {
            lines.push(evebox_status_line(context, &mut versions, service));
        } else {
            lines.push(Line::disabled(evebox_status_label(service)));
        }
    }

    let engine = config.elasticsearch.engine.name();
    if config.elasticsearch_enabled() {
        let running = context
            .manager
            .is_running(&elastic::container_name(context));
        lines.push(Line::running(engine, running, ""));
    } else {
        lines.push(Line::disabled(engine));
    }

    let housekeeper_name = housekeeper::container_name(context);
    if housekeeper::enabled(context) {
        let running = context.manager.is_running(&housekeeper_name);
        lines.push(Line::running("Housekeeper", running, ""));
    } else if context.manager.is_active(&housekeeper_name) {
        lines.push(Line::new(
            Level::Warn,
            "Housekeeper",
            "running but disabled; run evectl start or stop",
        ));
    }

    for line in &lines {
        line.log();
    }

    if !Service::ALL.iter().any(|service| service.enabled(config)) {
        info!("No services enabled");
    }
}

/// The URL the EveBox server is most likely reachable at.
pub(crate) fn guess_evebox_url(context: &Context) -> String {
    let scheme = if context.config.evebox_server.no_tls {
        "http"
    } else {
        "https"
    };

    if !context.config.evebox_server.allow_remote {
        return format!("{}://127.0.0.1:5636", scheme);
    }

    if let Some(bind_value) = &context.config.evebox_server.bind_address {
        match crate::system::resolve_interface_or_ip(bind_value) {
            Ok(address) => return format!("{}://{}:5636", scheme, address),
            Err(err) => {
                error!("Failed to resolve bind value {bind_value}: {err}");
            }
        }
    }

    let addr = crate::system::primary_ipv4().unwrap_or_else(|| "127.0.0.1".to_string());
    format!("{}://{}:5636", scheme, addr)
}

/// Format a time in the local timezone with a short description of
/// how long ago it was, for example `2026-09-16 00:17 (3 hours ago)`.
pub(crate) fn format_time_with_age(
    time: std::time::SystemTime,
    now: std::time::SystemTime,
) -> String {
    let mut datetime = time::OffsetDateTime::from(time);
    let format = if let Ok(offset) = time::UtcOffset::current_local_offset() {
        datetime = datetime.to_offset(offset);
        time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]")
    } else {
        time::macros::format_description!("[year]-[month]-[day] [hour]:[minute] UTC")
    };
    let formatted = datetime
        .format(format)
        .unwrap_or_else(|_| datetime.to_string());
    let age = now.duration_since(time).unwrap_or_default().as_secs();
    let age = match age {
        0..=59 => "just now".to_string(),
        60..=3599 => format_age(age / 60, "minute"),
        3600..=86399 => format_age(age / 3600, "hour"),
        _ => format_age(age / 86400, "day"),
    };
    format!("{formatted} ({age})")
}

fn format_age(count: u64, unit: &str) -> String {
    if count == 1 {
        format!("1 {unit} ago")
    } else {
        format!("{count} {unit}s ago")
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn formats_time_with_age() {
        use std::time::{Duration, SystemTime};
        let now = SystemTime::now();
        let ends_with = |t: SystemTime, suffix: &str| {
            let formatted = format_time_with_age(t, now);
            assert!(formatted.ends_with(suffix), "{formatted}");
        };
        ends_with(now, "(just now)");
        ends_with(now - Duration::from_secs(60), "(1 minute ago)");
        ends_with(now - Duration::from_secs(5 * 60), "(5 minutes ago)");
        ends_with(now - Duration::from_secs(3600), "(1 hour ago)");
        ends_with(now - Duration::from_secs(3 * 3600), "(3 hours ago)");
        ends_with(now - Duration::from_secs(2 * 86400), "(2 days ago)");
        // A file time in the future should not panic.
        ends_with(now + Duration::from_secs(60), "(just now)");
    }
}
