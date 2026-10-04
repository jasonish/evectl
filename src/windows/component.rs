// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Bundled components (Npcap and Suricata) and when to upgrade them.

use super::paths::Paths;
use crate::prelude::*;
use std::cmp::Ordering;

/// A component EveCtl installs at a bundled version.
pub(super) trait Component {
    fn name(&self) -> &'static str;

    fn bundled_version(&self) -> &'static str;

    /// Whether an installation is present at all.
    fn installed(&self, paths: &Paths) -> bool;

    /// The installed version, or None when it cannot be determined.
    fn installed_version(&self, paths: &Paths) -> Result<Option<String>>;

    /// Whether an installation whose version cannot be determined is
    /// replaced by the bundled version.
    fn reinstall_unknown_version(&self) -> bool;

    /// Install the component, replacing an existing installation when
    /// upgrading.
    fn install(&self, paths: &Paths, upgrade: bool) -> Result<()>;
}

/// Why a component is (re)installed by an upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Upgrade {
    /// Not installed.
    Install,
    /// Installed, but the version is unknown.
    Reinstall,
    /// The installed version is older than the bundled one.
    Outdated(String),
}

pub(super) fn upgrade_needed(component: &dyn Component, paths: &Paths) -> Result<Option<Upgrade>> {
    if !component.installed(paths) {
        return Ok(Some(Upgrade::Install));
    }
    let Some(installed) = component.installed_version(paths)? else {
        return Ok(component
            .reinstall_unknown_version()
            .then_some(Upgrade::Reinstall));
    };
    Ok(
        match compare_versions(&installed, component.bundled_version()) {
            Some(Ordering::Less) => Some(Upgrade::Outdated(installed)),
            _ => None,
        },
    )
}

pub(super) fn upgrade(component: &dyn Component, paths: &Paths, reason: &Upgrade) -> Result<()> {
    let name = component.name();
    let bundled = component.bundled_version();
    match reason {
        Upgrade::Install => info!("{name} was not detected. Installing version {bundled}..."),
        Upgrade::Reinstall => info!(
            "{name} is installed, but the version could not be determined. Reinstalling bundled version {bundled}."
        ),
        Upgrade::Outdated(installed) => {
            info!("{name} {installed} is older than bundled {bundled}. Upgrading {name}...")
        }
    }
    component.install(paths, true)
}

/// Compare dotted versions numerically, ignoring any non-numeric
/// decoration; None when either cannot be parsed.
pub(super) fn compare_versions(current: &str, target: &str) -> Option<Ordering> {
    let current_parts = parse_version_parts(current)?;
    let target_parts = parse_version_parts(target)?;
    let max_len = current_parts.len().max(target_parts.len());

    for idx in 0..max_len {
        let lhs = *current_parts.get(idx).unwrap_or(&0);
        let rhs = *target_parts.get(idx).unwrap_or(&0);
        let ord = lhs.cmp(&rhs);
        if ord != Ordering::Equal {
            return Some(ord);
        }
    }

    Some(Ordering::Equal)
}

pub(super) fn parse_version_parts(version: &str) -> Option<Vec<u32>> {
    let mut parts = vec![];
    let mut current = String::new();

    for ch in version.trim().chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
        } else if !current.is_empty() {
            let value = match current.parse::<u32>() {
                Ok(value) => value,
                Err(_) => return None,
            };
            parts.push(value);
            current.clear();
        }
    }

    if !current.is_empty() {
        let value = match current.parse::<u32>() {
            Ok(value) => value,
            Err(_) => return None,
        };
        parts.push(value);
    }

    if parts.is_empty() { None } else { Some(parts) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Fake {
        installed: bool,
        version: Option<&'static str>,
        reinstall: bool,
    }

    impl Component for Fake {
        fn name(&self) -> &'static str {
            "Fake"
        }

        fn bundled_version(&self) -> &'static str {
            "1.10"
        }

        fn installed(&self, _paths: &Paths) -> bool {
            self.installed
        }

        fn installed_version(&self, _paths: &Paths) -> Result<Option<String>> {
            Ok(self.version.map(str::to_string))
        }

        fn reinstall_unknown_version(&self) -> bool {
            self.reinstall
        }

        fn install(&self, _paths: &Paths, _upgrade: bool) -> Result<()> {
            unreachable!()
        }
    }

    #[test]
    fn upgrades_follow_installation_state_and_version_order() {
        let paths = Paths::new(PathBuf::from(r"C:\evectl"));
        let needed = |installed, version, reinstall| {
            upgrade_needed(
                &Fake {
                    installed,
                    version,
                    reinstall,
                },
                &paths,
            )
            .unwrap()
        };
        assert_eq!(needed(false, None, false), Some(Upgrade::Install));
        assert_eq!(needed(true, None, false), None);
        assert_eq!(needed(true, None, true), Some(Upgrade::Reinstall));
        assert_eq!(
            needed(true, Some("1.9"), false),
            Some(Upgrade::Outdated("1.9".to_string()))
        );
        assert_eq!(needed(true, Some("1.10"), false), None);
        assert_eq!(needed(true, Some("1.10.1"), false), None);
        assert_eq!(needed(true, Some("2.0"), false), None);
        assert_eq!(needed(true, Some("unknown"), false), None);
    }

    #[test]
    fn versions_compare_numerically_with_loose_formatting() {
        assert_eq!(compare_versions("1.88", "1.9"), Some(Ordering::Greater));
        assert_eq!(compare_versions("8.0.6", "8.0.6-1"), Some(Ordering::Less));
        assert_eq!(compare_versions("8.0", "8.0.0"), Some(Ordering::Equal));
        assert_eq!(compare_versions("v1.2", "1.2"), Some(Ordering::Equal));
        assert_eq!(compare_versions("", "1.0"), None);
    }
}
