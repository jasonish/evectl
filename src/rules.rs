// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Rules-management operations independent of the interactive menu.

use std::collections::HashSet;
use std::path::PathBuf;

use crate::container::{CommandExt, SuricataContainer};
use crate::prelude::*;
use crate::ruleindex::RuleIndex;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Ruleset {
    pub id: String,
    pub summary: Option<String>,
    /// False for obsolete sources or sources requiring parameters that
    /// the interactive enable workflow cannot supply.
    pub can_enable: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum OverrideFile {
    Enable,
    Disable,
    Modify,
}

impl OverrideFile {
    pub(crate) const ALL: [Self; 3] = [Self::Enable, Self::Disable, Self::Modify];

    pub(crate) fn filename(self) -> &'static str {
        match self {
            Self::Enable => "enable.conf",
            Self::Disable => "disable.conf",
            Self::Modify => "modify.conf",
        }
    }
}

pub(crate) trait Backend {
    fn available_rulesets(&self) -> Result<Vec<Ruleset>>;
    /// Must include enabled sources absent from the index. Index summaries
    /// are optional; disabling a source must not require downloading an index.
    fn enabled_rulesets(&self) -> Result<Vec<Ruleset>>;
    fn enable_ruleset(&self, id: &str) -> Result<()>;
    fn disable_ruleset(&self, id: &str) -> Result<()>;
    /// Refreshes the ruleset index first, and includes the backend's
    /// existing reload/restart behavior.
    fn update_rules(&self) -> Result<()>;

    fn override_path(&self, _file: OverrideFile) -> Option<PathBuf> {
        None
    }

    fn write_override_template(&self, _file: OverrideFile) -> Result<()> {
        bail!("Rule override files are not supported by this backend")
    }

    /// Whether rulesets can be added from a user-supplied URL.
    fn supports_custom_rulesets(&self) -> bool {
        false
    }

    /// Add and enable a ruleset downloaded from `url`.
    fn add_custom_ruleset(&self, _name: &str, _url: &str) -> Result<()> {
        bail!("Custom rulesets are not supported by this backend")
    }
}

/// Validate the name of a custom ruleset. The name is passed to
/// suricata-update as an argument and used as a file name, so keep it
/// simple and never let it look like an option.
pub(crate) fn check_custom_ruleset_name(name: &str) -> std::result::Result<(), String> {
    if name.is_empty() {
        return Err("A name is required".into());
    }
    if name.starts_with(['-', '.', '/']) {
        return Err("The name must not start with '-', '.' or '/'".into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c))
    {
        return Err("Use only letters, digits, '-', '_', '.' and '/'".into());
    }
    Ok(())
}

/// Validate the URL of a custom ruleset. suricata-update's
/// %(__version__)s substitution is allowed as it survives URL parsing.
pub(crate) fn check_custom_ruleset_url(url: &str) -> std::result::Result<(), String> {
    match reqwest::Url::parse(url) {
        Ok(parsed) if matches!(parsed.scheme(), "http" | "https") => Ok(()),
        Ok(_) => Err("The URL must start with http:// or https://".into()),
        Err(err) => Err(format!("Invalid URL: {err}")),
    }
}

/// The file suricata-update keeps an enabled source's configuration in,
/// relative to its sources directory.
fn source_filename(name: &str) -> String {
    format!("{}.yaml", name.replace('/', "-"))
}

/// Add a custom ruleset with `suricata-update add-source`, which also
/// enables it. A disabled source of the same name is replaced, as
/// suricata-update would otherwise refuse the name.
pub(crate) fn add_custom_ruleset(context: &Context, name: &str, url: &str) -> Result<()> {
    check_custom_ruleset_name(name).map_err(|err| anyhow!(err))?;
    check_custom_ruleset_url(url).map_err(|err| anyhow!(err))?;

    // /var/lib/suricata/update/sources inside the container.
    let sources_dir = crate::suricata::lib_dir(context)
        .join("update")
        .join("sources");
    let filename = source_filename(name);
    if sources_dir.join(&filename).exists() {
        bail!("A ruleset named {name} is already enabled");
    }

    let container = SuricataContainer::new(context.clone());
    if sources_dir.join(format!("{filename}.disabled")).exists() {
        info!("Replacing the disabled ruleset {name}");
        container
            .run()
            .rm()
            .args(&["suricata-update", "remove-source", name])
            .build()
            .status_ok()?;
    }
    container
        .run()
        .rm()
        .args(&["suricata-update", "add-source", name, url])
        .build()
        .status_ok()
}

pub(crate) fn load_rule_index(context: &Context) -> Result<RuleIndex> {
    let container = SuricataContainer::new(context.clone());
    let output = container
        .run()
        .rm()
        .args(&["cat", "/var/lib/suricata/update/cache/index.yaml"])
        .build()
        .status_output()?;
    let index: RuleIndex = yaml_serde::from_slice(&output)?;
    Ok(index)
}

/// Load the ruleset index, downloading it first if it isn't cached yet,
/// such as before the first rule update.
pub(crate) fn get_or_download_rule_index(context: &Context) -> Result<RuleIndex> {
    let cached = crate::suricata::lib_dir(context)
        .join("update")
        .join("cache")
        .join("index.yaml");
    if !cached.exists() {
        info!("Downloading the ruleset index...");
        update_sources(context)?;
    }
    load_rule_index(context)
}

pub(crate) fn get_enabled_ruleset(context: &Context) -> Result<HashSet<String>> {
    let mut enabled: HashSet<String> = HashSet::new();
    let container = SuricataContainer::new(context.clone());
    let output = container
        .run()
        .rm()
        .args(&["suricata-update", "list-sources", "--enabled"])
        .build()
        .status_output()?;
    let stdout = String::from_utf8_lossy(&output);
    let re = regex::Regex::new(r"^[\s]*\-\s*(.*)").unwrap();
    for line in stdout.lines() {
        if let Some(caps) = re.captures(line) {
            enabled.insert(String::from(&caps[1]));
        }
    }
    Ok(enabled)
}

pub(crate) fn enable_ruleset(context: &Context, ruleset: &str) -> Result<()> {
    let container = SuricataContainer::new(context.clone());
    container
        .run()
        .rm()
        .args(&["suricata-update", "enable-source", ruleset])
        .build()
        .status_ok()?;
    Ok(())
}

pub(crate) fn disable_ruleset(context: &Context, ruleset: &str) -> Result<()> {
    let container = SuricataContainer::new(context.clone());
    container
        .run()
        .rm()
        .args(&["suricata-update", "disable-source", ruleset])
        .build()
        .status_ok()?;
    Ok(())
}

pub(crate) fn update_sources(context: &Context) -> Result<()> {
    SuricataContainer::new(context.clone())
        .run()
        .rm()
        .it()
        .args(&["suricata-update", "update-sources"])
        .build()
        .status_ok()
}

pub(crate) fn update_rules(context: &Context, extra_args: &[&str]) -> Result<()> {
    if !context.config.suricata.enabled {
        bail!("Suricata is not enabled.");
    }
    let container = SuricataContainer::new(context.clone());

    let mut volumes = vec![];

    for file in OverrideFile::ALL {
        let source = context.config_dir().join(file.filename());
        let target = format!("/etc/suricata/{}", file.filename());
        if source.exists() {
            info!("Bind-mounting {} to {}", source.display(), &target);
            volumes.push(context.manager.bind_mount(&source, &target));
        }
    }

    info!("Updating Suricata rule sources...");
    if let Err(err) = update_sources(context) {
        error!("Rule source update did not complete successfully: {err}");
    }

    info!("Updating Suricata rules...");
    let suricata_running = context
        .manager
        .is_running(&crate::suricata::container_name(context));
    if !suricata_running && !extra_args.contains(&"--no-reload") {
        info!("Suricata is not running; skipping rule reload");
    }
    let args = build_update_args(extra_args, suricata_running);
    container
        .run()
        .rm()
        .it()
        .volumes(&volumes)
        .args(&args)
        .build()
        .status_ok()
        .context("Rule update did not complete successfully")
}

fn build_update_args<'a>(extra_args: &[&'a str], suricata_running: bool) -> Vec<&'a str> {
    let mut args = vec!["suricata-update"];
    args.extend_from_slice(extra_args);
    if !suricata_running && !args.contains(&"--no-reload") {
        args.push("--no-reload");
    }
    args
}

#[cfg(test)]
mod tests {
    use super::{
        build_update_args, check_custom_ruleset_name, check_custom_ruleset_url, source_filename,
    };

    #[test]
    fn custom_ruleset_names() {
        for name in ["local", "local/my-rules", "my_rules.v2", "A1"] {
            assert!(check_custom_ruleset_name(name).is_ok(), "{name}");
        }
        for name in ["", "-x", "--help", ".hidden", "/abs", "a b", "a\\b", "a:b"] {
            assert!(check_custom_ruleset_name(name).is_err(), "{name}");
        }
    }

    #[test]
    fn custom_ruleset_urls() {
        for url in [
            "https://example.com/rules.tar.gz",
            "http://example.com:8080/rules.rules",
            "https://example.com/suricata-%(__version__)s/rules.tar.gz",
        ] {
            assert!(check_custom_ruleset_url(url).is_ok(), "{url}");
        }
        for url in ["", "example.com/rules", "ftp://example.com/r", "file:///r"] {
            assert!(check_custom_ruleset_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn custom_ruleset_filename_matches_suricata_update() {
        assert_eq!(source_filename("local/my-rules"), "local-my-rules.yaml");
    }

    #[test]
    fn update_args_reload_when_suricata_is_running() {
        assert_eq!(build_update_args(&[], true), vec!["suricata-update"]);
    }

    #[test]
    fn update_args_skip_reload_when_suricata_is_stopped() {
        assert_eq!(
            build_update_args(&[], false),
            vec!["suricata-update", "--no-reload"]
        );
    }

    #[test]
    fn update_args_do_not_duplicate_no_reload() {
        assert_eq!(
            build_update_args(&["--no-reload", "--no-test"], false),
            vec!["suricata-update", "--no-reload", "--no-test"]
        );
    }
}
