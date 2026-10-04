// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Rules-management operations independent of the interactive menu.

use std::collections::HashSet;
use std::path::PathBuf;

use crate::container::{CommandExt, Container, RunCommandBuilder, SuricataContainer};
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
    fn update_sources(&self) -> Result<()>;
    /// Includes the backend's existing reload/restart behavior.
    fn update_rules(&self) -> Result<()>;

    fn override_path(&self, _file: OverrideFile) -> Option<PathBuf> {
        None
    }

    fn write_override_template(&self, _file: OverrideFile) -> Result<()> {
        bail!("Rule override files are not supported by this backend")
    }
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

pub(crate) fn get_enabled_ruleset(context: &Context) -> Result<HashSet<String>> {
    let mut enabled: HashSet<String> = HashSet::new();
    let container = SuricataContainer::new(context.clone());
    let output = container
        .run()
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
        .args(&["suricata-update", "enable-source", ruleset])
        .build()
        .status_ok()?;
    Ok(())
}

pub(crate) fn disable_ruleset(context: &Context, ruleset: &str) -> Result<()> {
    let container = SuricataContainer::new(context.clone());
    container
        .run()
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

pub(crate) struct ContainerBackend<'a>(pub(crate) &'a Context);

impl Backend for ContainerBackend<'_> {
    fn available_rulesets(&self) -> Result<Vec<Ruleset>> {
        Ok(load_rule_index(self.0)?
            .sources
            .into_iter()
            .map(|(id, source)| Ruleset {
                id,
                summary: Some(source.summary),
                can_enable: source.obsolete.is_none() && source.parameters.is_none(),
            })
            .collect())
    }

    fn enabled_rulesets(&self) -> Result<Vec<Ruleset>> {
        let enabled = get_enabled_ruleset(self.0)?;
        if enabled.is_empty() {
            return Ok(vec![]);
        }
        let index = load_rule_index(self.0).ok();
        Ok(enabled
            .into_iter()
            .map(|id| {
                let summary = index
                    .as_ref()
                    .and_then(|index| index.sources.get(&id))
                    .map(|source| source.summary.clone());
                Ruleset {
                    id,
                    summary,
                    can_enable: false,
                }
            })
            .collect())
    }

    fn enable_ruleset(&self, id: &str) -> Result<()> {
        enable_ruleset(self.0, id)
    }

    fn disable_ruleset(&self, id: &str) -> Result<()> {
        disable_ruleset(self.0, id)
    }

    fn update_sources(&self) -> Result<()> {
        update_sources(self.0)
    }

    fn update_rules(&self) -> Result<()> {
        update_rules(self.0, &[])
    }

    fn override_path(&self, file: OverrideFile) -> Option<PathBuf> {
        Some(self.0.config_dir().join(file.filename()))
    }

    fn write_override_template(&self, file: OverrideFile) -> Result<()> {
        let source = format!(
            "/usr/lib/suricata/python/suricata/update/configs/{}",
            file.filename()
        );
        let output = RunCommandBuilder::new(self.0.manager, self.0.image_name(Container::Suricata))
            .rm()
            .args(&["cat", &source])
            .build()
            .status_output()?;
        std::fs::create_dir_all(self.0.config_dir())?;
        std::fs::write(self.0.config_dir().join(file.filename()), output)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::build_update_args;

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
