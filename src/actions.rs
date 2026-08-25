// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use std::collections::HashSet;

use crate::build_evebox_agent_command;
use crate::build_evebox_server_command;
use crate::container::{CommandExt, SuricataContainer};
use crate::context::Context;
use crate::ruleindex::RuleIndex;

pub(crate) fn load_rule_index(context: &Context) -> Result<RuleIndex> {
    let container = SuricataContainer::new(context.clone());
    let output = container
        .run()
        .rm()
        .args(&["cat", "/var/lib/suricata/update/cache/index.yaml"])
        .build()
        .status_output()?;
    let index: RuleIndex = serde_yaml::from_slice(&output)?;
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

pub(crate) fn update_rules(context: &Context, extra_args: &[&str]) -> Result<()> {
    if !context.config.suricata.enabled {
        bail!("Suricata is not enabled.");
    }
    let container = SuricataContainer::new(context.clone());

    let mut volumes = vec![];

    let config_filenames = ["enable.conf", "disable.conf", "modify.conf"];
    for filename in config_filenames {
        let source = context.config_dir().join(filename);
        let target = format!("/etc/suricata/{}", filename);
        if source.exists() {
            info!("Bind-mounting {} to {}", source.display(), &target);
            volumes.push(context.manager.bind_mount(&source, &target));
        }
    }

    info!("Updating Suricata rule sources...");
    if let Err(err) = container
        .run()
        .rm()
        .it()
        .args(&["suricata-update", "update-sources"])
        .build()
        .status_ok()
    {
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
    if let Err(err) = container
        .run()
        .rm()
        .it()
        .volumes(&volumes)
        .args(&args)
        .build()
        .status_ok()
    {
        error!("Rule update did not complete successfully: {err}");
    }
    Ok(())
}

fn build_update_args<'a>(extra_args: &[&'a str], suricata_running: bool) -> Vec<&'a str> {
    let mut args = vec!["suricata-update"];
    args.extend_from_slice(extra_args);
    if !suricata_running && !args.contains(&"--no-reload") {
        args.push("--no-reload");
    }
    args
}

pub(crate) fn start_evebox_server(context: &Context) -> Result<()> {
    let container_name = crate::evebox::server::container_name(context);
    if context.manager.is_running(&container_name) {
        info!("EveBox-Server is already running");
        return Ok(());
    }
    context.manager.quiet_rm(&container_name);
    let mut command = build_evebox_server_command(context, true)?;
    let output = command.output()?;
    if !output.status.success() {
        bail!(String::from_utf8_lossy(&output.stderr).to_string());
    }
    Ok(())
}

pub(crate) fn start_evebox_agent(context: &Context) -> Result<()> {
    let container_name = crate::evebox::agent::container_name(context);
    if context.manager.is_running(&container_name) {
        info!("EveBox-Agent is already running");
        return Ok(());
    }
    context.manager.quiet_rm(&container_name);
    let mut command = build_evebox_agent_command(context, true)?;
    let output = command.output()?;
    if !output.status.success() {
        bail!(String::from_utf8_lossy(&output.stderr).to_string());
    }
    Ok(())
}

pub(crate) fn _stop_evebox_agent(context: &Context) -> Result<()> {
    context.manager.stop(
        &crate::evebox::agent::container_name(context),
        Some("SIGINT"),
    )
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
