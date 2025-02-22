// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use std::collections::HashSet;

use crate::build_evebox_agent_command;
use crate::build_evebox_server_command;
use crate::container::{CommandExt, SuricataContainer};
use crate::context::Context;
use crate::ruleindex::RuleIndex;

pub(crate) fn force_suricata_logrotate(context: &Context) {
    let _ = context
        .manager
        .command()
        .args([
            "exec",
            &crate::suricata::container_name(context),
            "logrotate",
            "-fv",
            "/etc/logrotate.d/suricata",
        ])
        .status();
}

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
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
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

pub(crate) fn update_rules(context: &Context) -> Result<()> {
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
            volumes.push(format!("{}:{}", source.display(), target));
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
    if let Err(err) = container
        .run()
        .rm()
        .it()
        .volumes(&volumes)
        .args(&["suricata-update"])
        .build()
        .status_ok()
    {
        error!("Rule update did not complete successfully: {err}");
    }
    Ok(())
}

pub(crate) fn start_evebox_server(context: &Context) -> Result<()> {
    context
        .manager
        .quiet_rm(&crate::evebox::server::container_name(context));
    let mut command = build_evebox_server_command(context, true)?;
    let output = command.output()?;
    if !output.status.success() {
        bail!(String::from_utf8_lossy(&output.stderr).to_string());
    }
    Ok(())
}

pub(crate) fn start_evebox_agent(context: &Context) -> Result<()> {
    context
        .manager
        .quiet_rm(&crate::evebox::agent::container_name(context));
    let mut command = build_evebox_agent_command(context, true);
    let output = command.output()?;
    if !output.status.success() {
        bail!(String::from_utf8_lossy(&output.stderr).to_string());
    }
    Ok(())
}

pub(crate) fn stop_evebox_server(context: &Context) -> Result<()> {
    context.manager.stop(
        &crate::evebox::server::container_name(context),
        Some("SIGINT"),
    )
}

pub(crate) fn _stop_evebox_agent(context: &Context) -> Result<()> {
    context.manager.stop(
        &crate::evebox::agent::container_name(context),
        Some("SIGINT"),
    )
}
