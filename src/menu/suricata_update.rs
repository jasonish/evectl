// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::{
    container::{CommandExt, Container, RunCommandBuilder},
    context::Context,
    prompt, term,
};
use anyhow::Result;
use colored::Colorize;
use std::io::Write;
use tracing::error;

#[derive(Debug, Clone)]
enum Options {
    EnableConf,
    DisableConf,
    ModifyConf,
    EnableRuleset,
    DisableRuleset,
    UpdateRules,
    Return,
}

/// Suricata configure menu.
pub(crate) fn menu(context: &mut Context) -> Result<()> {
    loop {
        term::title("EveCtl: Manager Suricata-Update");

        let selections = crate::prompt::Selections::with_index()
            .push(Options::EnableConf, "Edit enable.conf")
            .push(Options::DisableConf, "Edit disable.conf")
            .push(Options::ModifyConf, "Edit modify.conf")
            .push(Options::EnableRuleset, "Enable a Ruleset")
            .push(Options::DisableRuleset, "Disable a Ruleset")
            .push(Options::UpdateRules, "Update Rules")
            .push(Options::Return, "Return")
            .to_vec();

        match inquire::Select::new("Select menu option", selections).prompt_skippable()? {
            Some(selection) => match selection.tag {
                Options::DisableConf => edit_file(context, "disable.conf"),
                Options::EnableConf => edit_file(context, "enable.conf"),
                Options::ModifyConf => edit_file(context, "modify.conf"),
                Options::EnableRuleset => enable_ruleset(context).unwrap(),
                Options::DisableRuleset => disable_ruleset(context).unwrap(),
                Options::UpdateRules => update_rules(context)?,
                Options::Return => break,
            },
            _ => break,
        }
    }

    Ok(())
}

fn update_rules(context: &Context) -> Result<()> {
    if let Err(err) = crate::actions::update_rules(context) {
        error!("{}", err);
    }
    prompt::enter();
    Ok(())
}

fn disable_ruleset(context: &Context) -> Result<()> {
    let enabled = crate::actions::get_enabled_ruleset(context).unwrap();
    if enabled.is_empty() {
        prompt::enter_with_prefix("No rulesets enabled");
        return Ok(());
    }

    let index = crate::actions::load_rule_index(context).unwrap();
    let mut selections = crate::prompt::Selections::new();

    for (id, source) in &index.sources {
        if enabled.contains(id) {
            let message = format!("{}: {}", id, source.summary.green().italic());
            selections.push(id, message);
        }
    }

    if let Ok(selection) = inquire::Select::new(
        "Choose a ruleset to DISABLE or ESC to exit",
        selections.to_vec(),
    )
    .with_page_size(16)
    .prompt()
    {
        let _ = crate::actions::disable_ruleset(context, selection.tag);

        if prompt::confirm(
            "Would you like to update your rules now?",
            Some("A rule update is required to complete disabling this ruleset"),
        ) {
            crate::actions::update_rules(context)?;
        }

        prompt::enter();
    }

    Ok(())
}

fn enable_ruleset(context: &Context) -> Result<()> {
    let index = crate::actions::load_rule_index(context).unwrap();
    let enabled = crate::actions::get_enabled_ruleset(context).unwrap();
    let mut selections = crate::prompt::Selections::new();

    for (id, source) in &index.sources {
        if source.obsolete.is_some() {
            continue;
        }
        if source.parameters.is_some() {
            continue;
        }
        if enabled.contains(id) {
            continue;
        }

        let message = format!("{}: {}", id, source.summary.green().italic());

        selections.push(id, message);
    }

    if let Ok(selection) = inquire::Select::new(
        "Choose a ruleset to enable or ESC to exit",
        selections.to_vec(),
    )
    .with_page_size(16)
    .prompt()
    {
        let _ = crate::actions::enable_ruleset(context, selection.tag);

        if prompt::confirm(
            "Would you like to update your rules now?",
            Some("A rule update is require to make the new ruleset active"),
        ) {
            crate::actions::update_rules(context)?;
        }

        prompt::enter();
    }

    Ok(())
}

fn copy_suricata_update_template(context: &Context, filename: &str) -> Result<()> {
    let source = format!(
        "/usr/lib/suricata/python/suricata/update/configs/{}",
        filename
    );
    let image = context.image_name(Container::Suricata);
    let output = RunCommandBuilder::new(context.manager, image)
        .rm()
        .args(&["cat", &source])
        .build()
        .status_output()?;
    let target_filename = context.config_dir().join(filename);
    let mut target = std::fs::File::create(target_filename)?;
    target.write_all(&output)?;
    Ok(())
}

fn edit_file(context: &Context, filename: &str) {
    let path = context.config_dir().join(filename);
    if !path.exists() {
        if let Ok(true) = inquire::Confirm::new(&format!(
            "Would you like to start with a {} template",
            filename
        ))
        .with_default(true)
        .prompt()
        {
            if let Err(err) = copy_suricata_update_template(context, filename) {
                error!(
                    "Sorry, an error occurred copying the template for {}: {}",
                    filename, err
                );
                prompt::enter();
            }
        }
    }

    if let Ok(editor) = std::env::var("EDITOR") {
        if let Err(err) = std::process::Command::new(&editor).arg(&path).status() {
            error!("Failed to load {} in editor {}: {}", filename, editor, err);
        } else {
            return;
        }
    }

    if let Err(err) = std::process::Command::new("nanox").arg(&path).status() {
        error!("Failed to load {} in editor {}: {}", filename, "nano", err);
    } else {
        return;
    }

    if let Err(err) = std::process::Command::new("vim").arg(&path).status() {
        error!("Failed to load {} in editor {}: {}", filename, "vim", err);
    } else {
        return;
    }

    if let Err(err) = std::process::Command::new("vi").arg(&path).status() {
        error!("Failed to load {} in editor {}: {}", filename, "vi", err);
    } else {
        return;
    }

    prompt::enter_with_prefix("No editor found, please set to EDITOR environment variable");
}
