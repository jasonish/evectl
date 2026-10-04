// SPDX-FileCopyrightText: (C) 2024 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

#[cfg(test)]
mod tests;

use colored::Colorize;

use crate::config::EveOutput;
use crate::menu::file_extraction;
use crate::prelude::*;
use crate::prompt::Selections;
use crate::suricata::configuration::{Backend, Interface};
use crate::term;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Options {
    Toggle,
    Interface,
    SensorName,
    Bpf,
    EveOutput,
    FileExtraction,
    FileExtractionForceFilestore,
    FileExtractionMaxSize,
    FileExtractionRetention,
    FileExtractionRemove,
    Exit,
}

fn menu_options(config: &Config, backend: &dyn Backend) -> Result<Selections<Options>> {
    let mut selections = Selections::new();
    selections.push(
        Options::Toggle,
        if config.suricata.enabled {
            "Disable Suricata"
        } else {
            "Enable Suricata"
        },
    );
    selections.push(
        Options::Interface,
        match config.suricata.interfaces.first() {
            Some(interface) => format!("Select Interface (current: {interface})"),
            None => "Select Interface".to_string(),
        },
    );
    selections.push(
        Options::SensorName,
        format!(
            "Sensor Name (current: {})",
            config.suricata.sensor_name.as_deref().unwrap_or("none"),
        ),
    );
    let current_bpf = match &config.suricata.bpf {
        Some(bpf) => format!(" (current: \"{bpf}\")"),
        None => " (current: none)".to_string(),
    };
    selections.push(Options::Bpf, format!("BPF filter{current_bpf}"));

    // A backend with a fixed output (Windows: file) offers no selector.
    if backend.eve_outputs().len() > 1 {
        selections.push(
            Options::EveOutput,
            format!(
                "EVE output (current: {})",
                config.suricata.eve_output.name(),
            ),
        );
    }

    if config.suricata.file_extraction.enabled {
        selections.push(Options::FileExtraction, "Disable File Extraction");
        selections.push(
            Options::FileExtractionForceFilestore,
            file_extraction::force_filestore_label(config),
        );
        selections.push(
            Options::FileExtractionMaxSize,
            file_extraction::max_size_label(config),
        );
        selections.push(
            Options::FileExtractionRetention,
            file_extraction::retention_label(config),
        );
    } else {
        selections.push(Options::FileExtraction, "Enable File Extraction");
        if let Some(label) = file_extraction::remove_label_for(config, &backend.filestore_dir()?) {
            selections.push(Options::FileExtractionRemove, label);
        }
    }
    selections.push(Options::Exit, "Return");
    Ok(selections)
}

pub(crate) fn menu(config: &mut Config, backend: &dyn Backend) -> Result<()> {
    loop {
        term::clear();
        let selections = menu_options(config, backend)?;
        match selections.prompt("EveCtl: Configure Suricata")? {
            None | Some(Options::Exit) => break,
            Some(action) => crate::prompt::report(
                "Suricata configuration failed",
                run_action(config, backend, action),
            ),
        }
    }
    Ok(())
}

fn run_action(config: &mut Config, backend: &dyn Backend, action: Options) -> Result<()> {
    match action {
        Options::Toggle => toggle_enabled(config, || {
            select_interface_from("Select Interface", backend.interfaces()?)
        })?,
        Options::Interface => {
            let interface = select_interface_from("Select Interface", backend.interfaces()?)?;
            config.suricata.interfaces = vec![interface];
        }
        Options::SensorName => edit_setting(
            &mut config.suricata.sensor_name,
            "Enter Sensor Name:",
            "Clear Sensor Name?",
        ),
        Options::Bpf => edit_setting(
            &mut config.suricata.bpf,
            "Enter BPF filter:",
            "Clear BPF filter?",
        ),
        Options::EveOutput => set_eve_output(config, backend.eve_outputs())?,
        Options::FileExtraction => {
            file_extraction::toggle_config(config, &backend.filestore_dir()?);
        }
        Options::FileExtractionForceFilestore => file_extraction::set_force_filestore(config),
        Options::FileExtractionMaxSize => file_extraction::set_max_size(config),
        Options::FileExtractionRetention => file_extraction::set_retention(config),
        Options::FileExtractionRemove => {
            if config.suricata.file_extraction.enabled {
                bail!("Disable file extraction before removing extracted files");
            }
            crate::menu::cleanup::remove_with_confirmation(
                backend,
                crate::prompt::confirm_destructive,
            )?;
        }
        Options::Exit => {}
    }
    Ok(())
}

fn set_eve_output(config: &mut Config, outputs: &[EveOutput]) -> Result<()> {
    if outputs.len() < 2 {
        return Ok(());
    }
    let mut selections = Selections::new();
    for output in outputs {
        selections.push(*output, output.name());
    }
    let current = outputs
        .iter()
        .position(|output| *output == config.suricata.eve_output)
        .unwrap_or(0);
    if let Some(output) = selections.prompt_with("Select EVE output", |select| {
        select.with_starting_cursor(current)
    })? {
        config.suricata.eve_output = output;
    }
    Ok(())
}

/// Edit an optional setting, keeping it if the prompt is cancelled.
fn edit_setting(setting: &mut Option<String>, prompt: &str, clear_prompt: &str) {
    if let Some(value) = crate::prompt::edit_optional(prompt, setting.as_deref(), clear_prompt) {
        *setting = value;
    }
}

fn toggle_enabled(config: &mut Config, select: impl FnOnce() -> Result<String>) -> Result<()> {
    config.suricata.enabled = !config.suricata.enabled;
    if config.suricata.enabled && config.suricata.interfaces.is_empty() {
        config.suricata.interfaces = vec![select()?];
    }
    Ok(())
}

fn interface_choices(interfaces: Vec<Interface>) -> Result<Selections<String>> {
    if interfaces.is_empty() {
        bail!("No network interfaces found");
    }
    let mut selections = Selections::with_index();
    for interface in interfaces {
        let address = interface
            .address
            .map(|address| format!("-- {}", address.green().italic()))
            .unwrap_or_default();
        let label = format!("{} {}", interface.name, address);
        selections.push(interface.name, label);
    }
    Ok(selections)
}

/// Interface prompt shared with the setup wizard.
pub(crate) fn select_interface_from(prompt: &str, interfaces: Vec<Interface>) -> Result<String> {
    let choices = interface_choices(interfaces)?;
    Ok(choices.select(prompt).prompt()?.tag)
}
