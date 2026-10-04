// SPDX-FileCopyrightText: (C) 2024 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

#[cfg(test)]
mod tests;

use colored::Colorize;

use crate::config::EveOutput;
use crate::context::Context;
use crate::menu::file_extraction;
use crate::prelude::*;
use crate::prompt::Selections;
use crate::suricata::configuration::{Backend, ContainerBackend, Interface};
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

/// Container entry point. Only runtime paths, names, and cleanup image choices
/// use the snapshot; settings are edited directly in the caller's config.
pub(crate) fn container_menu(context: &mut Context) -> Result<()> {
    let runtime = context.clone();
    menu(&mut context.config, &ContainerBackend(&runtime))
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
        let selection =
            match inquire::Select::new("EveCtl: Configure Suricata", selections.to_vec())
                .with_page_size(selections.page_size())
                .prompt()
            {
                Ok(selection) => selection,
                Err(
                    inquire::InquireError::OperationCanceled
                    | inquire::InquireError::OperationInterrupted,
                ) => break,
                Err(err) => return Err(err.into()),
            };
        if selection.tag == Options::Exit {
            break;
        }
        if let Err(err) = run_action(config, backend, selection.tag)
            && !prompt_was_cancelled(&err)
        {
            error!("Suricata configuration failed: {err:#}");
            crate::prompt::enter();
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
        Options::SensorName => set_sensor_name(config),
        Options::Bpf => set_bpf_filter(config),
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
            file_extraction::remove_files(backend)?;
        }
        Options::Exit => {}
    }
    Ok(())
}

fn prompt_was_cancelled(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<inquire::InquireError>(),
        Some(
            inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted
        )
    )
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
    if let Some(selection) = inquire::Select::new("Select EVE output", selections.to_vec())
        .with_starting_cursor(current)
        .prompt_skippable()?
    {
        config.suricata.eve_output = selection.tag;
    }
    Ok(())
}

pub(crate) fn set_sensor_name(config: &mut Config) {
    let current = config.suricata.sensor_name.clone();
    if let Ok(sensor_name) = inquire::Text::new("Enter Sensor Name:").prompt() {
        if sensor_name.trim().is_empty() {
            if current.is_none() {
                return;
            }
            if inquire::Confirm::new("Clear Sensor Name?")
                .with_default(true)
                .prompt()
                .unwrap_or(false)
            {
                config.suricata.sensor_name = None;
            }
        } else {
            config.suricata.sensor_name = Some(sensor_name);
        }
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
    let selection = inquire::Select::new(prompt, choices.to_vec()).prompt()?;
    Ok(selection.tag)
}

pub(crate) fn set_bpf_filter(config: &mut Config) {
    let current = config.suricata.bpf.clone();
    if let Ok(filter) = inquire::Text::new("Enter BPF filter:").prompt() {
        if filter.is_empty() {
            if current.is_none() {
                return;
            }
            if inquire::Confirm::new("Clear BPF filter?")
                .with_default(true)
                .prompt()
                .unwrap_or(false)
            {
                config.suricata.bpf = None;
            }
        } else {
            config.suricata.bpf = Some(filter);
        }
    }
}
