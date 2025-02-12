// SPDX-FileCopyrightText: (C) 2024 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use colored::Colorize;

use crate::context::Context;
use crate::prelude::*;
use crate::prompt::Selections;
use crate::term;

#[derive(Clone)]
enum Options {
    Toggle,
    Interface,
    SensorName,
    Bpf,
    Exit,
}

pub(crate) fn menu(context: &mut Context) -> Result<()> {
    let config = &mut context.config;
    let original = config.clone();

    loop {
        term::clear();

        if config != &original {
            warn!("Suricata configuration updated, restart required.");
        }

        let mut selections = crate::prompt::Selections::new();

        if config.suricata.enabled {
            selections.push(Options::Toggle, "Disable Suricata");
        } else {
            selections.push(Options::Toggle, "Enable Suricata");
        }

        if config.suricata.interfaces.is_empty() {
            selections.push(Options::Interface, "Select Interface");
        } else {
            selections.push(
                Options::Interface,
                format!(
                    "Select Interface (current: {})",
                    &config.suricata.interfaces[0]
                ),
            );
        }

        //selections.push(Options::SensorName, "Set Sensor Name");

        selections.push(Options::SensorName, {
            if let Some(sensor_name) = &config.suricata.sensor_name {
                format!("Sensor Name (current: {})", sensor_name)
            } else {
                "Sensor Name (current: none)".to_string()
            }
        });


        let current_bpf = if let Some(bpf) = &config.suricata.bpf {
            format!(" (current: \"{}\")", bpf)
        } else {
            " (current: none)".to_string()
        };
        selections.push(Options::Bpf, format!("BPF filter{}", current_bpf));

        selections.push(Options::Exit, "Return");

        match inquire::Select::new("EveCtl: Configure Suricata", selections.to_vec()).prompt() {
            Ok(selection) => match selection.tag {
                Options::Toggle => {
                    toggle_enabled(config);
                }
                Options::Interface => {
                    let interface = select_interface("Select Interface")?;
                    config.suricata.interfaces = vec![interface.clone()];
                }
                Options::SensorName => {
                    set_sensor_name(config);
                }
                Options::Bpf => {
                    set_bpf_filter(config);
                }
                Options::Exit => break,
            },
            Err(_) => break,
        }
    }

    if config != &original {
        config.save()?;
    }

    Ok(())
}

fn set_sensor_name(config: &mut Config) {
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

fn toggle_enabled(config: &mut Config) {
    config.suricata.enabled = !config.suricata.enabled;
    if config.suricata.enabled && config.suricata.interfaces.is_empty() {
        if let Ok(interface) = select_interface("Select Interface") {
            config.suricata.interfaces = vec![interface];
        }
    }
}

pub(crate) fn select_interface(prompt: &str) -> Result<String> {
    let interfaces = evectl::system::get_interfaces().unwrap();

    let mut selections = Selections::with_index();
    for interface in &interfaces {
        let address = interface
            .addr4
            .first()
            .map(|s| format!("-- {}", s.green().italic()))
            .unwrap_or("".to_string());
        selections.push(&interface.name, format!("{} {}", interface.name, address));
    }

    let iface = inquire::Select::new(prompt, selections.to_vec()).prompt()?;
    Ok(iface.tag.to_string())
}

fn set_bpf_filter(config: &mut Config) {
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
