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

    loop {
        term::clear();

        let mut selections = crate::prompt::Selections::new();

        if config.suricata.enabled {
            selections.push(Options::Toggle, "Disable Suricata");
        } else {
            selections.push(Options::Toggle, "Enable Suricata");
        }

        if config.suricata.interfaces.is_empty() {
            selections.push(Options::Interface, "Select Interface");
        } else {
            let interface_display = if cfg!(windows) {
                // On Windows, try to display a friendly name instead of the GUID
                let current = &config.suricata.interfaces[0];
                if current.starts_with("\\Device\\NPF_") {
                    // Try to find the friendly name for this GUID
                    #[cfg(windows)]
                    {
                        if let Ok(interfaces) = evectl::system::get_interfaces() {
                            let guid = current.trim_start_matches("\\Device\\NPF_");
                            interfaces
                                .iter()
                                .find(|i| i.guid.as_ref().is_some_and(|g| g == guid))
                                .map(|i| i.name.clone())
                                .unwrap_or_else(|| current.clone())
                        } else {
                            current.clone()
                        }
                    }
                    #[cfg(not(windows))]
                    current.clone()
                } else {
                    current.clone()
                }
            } else {
                config.suricata.interfaces[0].clone()
            };

            selections.push(
                Options::Interface,
                format!("Select Interface (current: {})", interface_display),
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

        #[cfg(windows)]
        let display_text = {
            let guid_display = interface
                .guid
                .as_ref()
                .map(|g| format!(" [{}]", g.dimmed()))
                .unwrap_or_default();
            format!("{} {}{}", interface.name, address, guid_display)
        };

        #[cfg(not(windows))]
        let display_text = format!("{} {}", interface.name, address);

        selections.push(&interface.name, display_text);
    }

    let iface = inquire::Select::new(prompt, selections.to_vec()).prompt()?;

    #[cfg(windows)]
    {
        // On Windows, we need to return the GUID for Suricata/Npcap
        let selected_name = iface.tag;
        for interface in &interfaces {
            if interface.name == *selected_name {
                if let Some(guid) = &interface.guid {
                    // Ensure GUID has braces
                    let formatted_guid = if guid.starts_with('{') && guid.ends_with('}') {
                        guid.clone()
                    } else {
                        format!("{{{}}}", guid)
                    };
                    return Ok(format!("\\Device\\NPF_{}", formatted_guid));
                }
            }
        }
        // Fallback to interface name if GUID not found
        Ok(selected_name.to_string())
    }

    #[cfg(not(windows))]
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
