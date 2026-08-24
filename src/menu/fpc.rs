// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Full packet capture (FPC) configuration menu.
//!
//! FPC has Suricata write a rotating pcap spool which the local EveBox
//! server serves through its web UI. It requires both to be enabled.

use crate::config::FpcConfig;
use crate::context::Context;
use crate::prelude::*;
use crate::term;

#[derive(Clone)]
enum Options {
    Toggle,
    MaxFiles,
    Return,
}

pub(crate) fn menu(context: &mut Context) -> Result<()> {
    let config = &mut context.config;

    loop {
        term::clear();

        let mut selections = crate::prompt::Selections::new();

        if config.fpc.enabled {
            selections.push(Options::Toggle, "Disable Full Packet Capture");
        } else {
            selections.push(Options::Toggle, "Enable Full Packet Capture");
        }

        selections.push(
            Options::MaxFiles,
            format!(
                "Retention (current: {} x {} files, ~{} GB)",
                config.fpc.max_files(),
                FpcConfig::FILE_SIZE,
                config.fpc.disk_usage_gb()
            ),
        );

        selections.push(Options::Return, "Return");

        match inquire::Select::new("EveCtl: Configure Full Packet Capture", selections.to_vec())
            .prompt()
        {
            Ok(selection) => match selection.tag {
                Options::Toggle => toggle_enabled(config),
                Options::MaxFiles => set_max_files(config),
                Options::Return => break,
            },
            Err(_) => break,
        }
    }

    Ok(())
}

fn toggle_enabled(config: &mut Config) {
    if config.fpc.enabled {
        config.fpc.enabled = false;
        return;
    }

    if !config.suricata.enabled || !config.evebox_server.enabled {
        error!(
            "Full packet capture requires both Suricata and the EveBox server to be enabled \
             (Suricata enabled: {}, EveBox server enabled: {})",
            config.suricata.enabled, config.evebox_server.enabled
        );
        crate::prompt::enter();
        return;
    }

    let message = format!(
        "Enable full packet capture (up to ~{} GB)?",
        config.fpc.disk_usage_gb()
    );
    if inquire::Confirm::new(&message)
        .with_default(false)
        .prompt()
        .unwrap_or(false)
    {
        config.fpc.enabled = true;
    }
}

fn set_max_files(config: &mut Config) {
    let prompt = format!(
        "Maximum total number of {} pcap files to retain (across all capture threads):",
        FpcConfig::FILE_SIZE
    );
    if let Ok(value) = inquire::Text::new(&prompt)
        .with_default(&config.fpc.max_files().to_string())
        .prompt()
    {
        match value.trim().parse::<u32>() {
            Ok(n) if n > 0 => {
                config.fpc.max_files = if n == FpcConfig::DEFAULT_MAX_FILES {
                    None
                } else {
                    Some(n)
                };
            }
            _ => error!("Invalid value, must be a positive number"),
        }
    }
}
