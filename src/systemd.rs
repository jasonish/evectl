// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use std::io::Write;

const TEMPLATE: &str = r#"
[Unit]
Description=EveCtl
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart={current_exe} start
ExecStop={current_exe} stop
WorkingDirectory={working_directory}
User={username}
RemainAfterExit=true

[Install]
WantedBy=default.target
"#;

const PATH: &str = "/etc/systemd/system/evectl.service";

pub(crate) fn format_template() -> Result<String> {
    let whoami = std::process::Command::new("whoami").output()?.stdout;
    let whoami = String::from_utf8(whoami)?;
    let current_exe = std::env::current_exe()?;
    let working_directory = std::env::current_dir()?;
    let template = TEMPLATE
        .replace("{current_exe}", &current_exe.to_string_lossy())
        .replace("{working_directory}", &working_directory.to_string_lossy())
        .replace("{username}", whoami.trim());
    Ok(template.trim().to_string())
}

pub(crate) fn install() -> Result<()> {
    info!("Using sudo to install and active {}", PATH);
    info!("You may be asked for your password to continue...");

    let uid = evectl::system::getuid();

    // Using sudo, install systemd unit file.
    let template = format_template()?;

    // Write out template to tempfile.
    let mut tmp = tempfile::NamedTempFile::new()?;
    tmp.write_all(template.as_bytes())?;

    sudo_command(uid, "cp").arg(tmp.path()).arg(PATH).status()?;
    sudo_command(uid, "systemctl")
        .arg("daemon-reload")
        .status()?;
    sudo_command(uid, "systemctl")
        .arg("enable")
        .arg("evectl")
        .status()?;
    Ok(())
}

pub(crate) fn remove() {
    info!("Using sudo to removed and de-activate {}", PATH);
    info!("You may be asked for your password to continue...");

    let uid = evectl::system::getuid();

    if let Err(err) = sudo_command(uid, "systemctl")
        .arg("disable")
        .arg("evectl")
        .status()
    {
        error!("Failed to disable evectl: {}", err);
    }

    if let Err(err) = sudo_command(uid, "rm").arg(PATH).status() {
        error!("Failed to remove evectl.service: {}", err);
    }

    if let Err(err) = sudo_command(uid, "systemctl").arg("daemon-reload").status() {
        error!("Failed to reload systemd: {}", err);
    }
}

/// Check if the systemd service is enabled.
///
/// This is a simple test looking for the existence of the following
/// files:
/// - /etc/systemd/system/default.target.wants/evectl.service
/// - /etc/systemd/system/evectl.service
pub(crate) fn is_enabled() -> bool {
    std::path::Path::new("/etc/systemd/system/default.target.wants/evectl.service").exists()
        || std::path::Path::new("/etc/systemd/system/evectl.service").exists()
}

fn sudo_command(uid: u32, prog: &str) -> std::process::Command {
    if uid == 0 {
        std::process::Command::new("prog")
    } else {
        let mut command = std::process::Command::new("sudo");
        command.arg(prog);
        command
    }
}
