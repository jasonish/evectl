// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use crate::container::CommandExt;
use std::io::Write;
use std::path::Path;

const TEMPLATE: &str = r#"
[Unit]
Description=EveCtl
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart={current_exe} -D {exec_root} start
ExecStop={current_exe} -D {exec_root} stop
WorkingDirectory={root}
User={username}
RemainAfterExit=true

[Install]
WantedBy=default.target
"#;

const PATH: &str = "/etc/systemd/system/evectl.service";

pub(crate) fn format_template(root: &Path) -> Result<String> {
    let whoami = std::process::Command::new("whoami").output()?.stdout;
    let whoami = String::from_utf8(whoami)?;
    let current_exe = std::env::current_exe()?;
    let template = TEMPLATE
        .replace("{current_exe}", &exec_quote(&current_exe.to_string_lossy()))
        .replace("{exec_root}", &exec_quote(&root.to_string_lossy()))
        .replace("{root}", &specifier_escape(&root.to_string_lossy()))
        .replace("{username}", whoami.trim());
    Ok(template.trim().to_string())
}

/// Quote a path for an ExecStart/ExecStop command line: systemd
/// word-splits on whitespace and expands '%' specifiers.
fn exec_quote(path: &str) -> String {
    let escaped = path
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    format!("\"{}\"", escaped)
}

/// Escape '%' for settings like WorkingDirectory that take a single
/// path: no word splitting, but specifiers still expand.
fn specifier_escape(path: &str) -> String {
    path.replace('%', "%%")
}

pub(crate) fn install(root: &Path) -> Result<()> {
    info!("Using sudo to install and active {}", PATH);
    info!("You may be asked for your password to continue...");

    let uid = evectl::system::getuid();

    // Using sudo, install systemd unit file.
    let template = format_template(root)?;

    // Write out template to tempfile.
    let mut tmp = tempfile::NamedTempFile::new()?;
    tmp.write_all(template.as_bytes())?;

    sudo_command(uid, "cp")
        .arg(tmp.path())
        .arg(PATH)
        .status_ok()?;
    sudo_command(uid, "systemctl")
        .arg("daemon-reload")
        .status_ok()?;
    sudo_command(uid, "systemctl")
        .arg("enable")
        .arg("evectl")
        .status_ok()?;
    Ok(())
}

pub(crate) fn remove() -> Result<()> {
    info!("Using sudo to removed and de-activate {}", PATH);
    info!("You may be asked for your password to continue...");

    let uid = evectl::system::getuid();
    let mut errors = vec![];

    if let Err(err) = sudo_command(uid, "systemctl")
        .arg("disable")
        .arg("evectl")
        .status_ok()
    {
        errors.push(format!("failed to disable evectl: {}", err));
    }

    if let Err(err) = sudo_command(uid, "rm").arg(PATH).status_ok() {
        errors.push(format!("failed to remove evectl.service: {}", err));
    }

    if let Err(err) = sudo_command(uid, "systemctl")
        .arg("daemon-reload")
        .status_ok()
    {
        errors.push(format!("failed to reload systemd: {}", err));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        bail!("{}", errors.join(", "))
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
        std::process::Command::new(prog)
    } else {
        let mut command = std::process::Command::new("sudo");
        command.arg(prog);
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_quote_escapes_specifiers_and_quotes() {
        assert_eq!(exec_quote("/srv/sensor1"), "\"/srv/sensor1\"");
        assert_eq!(exec_quote("/srv/my sensor"), "\"/srv/my sensor\"");
        assert_eq!(exec_quote("/srv/100%"), "\"/srv/100%%\"");
        assert_eq!(exec_quote("/srv/a\"b"), "\"/srv/a\\\"b\"");
    }

    #[test]
    fn format_template_quotes_instance_directory() {
        let template = format_template(Path::new("/srv/my sensor")).unwrap();
        assert!(template.contains(" -D \"/srv/my sensor\" start"));
        assert!(template.contains(" -D \"/srv/my sensor\" stop"));
        assert!(template.contains("WorkingDirectory=/srv/my sensor"));
    }
}
