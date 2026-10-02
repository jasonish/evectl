// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Build background launches without exposing environment secrets in argv.

use std::process::Command;

fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Start-Process joins ArgumentList with spaces, so each argument must also
/// be quoted for the child's Windows command-line parser.
fn quote_argument(value: &str) -> String {
    let mut quoted = String::from("\"");
    let mut slashes = 0;
    for ch in value.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        if ch == '"' {
            quoted.extend(std::iter::repeat_n('\\', slashes * 2 + 1));
        } else {
            quoted.extend(std::iter::repeat_n('\\', slashes));
        }
        slashes = 0;
        quoted.push(ch);
    }
    quoted.extend(std::iter::repeat_n('\\', slashes * 2));
    quoted.push('"');
    quoted
}

pub(super) fn detached_command(command: &Command) -> Command {
    let program = powershell_quote(&command.get_program().to_string_lossy());
    let working_dir = command
        .get_current_dir()
        .map(|path| powershell_quote(&path.to_string_lossy()))
        .unwrap_or_else(|| "'.'".to_string());
    let argument_list = command
        .get_args()
        .map(|arg| powershell_quote(&quote_argument(&arg.to_string_lossy())))
        .collect::<Vec<_>>()
        .join(", ");
    let script = format!(
        "$argList = @({argument_list}); \
         $p = Start-Process -FilePath {program} -WorkingDirectory {working_dir} \
         -ArgumentList $argList -WindowStyle Hidden -PassThru; \
         Write-Output $p.Id"
    );

    let mut launcher = Command::new("powershell");
    launcher.args(["-NoProfile", "-Command", &script]);
    // Start-Process inherits the PowerShell environment. Do not interpolate
    // credentials into the script or they will appear in its command line.
    for (name, value) in command.get_envs() {
        match value {
            Some(value) => launcher.env(name, value),
            None => launcher.env_remove(name),
        };
    }
    launcher
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn quotes_windows_arguments() {
        assert_eq!(quote_argument(""), "\"\"");
        assert_eq!(quote_argument("agent"), "\"agent\"");
        assert_eq!(
            quote_argument(r"C:\Users\Test User\pcap"),
            r#""C:\Users\Test User\pcap""#
        );
        assert_eq!(quote_argument("path\\"), "\"path\\\\\"");
        assert_eq!(quote_argument("a\\\"b"), "\"a\\\\\\\"b\"");
    }

    #[test]
    fn detached_launch_preserves_environment_without_logging_key() {
        let mut command = Command::new(r"C:\Test User\evebox.exe");
        command.current_dir(r"C:\Test User\agent");
        command.args(["agent", "--pcap-directory", r"C:\O'Brien\Test User\pcap"]);
        command.env("EVEBOX_SERVER_KEY", "secret-agent-key");
        command.env_remove("UNUSED_VARIABLE");
        let launcher = detached_command(&command);
        let script = launcher.get_args().last().unwrap().to_string_lossy();
        assert!(script.contains(r#"'"C:\O''Brien\Test User\pcap"'"#));
        assert!(!script.contains("secret-agent-key"));
        assert!(!script.contains("EVEBOX_SERVER_KEY"));
        assert!(launcher.get_envs().any(|(name, value)| {
            name == "EVEBOX_SERVER_KEY" && value == Some(OsStr::new("secret-agent-key"))
        }));
        assert!(
            launcher
                .get_envs()
                .any(|(name, value)| { name == "UNUSED_VARIABLE" && value.is_none() })
        );
    }
}
