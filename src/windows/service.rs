// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Suricata as a Windows service, registered with Suricata's own
//! `--service-install`. Running under the service manager is what lets
//! Suricata receive the control that reloads rules.

use super::paths::{Paths, ensure_dir};
use super::runtime::{
    is_pid_running, normalize_path_for_compare, path_is_same_or_descendant, powershell,
    powershell_elevated,
};
use crate::prelude::*;
use std::io::IsTerminal;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_CALL_NOT_IMPLEMENTED, ERROR_INVALID_SERVICE_CONTROL,
    ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOT_ACTIVE, HLOCAL, LocalFree, WIN32_ERROR,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
    QueryServiceConfigW, QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_CONTROL_STOP, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_PROCESS,
    SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_USER_DEFINED_CONTROL,
    StartServiceW,
};
use windows::Win32::UI::Shell::CommandLineToArgvW;
use windows::core::{HSTRING, PCWSTR};

/// The name Suricata registers its service under.
const SERVICE_NAME: &str = "Suricata";

const START_TIMEOUT: Duration = Duration::from_secs(10);
const STOP_TIMEOUT: Duration = Duration::from_secs(30);
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// What the user running EveCtl is granted at registration, so that
/// day to day use needs no administrator approval.
const USER_ACCESS: u32 =
    SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | SERVICE_USER_DEFINED_CONTROL;

/// Exit codes of the elevated service scripts.
const COMMAND_FAILED: i32 = 2;
const PERMISSIONS_FAILED: i32 = 3;

/// Why registration needs administrator approval, shown before Windows
/// asks for it.
const INSTALL_REASON: &str = "\
Suricata runs as a Windows service, so EveCtl can have it reload rules
without restarting it. Registering the service is a
one-time step that needs administrator approval.";

const UPDATE_REASON: &str = "\
Suricata's settings have changed, so its Windows service registration
needs updating. This needs administrator approval.";

const ACCESS_REASON: &str = "\
Your account can't start and stop the Suricata service yet. Granting
it access needs administrator approval.";

const APPROVAL_NOTE: &str = "\
Windows will show a User Account Control prompt for Windows PowerShell,
which EveCtl uses to run Suricata's service installer. Choose Yes to
allow it. Starting and stopping Suricata won't need approval after this.";

/// Controls handled by Suricata's service, from the user-defined
/// range of 128 to 255. EveCtl's Suricata builds (from
/// evectl-suricata-windows) reload rules on 128.
#[derive(Debug, Clone, Copy)]
pub(super) enum Control {
    ReloadRules,
}

impl Control {
    fn code(self) -> u32 {
        match self {
            Control::ReloadRules => 128,
        }
    }
}

impl std::fmt::Display for Control {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Control::ReloadRules => "reload its rules",
        })
    }
}

/// A service manager or service handle, closed on drop.
struct Handle(SC_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

/// An open service, holding the manager handle it was opened through.
struct Service {
    handle: Handle,
    _manager: Handle,
}

impl Service {
    fn status(&self) -> Result<SERVICE_STATUS_PROCESS> {
        let mut status = SERVICE_STATUS_PROCESS::default();
        let buffer = unsafe {
            std::slice::from_raw_parts_mut(
                (&raw mut status).cast::<u8>(),
                size_of::<SERVICE_STATUS_PROCESS>(),
            )
        };
        let mut needed = 0;
        unsafe {
            QueryServiceStatusEx(
                self.handle.0,
                SC_STATUS_PROCESS_INFO,
                Some(buffer),
                &mut needed,
            )
        }
        .context("Failed to query service status")?;
        Ok(status)
    }

    /// The command line the service runs, split into arguments.
    fn command_line(&self) -> Result<Vec<String>> {
        let mut needed = 0;
        // The first call only reports the buffer size needed.
        let _ = unsafe { QueryServiceConfigW(self.handle.0, None, 0, &mut needed) };
        let mut buffer = vec![0u64; (needed as usize).div_ceil(size_of::<u64>())];
        let config = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        unsafe { QueryServiceConfigW(self.handle.0, Some(config), needed, &mut needed) }
            .context("Failed to query service configuration")?;
        let binary_path = unsafe { (*config).lpBinaryPathName.to_string() }
            .context("Invalid service binary path")?;
        split_command_line(&binary_path)
    }
}

fn is_error(err: &windows::core::Error, code: WIN32_ERROR) -> bool {
    err.code() == code.to_hresult()
}

/// Open a service, or None if no service of that name is registered.
fn open_service(name: &str, access: u32) -> windows::core::Result<Option<Service>> {
    let manager =
        Handle(unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }?);
    match unsafe { OpenServiceW(manager.0, &HSTRING::from(name), access) } {
        Ok(handle) => Ok(Some(Service {
            handle: Handle(handle),
            _manager: manager,
        })),
        Err(err) if is_error(&err, ERROR_SERVICE_DOES_NOT_EXIST) => Ok(None),
        Err(err) => Err(err),
    }
}

fn open(access: u32) -> Result<Option<Service>> {
    open_service(SERVICE_NAME, access).context("Failed to open the Suricata service")
}

/// Open the Suricata service if it runs EveCtl's Suricata, leaving a
/// service registered by any other installation alone.
fn open_managed(paths: &Paths, access: u32) -> Result<Option<Service>> {
    let Some(service) = open(access | SERVICE_QUERY_CONFIG)? else {
        return Ok(None);
    };
    let managed = is_managed_command(paths, &service.command_line()?);
    Ok(managed.then_some(service))
}

/// Split a command line into arguments the way a Windows program does.
fn split_command_line(line: &str) -> Result<Vec<String>> {
    let mut count = 0;
    let argv = unsafe { CommandLineToArgvW(&HSTRING::from(line), &mut count) };
    if argv.is_null() {
        bail!("Failed to parse command line: {line}");
    }
    let args = (0..count as usize)
        .map(|index| unsafe { (*argv.add(index)).to_string() })
        .collect::<std::result::Result<Vec<_>, _>>();
    unsafe { LocalFree(Some(HLOCAL(argv.cast()))) };
    args.with_context(|| format!("Invalid command line: {line}"))
}

fn is_managed_command(paths: &Paths, command: &[String]) -> bool {
    command.first().is_some_and(|exe| {
        path_is_same_or_descendant(Path::new(exe), &paths.suricata_install_dir())
    })
}

/// Whether a registered command line runs `exe` with `args`. Suricata
/// stores the arguments joined with spaces, so one containing spaces
/// comes back split; the joined forms are compared.
fn command_matches(registered: &[String], exe: &Path, args: &[String]) -> bool {
    match registered.split_first() {
        Some((registered_exe, registered_args)) => {
            normalize_path_for_compare(Path::new(registered_exe)) == normalize_path_for_compare(exe)
                && registered_args.join(" ") == args.join(" ")
        }
        None => false,
    }
}

/// The command line of EveCtl's Suricata service while it is running.
pub(super) fn running_command(paths: &Paths) -> Result<Option<Vec<String>>> {
    let Some(service) = open(SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)? else {
        return Ok(None);
    };
    let command = service.command_line()?;
    if !is_managed_command(paths, &command) || service.status()?.dwCurrentState == SERVICE_STOPPED {
        return Ok(None);
    }
    Ok(Some(command))
}

pub(super) fn is_running(paths: &Paths) -> Result<bool> {
    Ok(running_command(paths)?.is_some())
}

/// True if this user can start, stop, and send controls to the
/// Suricata service.
fn user_has_access() -> Result<bool> {
    match open_service(SERVICE_NAME, USER_ACCESS) {
        Ok(service) => Ok(service.is_some()),
        Err(err) if is_error(&err, ERROR_ACCESS_DENIED) => Ok(false),
        Err(err) => Err(err).context("Failed to open the Suricata service"),
    }
}

/// The SID of the user running EveCtl, taken before elevating as the
/// approving administrator may be a different account.
fn current_user_sid() -> Result<String> {
    let output = powershell(
        "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        "Failed to determine the current user",
    )?;
    let sid = output.trim();
    let valid = sid
        .strip_prefix("S-1-")
        .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '-'));
    if !valid {
        bail!("Unexpected user SID: {sid}");
    }
    Ok(sid.to_string())
}

/// The permissions Suricata's `--service-install` sets, the service
/// manager's default without sending controls (CR) for interactive and
/// service users, plus starting, stopping, and sending controls for
/// the given user.
fn service_sddl(user_sid: &str) -> String {
    format!(
        "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLORC;;;IU)(A;;CCLCSWLORC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;{user_sid})S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
    )
}

/// A PowerShell single-quoted string literal.
fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// The elevated script that runs a service command, then grants
/// `sddl` on the service if given, recording the output in `log`. A
/// failing command's exit code is recorded too, as a program that
/// can't start, for a missing DLL say, fails without any output.
fn service_script(command: &[String], sddl: Option<&str>, log: &Path) -> String {
    let invocation = command
        .iter()
        .map(|arg| ps_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let mut script = format!(
        r#"$log = {log}
$output = & {invocation} 2>&1
$code = $LASTEXITCODE
$output | ForEach-Object {{ "$_" }} | Out-File -LiteralPath $log -Encoding utf8
if ($code -ne 0) {{ 'exit code {{0}} (0x{{0:X8}})' -f $code | Out-File -LiteralPath $log -Encoding utf8 -Append; exit {COMMAND_FAILED} }}
"#,
        log = ps_quote(&log.to_string_lossy()),
    );
    if let Some(sddl) = sddl {
        script.push_str(&format!(
            r#"$output = & sc.exe sdset {name} {sddl} 2>&1
$code = $LASTEXITCODE
$output | ForEach-Object {{ "$_" }} | Out-File -LiteralPath $log -Encoding utf8 -Append
if ($code -ne 0) {{ 'exit code {{0}} (0x{{0:X8}})' -f $code | Out-File -LiteralPath $log -Encoding utf8 -Append; exit {PERMISSIONS_FAILED} }}
"#,
            name = ps_quote(SERVICE_NAME),
            sddl = ps_quote(sddl),
        ));
    }
    script.push_str("exit 0\n");
    script
}

/// Run a service script elevated, reporting failures with the output
/// it recorded. `name` names the command in errors.
fn run_service_script(
    paths: &Paths,
    name: &str,
    command: &[String],
    sddl: Option<&str>,
) -> Result<()> {
    let log = paths.suricata_run_dir().join("service.log");
    ensure_dir(&paths.suricata_run_dir())?;
    let _ = std::fs::remove_file(&log);
    let code = powershell_elevated(&service_script(command, sddl, &log))?;
    let output = std::fs::read_to_string(&log).unwrap_or_default();
    let output = output.trim_start_matches('\u{feff}').trim();
    match code {
        0 => Ok(()),
        COMMAND_FAILED => bail!("{name} failed:\n{output}"),
        PERMISSIONS_FAILED => bail!("Failed to grant control of the Suricata service:\n{output}"),
        code => bail!("The elevated service script failed with exit code {code}"),
    }
}

/// Explain why Windows is about to ask for administrator approval and
/// wait for the user, so the prompt isn't a surprise. Without a
/// terminal there's no one to wait for, and Windows asks directly.
fn confirm_approval(reason: &str) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        info!("Windows will ask for administrator approval to register the Suricata service");
        return Ok(());
    }
    println!("\n{reason}\n\n{APPROVAL_NOTE}\n");
    let answer = inquire::Text::new("Press ENTER to continue, or ESC to cancel:").prompt();
    if crate::prompt::skippable(answer)?.is_none() {
        bail!("Suricata service registration canceled");
    }
    info!("Waiting for administrator approval");
    Ok(())
}

/// Register the Suricata service to run `command`, or update the
/// registration when its command differs or this user can't control
/// it. Changing the registration needs administrator approval, so
/// Windows prompts for it.
pub(super) fn register(paths: &Paths, command: &Command) -> Result<()> {
    let exe = Path::new(command.get_program());
    let args = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if !path_is_same_or_descendant(exe, &paths.suricata_install_dir()) {
        bail!(
            "Suricata runs as a service only from the EveCtl installation in {}. Run 'evectl install' first.",
            paths.suricata_install_dir().display()
        );
    }

    let (flag, reason) = match open(SERVICE_QUERY_CONFIG)? {
        None => ("--service-install", INSTALL_REASON),
        Some(service) => {
            let registered = service.command_line()?;
            if !is_managed_command(paths, &registered) {
                bail!(
                    "Another Suricata service is registered, running {}. Remove it with 'suricata --service-remove' to run EveCtl's Suricata.",
                    registered.first().map(String::as_str).unwrap_or_default()
                );
            }
            let matches = command_matches(&registered, exe, &args);
            if matches && user_has_access()? {
                return Ok(());
            }
            let reason = if matches {
                ACCESS_REASON
            } else {
                UPDATE_REASON
            };
            ("--service-change-params", reason)
        }
    };

    // Taken first so a failure doesn't come after the explanation.
    let sddl = service_sddl(&current_user_sid()?);
    confirm_approval(reason)?;
    let mut service_command = vec![exe.to_string_lossy().into_owned(), flag.to_string()];
    service_command.extend(args);
    run_service_script(
        paths,
        &format!("suricata {flag}"),
        &service_command,
        Some(&sddl),
    )
    .context("Failed to register the Suricata service")
}

/// Remove EveCtl's Suricata service registration, which must be
/// stopped. Suricata has its own command for this, but it needs
/// Npcap's DLLs to even start, and an uninstall may find Npcap
/// already gone, so the service manager's tool does it instead.
pub(super) fn unregister(paths: &Paths) -> Result<()> {
    let Some(service) = open(SERVICE_QUERY_CONFIG)? else {
        return Ok(());
    };
    let registered = service.command_line()?;
    if !is_managed_command(paths, &registered) {
        return Ok(());
    }
    let command = ["sc.exe", "delete", SERVICE_NAME]
        .map(String::from)
        .to_vec();
    info!("Removing the Suricata service, Windows will ask for administrator approval");
    run_service_script(paths, "sc.exe delete", &command, None)
        .context("Failed to remove the Suricata service")
}

/// Start EveCtl's Suricata service, returning its process ID once it
/// reports running.
pub(super) fn start(paths: &Paths) -> Result<u32> {
    let service = open_managed(paths, SERVICE_START | SERVICE_QUERY_STATUS)?
        .ok_or_else(|| anyhow!("The Suricata service is not registered"))?;
    unsafe { StartServiceW(service.handle.0, None) }
        .context("Failed to start the Suricata service")?;
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        let status = service.status()?;
        match status.dwCurrentState {
            SERVICE_RUNNING => return Ok(status.dwProcessId),
            SERVICE_STOPPED => bail!(
                "The Suricata service stopped during startup (exit code {})",
                status.dwWin32ExitCode
            ),
            _ if Instant::now() >= deadline => bail!(
                "The Suricata service did not start within {} seconds",
                START_TIMEOUT.as_secs()
            ),
            _ => std::thread::sleep(POLL_INTERVAL),
        }
    }
}

/// Stop EveCtl's Suricata service and wait for its process to exit,
/// so another Suricata can start right away.
pub(super) fn stop(paths: &Paths) -> Result<()> {
    let Some(service) = open_managed(paths, SERVICE_STOP | SERVICE_QUERY_STATUS)? else {
        return Ok(());
    };
    let deadline = Instant::now() + STOP_TIMEOUT;
    let mut pid = None;
    loop {
        let status = service.status()?;
        if status.dwProcessId != 0 {
            pid = Some(status.dwProcessId);
        }
        let state = status.dwCurrentState;
        if state == SERVICE_STOPPED {
            break;
        }
        // A stop can't be sent while the service is starting or
        // already stopping.
        if state != SERVICE_START_PENDING && state != SERVICE_STOP_PENDING {
            let mut status = SERVICE_STATUS::default();
            match unsafe { ControlService(service.handle.0, SERVICE_CONTROL_STOP, &mut status) } {
                Ok(()) => {}
                Err(err) if is_error(&err, ERROR_SERVICE_NOT_ACTIVE) => break,
                Err(err) => return Err(err).context("Failed to stop the Suricata service"),
            }
        }
        if Instant::now() >= deadline {
            bail!(
                "The Suricata service did not stop within {} seconds",
                STOP_TIMEOUT.as_secs()
            );
        }
        std::thread::sleep(POLL_INTERVAL);
    }

    // Suricata reports stopped just before its process exits.
    if let Some(pid) = pid {
        let deadline = Instant::now() + EXIT_TIMEOUT;
        while is_pid_running(pid) {
            if Instant::now() >= deadline {
                bail!("The Suricata service stopped, but process {pid} did not exit");
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
    Ok(())
}

/// Send a control to EveCtl's running Suricata service. Returns false
/// if the installed Suricata doesn't handle it.
pub(super) fn control(paths: &Paths, control: Control) -> Result<bool> {
    let service = open_managed(paths, SERVICE_USER_DEFINED_CONTROL)?
        .ok_or_else(|| anyhow!("The Suricata service is not registered"))?;
    let mut status = SERVICE_STATUS::default();
    match unsafe { ControlService(service.handle.0, control.code(), &mut status) } {
        Ok(()) => Ok(true),
        Err(err)
            if is_error(&err, ERROR_CALL_NOT_IMPLEMENTED)
                || is_error(&err, ERROR_INVALID_SERVICE_CONTROL) =>
        {
            Ok(false)
        }
        Err(err) => {
            Err(err).with_context(|| format!("Failed to ask the Suricata service to {control}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn command_lines_split_like_windows_programs() {
        assert_eq!(
            split_command_line(
                r#""C:\Program Files\Suricata\suricata.exe" -c C:\x.yaml --set a=b"#
            )
            .unwrap(),
            args(&[
                r"C:\Program Files\Suricata\suricata.exe",
                "-c",
                r"C:\x.yaml",
                "--set",
                "a=b"
            ])
        );
    }

    #[test]
    fn registered_commands_match_with_or_without_quoting() {
        let exe = Path::new(r"C:\evectl\suricata\install\suricata.exe");
        let wanted = args(&["-l", r"C:\Users\Jane Doe\log", "not port 22"]);

        // Suricata joins the arguments unquoted, so they come back split.
        let unquoted = split_command_line(
            r#""C:\evectl\suricata\install\suricata.exe" -l C:\Users\Jane Doe\log not port 22"#,
        )
        .unwrap();
        assert!(command_matches(&unquoted, exe, &wanted));
        let quoted = split_command_line(
            r#""C:\EveCtl\Suricata\Install\suricata.exe" -l "C:\Users\Jane Doe\log" "not port 22""#,
        )
        .unwrap();
        assert!(command_matches(&quoted, exe, &wanted));

        assert!(!command_matches(&quoted, exe, &args(&["-l", r"C:\other"])));
        let other_exe = Path::new(r"C:\Program Files\Suricata\suricata.exe");
        assert!(!command_matches(&quoted, other_exe, &wanted));
        assert!(!command_matches(&[], exe, &wanted));
    }

    #[test]
    fn only_evectl_installations_are_managed() {
        let paths = Paths::new(PathBuf::from(r"C:\evectl"));
        assert!(is_managed_command(
            &paths,
            &args(&[r"c:\EVECTL\suricata\install\suricata.exe", "-c", "x"])
        ));
        assert!(!is_managed_command(
            &paths,
            &args(&[r"C:\Program Files\Suricata\suricata.exe"])
        ));
        assert!(!is_managed_command(&paths, &[]));
    }

    #[test]
    fn user_is_granted_service_control() {
        let sddl = service_sddl("S-1-5-21-1-2-3-1001");
        assert!(sddl.starts_with("D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)"));
        assert!(sddl.contains("(A;;CCLCSWRPWPDTLOCRRC;;;S-1-5-21-1-2-3-1001)S:"));
        // Other users can't send controls, as Suricata's install sets.
        assert!(sddl.contains("(A;;CCLCSWLORC;;;IU)(A;;CCLCSWLORC;;;SU)"));
    }

    #[test]
    fn service_script_quotes_arguments_and_reports_each_step() {
        let script = service_script(
            &args(&[
                r"C:\Users\O'Brien\suricata.exe",
                "--service-install",
                "-l",
                "a b",
            ]),
            Some("D:(A;;RP;;;SY)"),
            Path::new(r"C:\run\service.log"),
        );
        assert!(script.starts_with("$log = 'C:\\run\\service.log'\n"));
        assert!(script.contains(
            r"$output = & 'C:\Users\O''Brien\suricata.exe' '--service-install' '-l' 'a b' 2>&1"
        ));
        assert!(script.contains(&format!(
            "'exit code {{0}} (0x{{0:X8}})' -f $code | Out-File -LiteralPath $log -Encoding utf8 -Append; exit {COMMAND_FAILED}"
        )));
        assert!(script.contains("& sc.exe sdset 'Suricata' 'D:(A;;RP;;;SY)' 2>&1"));
        assert!(script.contains(&format!("exit {PERMISSIONS_FAILED}")));
        assert!(script.ends_with("exit 0\n"));

        let script = service_script(
            &args(&["sc.exe", "delete", "Suricata"]),
            None,
            Path::new(r"C:\run\service.log"),
        );
        assert!(script.contains("$output = & 'sc.exe' 'delete' 'Suricata' 2>&1"));
        assert!(!script.contains("sdset"));
    }

    #[test]
    fn control_codes_are_user_defined() {
        assert!((128..=255).contains(&Control::ReloadRules.code()));
    }

    #[test]
    fn queries_installed_services() {
        // The event log service is present and running on every system.
        let service = open_service("EventLog", SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)
            .unwrap()
            .unwrap();
        assert_eq!(service.status().unwrap().dwCurrentState, SERVICE_RUNNING);
        let command = service.command_line().unwrap();
        assert!(command[0].to_ascii_lowercase().ends_with("svchost.exe"));

        assert!(
            open_service("evectl-no-such-service", SERVICE_QUERY_STATUS)
                .unwrap()
                .is_none()
        );
    }
}
