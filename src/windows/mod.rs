// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

#[cfg(windows)]
mod imp {
    use crate::prelude::*;
    use clap::{Parser, Subcommand};
    use indicatif::{ProgressBar, ProgressStyle};
    use serde::{Deserialize, Serialize};
    use std::io::{BufRead, BufReader, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use suricasta_rules::cli as suricasta_cli;
    use suricasta_rules::paths::PathProvider;

    const NPCAP_VERSION: &str = "1.87";
    const SURICATA_VERSION: &str = "8.0.3-1";
    const SURICATA_SYSTEM_EXE_PATHS: [&str; 2] = [
        r"C:\Program Files\Suricata\suricata.exe",
        r"C:\Program Files (x86)\Suricata\suricata.exe",
    ];
    const SURICATA_VERSION_MARKER: &str = ".evectl-suricata-version";
    const EVEBOX_VERSION: &str = "0.23.0";
    const EVEBOX_VERSION_MARKER: &str = ".evectl-evebox-version";
    const EVEBOX_URL: &str =
        "https://evebox.org/files/release/0.23.0/evebox-0.23.0-windows-x64.zip";
    const STATUS_CONTROL_C_EXIT: i32 = -1073741510;
    const ROLE_SURICATA: &str = "suricata";
    const ROLE_EVEBOX: &str = "evebox";
    const EVEBOX_HOST: &str = "127.0.0.1";
    const EVEBOX_PORT: &str = "5636";
    const EVEBOX_ACCESS_URL: &str = "http://127.0.0.1:5636";
    const SURICATA_READY_TIMEOUT: Duration = Duration::from_secs(5);
    const EVEBOX_STARTUP_GRACE_PERIOD: Duration = Duration::from_millis(750);
    const PROCESS_STOP_TIMEOUT: Duration = Duration::from_secs(5);

    static CTRL_C_RECEIVED: AtomicBool = AtomicBool::new(false);
    static CTRL_C_HANDLER_SETUP: OnceLock<Result<(), String>> = OnceLock::new();

    #[derive(Debug, Serialize, Deserialize, Clone)]
    struct RuntimeMetadata {
        pid: u32,
        role: String,
        exe_path: String,
        argv: Vec<String>,
        started_at: u64,
        stdout_path: Option<String>,
        stderr_path: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct NamedProcessInfo {
        #[serde(rename = "Id")]
        id: u32,
        #[serde(rename = "ProcessName")]
        process_name: Option<String>,
        #[serde(rename = "Path")]
        path: Option<String>,
    }

    #[derive(Debug, Default, Clone, Copy)]
    struct UpgradePlan {
        npcap: bool,
        suricata: bool,
        evebox: bool,
        evectl: bool,
    }

    impl UpgradePlan {
        fn any(self) -> bool {
            self.any_components() || self.evectl
        }

        fn any_components(self) -> bool {
            self.npcap || self.suricata || self.evebox
        }
    }

    #[derive(Debug, Default, Clone)]
    struct RestartPlan {
        suricata_running: bool,
        suricata_guid: Option<String>,
        evebox_running: bool,
    }

    impl RestartPlan {
        fn any(&self) -> bool {
            self.suricata_running || self.evebox_running
        }
    }

    #[derive(Parser, Debug, Clone)]
    pub(crate) struct Args {
        #[command(subcommand)]
        pub(crate) command: Commands,
    }

    #[derive(Subcommand, Debug, Clone)]
    pub(crate) enum Commands {
        /// Display project directories for config, rules, and logs.
        Info,

        /// Install Npcap (interactive), Suricata, and optionally EveBox.
        Install {
            /// Install EveBox without prompting.
            #[arg(long, conflicts_with = "no_evebox")]
            evebox: bool,

            /// Skip EveBox installation and do not prompt.
            #[arg(long)]
            no_evebox: bool,
        },

        /// Upgrade bundled Windows components when newer, and report when an EveCtl update is available.
        #[command(alias = "upgrade-suricata")]
        Upgrade,

        /// Uninstall EveBox (if installed), then Suricata, then Npcap.
        Uninstall,

        /// List network interfaces with their IP addresses and GUIDs
        ListInterfaces,

        /// Start the Windows-managed Suricata and EveBox stack.
        Start {
            /// Launch the stack in the background as detached processes.
            #[arg(long)]
            background: bool,

            /// Network interface GUID to listen on. If omitted, the saved config is used.
            #[arg(long)]
            guid: Option<String>,
        },

        /// Stop the Windows-managed Suricata and EveBox stack.
        Stop,

        /// Manage evectl configuration.
        Config {
            #[command(subcommand)]
            command: ConfigCommands,
        },

        /// Manage Suricata rules and rulesets
        Rules {
            #[command(subcommand)]
            command: RulesCommands,
        },
    }

    #[derive(Subcommand, Debug, Clone)]
    pub(crate) enum ConfigCommands {
        /// Select and save the default interface GUID used by start.
        SetInterface,
    }

    #[derive(Subcommand, Debug, Clone)]
    pub(crate) enum RulesCommands {
        /// Update Suricata rules using built-in Windows-compatible updater
        Update {
            /// Force download even if cache is recent
            #[arg(short = 'f', long)]
            force: bool,

            /// Reduce output to warnings/errors
            #[arg(short = 'q', long)]
            quiet: bool,
        },

        /// Refresh Suricata ruleset index
        UpdateSources,

        /// Enable a Suricata ruleset (for example: et/open). If omitted, an interactive selector is shown.
        EnableRuleset {
            #[arg(value_name = "RULESET")]
            name: Option<String>,
        },

        /// Disable a Suricata ruleset
        DisableRuleset {
            #[arg(value_name = "RULESET")]
            name: String,
        },

        /// List currently enabled Suricata rulesets
        ListEnabledRulesets,
    }

    impl Args {
        pub(crate) fn from_command(command: Commands) -> Self {
            Self { command }
        }
    }

    pub(crate) fn main(args: Args) -> Result<()> {
        match args.command {
            Commands::Info => project_info(),
            Commands::Install { evebox, no_evebox } => install(evebox, no_evebox),
            Commands::Upgrade => upgrade_windows_components(),
            Commands::Uninstall => uninstall_windows_components(),
            Commands::ListInterfaces => list_interfaces(),
            Commands::Start { background, guid } => start_stack(background, guid),
            Commands::Stop => stop_stack(),
            Commands::Config { command } => match command {
                ConfigCommands::SetInterface => config_set_interface(),
            },
            Commands::Rules { command } => match command {
                RulesCommands::Update { force, quiet } => update_rules(force, quiet),
                RulesCommands::UpdateSources => update_sources(),
                RulesCommands::EnableRuleset { name } => enable_ruleset(name.as_deref()),
                RulesCommands::DisableRuleset { name } => disable_ruleset(&name),
                RulesCommands::ListEnabledRulesets => list_enabled_rulesets(),
            },
        }
    }
    struct EvectlWindowsPaths {
        sources_dir: std::path::PathBuf,
        cache_dir: std::path::PathBuf,
        rules_dir: std::path::PathBuf,
    }

    impl PathProvider for EvectlWindowsPaths {
        fn sources_dir(&self) -> std::path::PathBuf {
            self.sources_dir.clone()
        }

        fn cache_dir(&self) -> std::path::PathBuf {
            self.cache_dir.clone()
        }

        fn rules_dir(&self) -> std::path::PathBuf {
            self.rules_dir.clone()
        }
    }

    #[cfg(windows)]
    fn get_suricasta_paths() -> Result<EvectlWindowsPaths> {
        let lib_dir = get_suricata_data_dir()?.join("lib");
        Ok(EvectlWindowsPaths {
            sources_dir: lib_dir.join("update").join("sources"),
            cache_dir: lib_dir.join("update").join("cache"),
            rules_dir: lib_dir.join("rules"),
        })
    }

    #[cfg(windows)]
    fn with_path_provider<T>(f: impl FnOnce(&dyn PathProvider) -> Result<T>) -> Result<T> {
        let paths = get_suricasta_paths()?;
        f(&paths)
    }

    #[cfg(windows)]
    fn update_rules(force: bool, quiet: bool) -> Result<()> {
        let suricata_version = detect_suricata_version_for_rules_update();

        if let Some(version) = &suricata_version {
            info!("Selecting rules for Suricata version {}", version);
        } else {
            warn!(
                "Could not determine Suricata version for rules update; using suricasta-rules default"
            );
        }

        with_path_provider(|paths| {
            suricasta_cli::update_rules_with_suricata_version(
                paths,
                force,
                quiet,
                suricata_version.as_deref(),
            )
        })
    }

    #[cfg(windows)]
    fn detect_suricata_version_for_rules_update() -> Option<String> {
        if let Some(version) = get_suricata_runtime_version() {
            return Some(version);
        }

        match get_suricata_installed_version() {
            Ok(Some(version)) => normalize_suricata_version(&version)
                .or_else(|| normalize_suricata_version(suricata_version_for_comparison())),
            Ok(None) => normalize_suricata_version(suricata_version_for_comparison()),
            Err(err) => {
                warn!(
                    "Failed to determine installed Suricata version for rules update: {}",
                    err
                );
                normalize_suricata_version(suricata_version_for_comparison())
            }
        }
    }

    #[cfg(windows)]
    fn get_suricata_runtime_version() -> Option<String> {
        use std::process::Command;

        let suricata_path = find_suricata_executable()?;
        let output = Command::new(&suricata_path).arg("-V").output().ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(version) = parse_suricata_version_from_text(&stdout) {
            return Some(version);
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        parse_suricata_version_from_text(&stderr)
    }

    #[cfg(windows)]
    fn parse_suricata_version_from_text(text: &str) -> Option<String> {
        use std::sync::LazyLock;

        static VERSION_HINT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(
                r"(?i)\b(?:suricata\s+)?version\s+([0-9]+(?:\.[0-9]+){1,3}(?:-[0-9]+)?)\b",
            )
            .expect("hardcoded regex is valid")
        });
        static SEMVER_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"\b([0-9]+(?:\.[0-9]+){1,3}(?:-[0-9]+)?)\b")
                .expect("hardcoded regex is valid")
        });

        if let Some(caps) = VERSION_HINT_RE.captures(text)
            && let Some(candidate) = caps.get(1)
            && let Some(version) = normalize_suricata_version(candidate.as_str())
        {
            return Some(version);
        }

        for caps in SEMVER_RE.captures_iter(text) {
            if let Some(candidate) = caps.get(1)
                && let Some(version) = normalize_suricata_version(candidate.as_str())
            {
                return Some(version);
            }
        }

        None
    }

    #[cfg(windows)]
    fn normalize_suricata_version(version: &str) -> Option<String> {
        let candidate = version
            .trim()
            .trim_matches(['"', '\''])
            .split_whitespace()
            .next()
            .unwrap_or("")
            .split('-')
            .next()
            .unwrap_or("")
            .trim_matches(|ch: char| !ch.is_ascii_digit() && ch != '.');

        if parse_version_parts(candidate).is_some() {
            Some(candidate.to_string())
        } else {
            None
        }
    }

    #[cfg(windows)]
    fn update_sources() -> Result<()> {
        with_path_provider(suricasta_cli::update_sources)
    }

    #[cfg(windows)]
    fn enable_ruleset(name: Option<&str>) -> Result<()> {
        with_path_provider(|paths| {
            let command = suricasta_cli::Commands::EnableRuleset {
                name: name.map(str::to_string),
            };
            suricasta_cli::run_with_path_provider(&command, paths)
        })
    }

    #[cfg(windows)]
    fn disable_ruleset(name: &str) -> Result<()> {
        with_path_provider(|paths| suricasta_cli::disable_ruleset(paths, name))
    }

    #[cfg(windows)]
    fn list_enabled_rulesets() -> Result<()> {
        let rulesets = with_path_provider(suricasta_cli::enabled_rulesets)?;

        if rulesets.is_empty() {
            println!("No Suricata rulesets enabled");
            return Ok(());
        }

        println!("Enabled Suricata rulesets:");
        for ruleset in rulesets {
            println!("- {}", ruleset);
        }

        Ok(())
    }

    #[cfg(windows)]
    fn write_suricata_rules_include_stub() -> Result<std::path::PathBuf> {
        let paths = get_suricasta_paths()?;
        std::fs::create_dir_all(&paths.rules_dir).context(format!(
            "Failed to create Suricata rules directory {}",
            paths.rules_dir.display()
        ))?;

        let run_dir = get_suricata_run_dir()?;
        std::fs::create_dir_all(&run_dir).context(format!(
            "Failed to create Suricata runtime directory {}",
            run_dir.display()
        ))?;

        let include_path = run_dir.join("rules-include.yaml");
        let rules_dir = paths.rules_dir.to_string_lossy().replace('\'', "''");

        let stub = format!(
            "%YAML 1.1\n---\ndefault-rule-path: '{}'\nrule-files:\n  - suricata.rules\n",
            rules_dir
        );

        std::fs::write(&include_path, stub).context(format!(
            "Failed to write Suricata rules include file {}",
            include_path.display()
        ))?;

        Ok(include_path)
    }

    #[cfg(windows)]
    fn ensure_dir(path: &Path) -> Result<()> {
        std::fs::create_dir_all(path)
            .context(format!("Failed to create directory {}", path.display()))
    }

    #[cfg(windows)]
    fn write_pid(path: &Path, pid: u32) -> Result<()> {
        std::fs::write(path, format!("{pid}\n"))
            .context(format!("Failed to write PID file {}", path.display()))
    }

    #[cfg(windows)]
    fn read_pid(path: &Path) -> Result<Option<u32>> {
        if !path.exists() {
            return Ok(None);
        }

        let raw = std::fs::read_to_string(path)
            .context(format!("Failed to read PID file {}", path.display()))?;
        let pid = raw
            .trim()
            .parse::<u32>()
            .context(format!("Failed to parse PID file {}", path.display()))?;
        Ok(Some(pid))
    }

    #[cfg(windows)]
    fn remove_file_if_exists(path: &Path) -> Result<()> {
        if path.exists() {
            std::fs::remove_file(path)
                .context(format!("Failed to remove file {}", path.display()))?;
        }
        Ok(())
    }

    #[cfg(windows)]
    fn write_runtime_metadata(path: &Path, metadata: &RuntimeMetadata) -> Result<()> {
        let contents = serde_json::to_string_pretty(metadata)?;
        std::fs::write(path, contents).context(format!(
            "Failed to write runtime metadata {}",
            path.display()
        ))
    }

    #[cfg(windows)]
    fn read_runtime_metadata(path: &Path) -> Result<Option<RuntimeMetadata>> {
        if !path.exists() {
            return Ok(None);
        }

        let contents = std::fs::read_to_string(path).context(format!(
            "Failed to read runtime metadata {}",
            path.display()
        ))?;
        let metadata = serde_json::from_str(&contents).context(format!(
            "Failed to parse runtime metadata {}",
            path.display()
        ))?;
        Ok(Some(metadata))
    }

    #[cfg(windows)]
    fn normalize_path_for_compare(path: &Path) -> String {
        path.to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase()
    }

    #[cfg(windows)]
    fn command_argv(command: &Command) -> Vec<String> {
        let mut argv = vec![command.get_program().to_string_lossy().to_string()];
        argv.extend(
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().to_string()),
        );
        argv
    }

    #[cfg(windows)]
    fn build_runtime_metadata(
        role: &str,
        command: &Command,
        pid: u32,
        stdout_path: Option<&Path>,
        stderr_path: Option<&Path>,
    ) -> Result<RuntimeMetadata> {
        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("System clock is before UNIX_EPOCH")?
            .as_secs();

        Ok(RuntimeMetadata {
            pid,
            role: role.to_string(),
            exe_path: command.get_program().to_string_lossy().to_string(),
            argv: command_argv(command),
            started_at,
            stdout_path: stdout_path.map(|path| path.to_string_lossy().to_string()),
            stderr_path: stderr_path.map(|path| path.to_string_lossy().to_string()),
        })
    }

    #[cfg(windows)]
    fn powershell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }

    #[cfg(windows)]
    fn spawn_detached(command: &Command) -> Result<u32> {
        let program = powershell_quote(&command.get_program().to_string_lossy());
        let working_dir = command
            .get_current_dir()
            .map(|path| powershell_quote(&path.to_string_lossy()))
            .unwrap_or_else(|| "'.'".to_string());
        let argument_list = command
            .get_args()
            .map(|arg| powershell_quote(&arg.to_string_lossy()))
            .collect::<Vec<_>>()
            .join(", ");

        let script = format!(
            "$argList = @({argument_list}); \
             $p = Start-Process -FilePath {program} -WorkingDirectory {working_dir} \
             -ArgumentList $argList -WindowStyle Hidden -PassThru; \
             Write-Output $p.Id"
        );

        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output()
            .context("Failed to spawn detached process")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to spawn detached process: {}", stderr.trim());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .trim()
            .parse::<u32>()
            .context("Failed to parse detached process PID")
    }

    #[cfg(windows)]
    fn count_named_processes(process_name: &str) -> Result<usize> {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "$p = @(Get-Process -Name '{}' -ErrorAction SilentlyContinue); Write-Output $p.Count",
                    process_name.replace('\'', "''")
                ),
            ])
            .output()
            .context("Failed to query process list")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to query process list: {}", stderr.trim());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .trim()
            .parse::<usize>()
            .context("Failed to parse process count")
    }

    #[cfg(windows)]
    fn list_named_processes(process_name: &str) -> Result<Vec<NamedProcessInfo>> {
        let script = format!(
            "$procs = @(Get-Process -Name '{}' -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, Path); ConvertTo-Json -InputObject @($procs) -Compress",
            process_name.replace('\'', "''")
        );

        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output()
            .context("Failed to query process details")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to query process details: {}", stderr.trim());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stdout = stdout.trim();
        if stdout.is_empty() {
            return Ok(vec![]);
        }

        serde_json::from_str(stdout).context("Failed to parse process details")
    }

    #[cfg(windows)]
    fn is_pid_running(pid: u32) -> bool {
        Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "$p = Get-Process -Id {} -ErrorAction SilentlyContinue; if ($null -ne $p) {{ exit 0 }} else {{ exit 1 }}",
                    pid
                ),
            ])
            .status()
            .is_ok_and(|status| status.success())
    }

    #[cfg(windows)]
    fn get_process_exe_path(pid: u32) -> Result<Option<PathBuf>> {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "$p = Get-Process -Id {} -ErrorAction SilentlyContinue; if ($null -ne $p -and $p.Path) {{ Write-Output $p.Path }}",
                    pid
                ),
            ])
            .output()
            .context("Failed to inspect process executable path")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "Failed to inspect process executable path: {}",
                stderr.trim()
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let path = stdout.trim();
        if path.is_empty() {
            Ok(None)
        } else {
            Ok(Some(PathBuf::from(path)))
        }
    }

    #[cfg(windows)]
    fn process_matches_exe(pid: u32, exe_path: &Path) -> Result<bool> {
        let running_path = match get_process_exe_path(pid)? {
            Some(path) => path,
            None => return Ok(false),
        };

        Ok(normalize_path_for_compare(&running_path) == normalize_path_for_compare(exe_path))
    }

    #[cfg(windows)]
    fn path_is_same_or_descendant(path: &Path, dir: &Path) -> bool {
        let path = normalize_path_for_compare(path);
        let dir = normalize_path_for_compare(dir);

        if path == dir {
            return true;
        }

        let mut prefix = dir;
        if !prefix.ends_with('\\') {
            prefix.push('\\');
        }

        path.starts_with(&prefix)
    }

    #[cfg(windows)]
    fn process_matches_dir(
        process: &NamedProcessInfo,
        dir: &Path,
        exact_exe_path: Option<&Path>,
    ) -> Result<bool> {
        if let Some(path) = process.path.as_deref() {
            return Ok(path_is_same_or_descendant(Path::new(path), dir));
        }

        if let Some(exe_path) = exact_exe_path {
            return process_matches_exe(process.id, exe_path);
        }

        Ok(false)
    }

    #[cfg(windows)]
    fn format_process_info(process: &NamedProcessInfo) -> String {
        match process.path.as_deref() {
            Some(path) if !path.is_empty() => format!(
                "PID {} ({}) [{}]",
                process.id,
                process.process_name.as_deref().unwrap_or("unknown"),
                path
            ),
            _ => format!(
                "PID {} ({})",
                process.id,
                process.process_name.as_deref().unwrap_or("unknown")
            ),
        }
    }

    #[cfg(windows)]
    fn log_processes_in_dir(
        process_name: &str,
        dir: &Path,
        exact_exe_path: Option<&Path>,
    ) -> Result<()> {
        let mut matches = vec![];

        for process in list_named_processes(process_name)? {
            if process_matches_dir(&process, dir, exact_exe_path)? {
                matches.push(format_process_info(&process));
            }
        }

        if matches.is_empty() {
            info!(
                "No {} processes were found running from {}",
                process_name,
                dir.display()
            );
        } else {
            warn!(
                "Detected {} process(es) running from {}:\n- {}",
                process_name,
                dir.display(),
                matches.join("\n- ")
            );
        }

        Ok(())
    }

    #[cfg(windows)]
    fn stop_named_processes_in_dir(
        process_name: &str,
        dir: &Path,
        exact_exe_path: Option<&Path>,
    ) -> Result<()> {
        let mut matched_pids = vec![];

        for process in list_named_processes(process_name)? {
            if !process_matches_dir(&process, dir, exact_exe_path)? {
                continue;
            }

            info!(
                "Stopping {} process {} from managed path {}",
                process_name,
                format_process_info(&process),
                dir.display()
            );
            stop_pid(process.id)?;
            matched_pids.push(process.id);
        }

        if matched_pids.is_empty() {
            return Ok(());
        }

        let mut remaining = vec![];
        for process in list_named_processes(process_name)? {
            if process_matches_dir(&process, dir, exact_exe_path)? {
                remaining.push(format_process_info(&process));
            }
        }

        if remaining.is_empty() {
            Ok(())
        } else {
            bail!(
                "{} processes are still running from {}:\n- {}",
                process_name,
                dir.display(),
                remaining.join("\n- ")
            )
        }
    }

    #[cfg(windows)]
    fn stop_pid(pid: u32) -> Result<()> {
        let status = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .status()
            .context(format!("Failed to stop process {}", pid))?;

        if !status.success() {
            bail!("taskkill failed for PID {}", pid);
        }

        let started = std::time::Instant::now();
        while started.elapsed() < PROCESS_STOP_TIMEOUT {
            if !is_pid_running(pid) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        bail!("Process {} did not exit after taskkill", pid)
    }

    #[cfg(windows)]
    fn role_paths(role: &str) -> Result<(PathBuf, PathBuf)> {
        match role {
            ROLE_SURICATA => Ok((get_suricata_pid_path()?, get_suricata_runtime_path()?)),
            ROLE_EVEBOX => Ok((get_evebox_pid_path()?, get_evebox_runtime_path()?)),
            _ => bail!("Unknown runtime role {}", role),
        }
    }

    #[cfg(windows)]
    fn cleanup_runtime_files(role: &str) -> Result<()> {
        let (pid_path, runtime_path) = role_paths(role)?;
        remove_file_if_exists(&pid_path)?;
        remove_file_if_exists(&runtime_path)?;
        Ok(())
    }

    #[cfg(windows)]
    fn managed_process_is_running(role: &str) -> Result<bool> {
        let (pid_path, runtime_path) = role_paths(role)?;
        let metadata = match read_runtime_metadata(&runtime_path)? {
            Some(metadata) => metadata,
            None => {
                if pid_path.exists() {
                    remove_file_if_exists(&pid_path)?;
                }
                return Ok(false);
            }
        };

        if metadata.role != role {
            warn!(
                "Runtime metadata {} belongs to role {} instead of {}. Cleaning it up.",
                runtime_path.display(),
                metadata.role,
                role
            );
            cleanup_runtime_files(role)?;
            return Ok(false);
        }

        if !is_pid_running(metadata.pid) {
            cleanup_runtime_files(role)?;
            return Ok(false);
        }

        if !process_matches_exe(metadata.pid, Path::new(&metadata.exe_path))? {
            warn!(
                "PID {} for role {} no longer matches {}. Cleaning up stale state.",
                metadata.pid, role, metadata.exe_path
            );
            cleanup_runtime_files(role)?;
            return Ok(false);
        }

        if let Some(pid) = read_pid(&pid_path)?
            && pid != metadata.pid
        {
            warn!(
                "PID file {} disagrees with runtime metadata for role {}. Rewriting it.",
                pid_path.display(),
                role
            );
            write_pid(&pid_path, metadata.pid)?;
        }

        Ok(true)
    }

    #[cfg(windows)]
    fn stop_managed_process(role: &str) -> Result<()> {
        let (pid_path, runtime_path) = role_paths(role)?;
        let metadata = match read_runtime_metadata(&runtime_path)? {
            Some(metadata) => metadata,
            None => {
                remove_file_if_exists(&pid_path)?;
                return Ok(());
            }
        };

        if metadata.role != role {
            warn!(
                "Runtime metadata {} belongs to role {} instead of {}. Removing stale state.",
                runtime_path.display(),
                metadata.role,
                role
            );
            cleanup_runtime_files(role)?;
            return Ok(());
        }

        let pid_running = is_pid_running(metadata.pid);
        if pid_running && process_matches_exe(metadata.pid, Path::new(&metadata.exe_path))? {
            info!("Stopping {} process with PID {}", role, metadata.pid);
            stop_pid(metadata.pid)?;
        } else if pid_running {
            warn!(
                "Refusing to stop PID {} for role {} because it no longer matches {}",
                metadata.pid, role, metadata.exe_path
            );
        }

        cleanup_runtime_files(role)
    }

    #[cfg(windows)]
    fn prompt_for_interface_guid() -> Result<String> {
        let interfaces = get_windows_interfaces()?;
        if interfaces.is_empty() {
            bail!("No network interfaces found");
        }

        let mut selections = vec![];
        for interface in &interfaces {
            let display_name = if interface.ip_address.is_empty() {
                format!("{} (no IP)", interface.name)
            } else {
                format!("{} ({})", interface.name, interface.ip_address)
            };
            selections.push((interface.guid.clone(), display_name));
        }

        let choices: Vec<String> = selections.iter().map(|(_, name)| name.clone()).collect();
        let selection =
            inquire::Select::new("Select network interface to listen on:", choices).prompt()?;

        selections
            .iter()
            .find(|(_, name)| name == &selection)
            .map(|(guid, _)| guid.clone())
            .ok_or_else(|| anyhow!("Failed to find GUID for selected interface"))
    }

    #[cfg(windows)]
    fn resolve_interface_guid(guid: Option<String>, allow_prompt: bool) -> Result<String> {
        if let Some(guid) = guid.as_deref().and_then(normalize_interface_guid) {
            return Ok(guid);
        }

        if let Some(guid) = get_configured_interface_guid()? {
            return Ok(guid);
        }

        if allow_prompt {
            prompt_for_interface_guid()
        } else {
            bail!(
                "No interface is configured. Use 'evectl config set-interface', pass --guid <GUID>, or run interactively to choose one."
            )
        }
    }

    #[cfg(windows)]
    fn config_set_interface() -> Result<()> {
        let guid = prompt_for_interface_guid()?;
        let config_path = set_configured_interface_guid(&guid)?;

        println!("Saved default interface GUID: {}", guid);
        println!("Config file: {}", config_path.display());

        Ok(())
    }

    #[cfg(windows)]
    fn project_info() -> Result<()> {
        let data_root = get_evectl_data_dir()?;

        let evectl_config = data_root.join("evectl.toml");
        let suricata_config_dir = data_root.join("suricata");
        let suricata_rules_dir = suricata_config_dir.join("lib").join("rules");
        let suricata_update_dir = suricata_config_dir.join("lib").join("update");
        let suricata_update_cache_dir = suricata_update_dir.join("cache");
        let suricata_install_dir = data_root.join("suricata").join("install");
        let suricata_log_dir = data_root.join("suricata").join("log");
        let suricata_run_dir = data_root.join("suricata").join("run");
        let evebox_data_dir = data_root.join("evebox");
        let evebox_run_dir = evebox_data_dir.join("run");
        let evebox_log_dir = evebox_data_dir.join("log");
        let evebox_exe = find_evebox_exe(&evebox_data_dir)?;
        let evectl_exe = std::env::current_exe().ok();

        println!("Windows path-based directories:");
        println!("  Data root:                 {}", data_root.display());
        if let Some(evectl_exe) = &evectl_exe {
            println!("  Current EveCtl binary:     {}", evectl_exe.display());
        } else {
            println!("  Current EveCtl binary:     <unknown>");
        }
        println!();

        println!("Config and rules paths in use:");
        println!("  EveCtl config file:        {}", evectl_config.display());
        match get_configured_interface_guid() {
            Ok(Some(guid)) => println!("  Configured interface GUID: {}", guid),
            Ok(None) => println!("  Configured interface GUID: <not set>"),
            Err(err) => println!("  Configured interface GUID: <error: {}>", err),
        }
        println!(
            "  Suricata config directory: {}",
            suricata_config_dir.display()
        );
        println!(
            "  Suricata rules directory:  {}",
            suricata_rules_dir.display()
        );
        println!(
            "  Rule update state:         {}",
            suricata_update_dir.display()
        );
        println!(
            "  Rule update cache:         {}",
            suricata_update_cache_dir.display()
        );
        println!();

        println!("Suricata paths in use:");
        println!(
            "  Suricata install dir:      {}",
            suricata_install_dir.display()
        );
        println!(
            "  Suricata logs:             {}",
            suricata_log_dir.display()
        );
        println!(
            "  Suricata runtime files:    {}",
            suricata_run_dir.display()
        );
        println!();

        println!("Other Windows data paths:");
        println!("  EveBox data directory:     {}", evebox_data_dir.display());
        println!("  EveBox runtime files:      {}", evebox_run_dir.display());
        println!("  EveBox logs:               {}", evebox_log_dir.display());
        if let Some(evebox_exe) = evebox_exe {
            println!("  Current EveBox binary:     {}", evebox_exe.display());
        } else {
            println!(
                "  Current EveBox binary:     {} (not installed)",
                evebox_data_dir.join("evebox.exe").display()
            );
        }

        Ok(())
    }

    #[cfg(windows)]
    fn download_file(url: &str, path: &std::path::Path, name: &str) -> Result<()> {
        use std::fs::File;
        use std::io::{Read, Write};

        info!("Downloading {} from {}", name, url);
        info!("Saving to {:?}", path);

        let mut response =
            reqwest::blocking::get(url).context(format!("Failed to download {}", name))?;

        if !response.status().is_success() {
            bail!("Failed to download {}: HTTP {}", name, response.status());
        }

        let total_size = response.content_length().unwrap_or(0);
        let mut file = File::create(path).context(format!("Failed to create file for {}", name))?;

        let pb = if total_size > 0 {
            let pb = ProgressBar::new(total_size);
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
                .progress_chars("#>-"));
            pb
        } else {
            ProgressBar::new_spinner()
        };

        let mut downloaded = 0u64;
        let mut buffer = [0; 8192];

        loop {
            let bytes_read = response.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            file.write_all(&buffer[..bytes_read])?;
            downloaded += bytes_read as u64;
            pb.set_position(downloaded);
        }

        pb.finish_with_message("Download complete");
        file.flush()?;
        drop(file);

        info!("Downloaded {} to {:?}", name, path);
        Ok(())
    }

    #[cfg(windows)]
    fn download_npcap() -> Result<()> {
        install_or_upgrade_npcap(false)
    }

    #[cfg(windows)]
    fn install_or_upgrade_npcap(upgrade: bool) -> Result<()> {
        let installed = is_npcap_installed();
        if installed && !upgrade {
            info!("Npcap is already installed on this system.");
            return Ok(());
        }

        if upgrade {
            if installed {
                info!("Upgrading Npcap to version {}...", NPCAP_VERSION);
            } else {
                info!(
                    "Npcap was not detected. Installing version {} instead...",
                    NPCAP_VERSION
                );
            }
        }

        let url = format!("https://npcap.com/dist/npcap-{}.exe", NPCAP_VERSION);
        let temp_dir = tempfile::tempdir()?;
        let exe_path = temp_dir.path().join(format!("npcap-{}.exe", NPCAP_VERSION));

        download_file(&url, &exe_path, "Npcap")?;

        info!("Launching Npcap installer...");

        #[cfg(windows)]
        {
            launch_windows_installer(&exe_path, "Npcap", false)?;
            wait_for_installer_completion()?;
        }

        #[cfg(not(windows))]
        {
            use std::process::Command;

            let status = Command::new(&exe_path)
                .spawn()
                .context("Failed to launch Npcap installer")?
                .wait()
                .context("Failed to wait for Npcap installer")?;

            if !status.success() {
                bail!("Npcap installer exited with status: {}", status);
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    fn launch_windows_installer(path: &std::path::Path, name: &str, elevated: bool) -> Result<()> {
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        use windows::core::PCWSTR;

        let path_str = path.to_string_lossy();
        let path_wide: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();

        let verb = if elevated { "runas" } else { "open" }
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();

        unsafe {
            let result = ShellExecuteW(
                None,
                PCWSTR(verb.as_ptr()),
                PCWSTR(path_wide.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            );

            if result.0 as usize <= 32 {
                bail!(
                    "Failed to launch {} installer. Error code: {:?}",
                    name,
                    result.0
                );
            }
        }

        info!("{} installer launched successfully", name);
        Ok(())
    }

    #[cfg(windows)]
    fn wait_for_installer_completion() -> Result<()> {
        use std::io::{self, Write};

        info!("Please complete the installation in the opened window.");
        print!("Press Enter when the installation is complete to continue...");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        Ok(())
    }

    #[cfg(windows)]
    fn get_evectl_data_dir() -> Result<std::path::PathBuf> {
        Ok(dirs::data_local_dir()
            .ok_or_else(|| anyhow!("Could not find local data directory"))?
            .join("evectl"))
    }

    #[cfg(windows)]
    fn get_evectl_config_path() -> Result<PathBuf> {
        Ok(get_evectl_data_dir()?.join("evectl.toml"))
    }

    #[cfg(windows)]
    fn load_evectl_config() -> Result<crate::config::Config> {
        let config_path = get_evectl_config_path()?;
        if config_path.exists() {
            crate::config::Config::from_file(&config_path)
        } else {
            Ok(crate::config::Config::default_with_filename(&config_path))
        }
    }

    #[cfg(windows)]
    fn normalize_interface_guid(value: &str) -> Option<String> {
        let value = value.trim();
        if value.is_empty() {
            return None;
        }

        let value = value
            .strip_prefix(r"\Device\NPF_")
            .or_else(|| value.strip_prefix(r"\device\npf_"))
            .unwrap_or(value)
            .trim_matches(['{', '}']);

        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    }

    #[cfg(windows)]
    fn get_configured_interface_guid() -> Result<Option<String>> {
        let config = load_evectl_config()?;
        Ok(config
            .suricata
            .interfaces
            .first()
            .and_then(|value| normalize_interface_guid(value)))
    }

    #[cfg(windows)]
    fn set_configured_interface_guid(guid: &str) -> Result<PathBuf> {
        let config_path = get_evectl_config_path()?;
        ensure_dir(&get_evectl_data_dir()?)?;

        let mut config = load_evectl_config()?;
        config.suricata.interfaces = vec![guid.to_string()];
        config.save()?;

        Ok(config_path)
    }

    #[cfg(windows)]
    fn get_suricata_data_dir() -> Result<std::path::PathBuf> {
        Ok(get_evectl_data_dir()?.join("suricata"))
    }

    #[cfg(windows)]
    fn get_suricata_run_dir() -> Result<PathBuf> {
        Ok(get_suricata_data_dir()?.join("run"))
    }

    #[cfg(windows)]
    fn get_suricata_log_dir() -> Result<PathBuf> {
        Ok(get_suricata_data_dir()?.join("log"))
    }

    #[cfg(windows)]
    fn get_suricata_install_dir() -> Result<std::path::PathBuf> {
        Ok(get_suricata_data_dir()?.join("install"))
    }

    #[cfg(windows)]
    fn get_suricata_exe_path() -> Result<std::path::PathBuf> {
        Ok(get_suricata_install_dir()?.join("suricata.exe"))
    }

    #[cfg(windows)]
    fn get_suricata_version_marker_path() -> Result<std::path::PathBuf> {
        Ok(get_suricata_install_dir()?.join(SURICATA_VERSION_MARKER))
    }

    #[cfg(windows)]
    fn get_suricata_pid_path() -> Result<PathBuf> {
        Ok(get_suricata_run_dir()?.join("suricata.pid"))
    }

    #[cfg(windows)]
    fn get_suricata_runtime_path() -> Result<PathBuf> {
        Ok(get_suricata_run_dir()?.join("suricata.runtime.json"))
    }

    #[cfg(windows)]
    fn get_suricata_stdout_log_path() -> Result<PathBuf> {
        Ok(get_suricata_log_dir()?.join("suricata-stdout.log"))
    }

    #[cfg(windows)]
    fn get_suricata_stderr_log_path() -> Result<PathBuf> {
        Ok(get_suricata_log_dir()?.join("suricata-stderr.log"))
    }

    #[cfg(windows)]
    fn get_suricata_eve_json_path() -> Result<PathBuf> {
        Ok(get_suricata_log_dir()?.join("eve.json"))
    }

    #[cfg(windows)]
    fn find_suricata_executable() -> Option<std::path::PathBuf> {
        use std::process::Command;

        if let Ok(path) = get_suricata_exe_path()
            && path.exists()
        {
            return Some(path);
        }

        for path in &SURICATA_SYSTEM_EXE_PATHS {
            let path = std::path::PathBuf::from(path);
            if path.exists() {
                return Some(path);
            }
        }

        if let Ok(output) = Command::new("where").arg("suricata.exe").output()
            && output.status.success()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(path) = stdout.lines().map(str::trim).find(|line| !line.is_empty()) {
                let path = std::path::PathBuf::from(path);
                if path.exists() {
                    return Some(path);
                }
            }
        }

        None
    }

    #[cfg(windows)]
    fn find_file_recursive(
        root: &std::path::Path,
        target_filename: &str,
    ) -> Result<Option<std::path::PathBuf>> {
        let mut stack = vec![root.to_path_buf()];

        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir)
                .context(format!("Failed to read directory {}", dir.display()))?
            {
                let entry = entry?;
                let path = entry.path();
                let file_type = entry.file_type()?;

                if file_type.is_dir() {
                    stack.push(path);
                    continue;
                }

                if file_type.is_file()
                    && entry
                        .file_name()
                        .to_string_lossy()
                        .eq_ignore_ascii_case(target_filename)
                {
                    return Ok(Some(path));
                }
            }
        }

        Ok(None)
    }

    #[cfg(windows)]
    fn find_suricata_install_file(
        install_dir: &std::path::Path,
        filename: &str,
    ) -> Option<std::path::PathBuf> {
        let candidates = [
            install_dir.join(filename),
            install_dir.join("etc").join(filename),
        ];

        for candidate in candidates {
            if candidate.exists() {
                return Some(candidate);
            }
        }

        match find_file_recursive(install_dir, filename) {
            Ok(path) => path,
            Err(err) => {
                warn!(
                    "Failed to search for {} under {}: {}",
                    filename,
                    install_dir.display(),
                    err
                );
                None
            }
        }
    }

    #[cfg(windows)]
    fn copy_dir_recursive(source: &std::path::Path, destination: &std::path::Path) -> Result<()> {
        std::fs::create_dir_all(destination).context(format!(
            "Failed to create destination directory {}",
            destination.display()
        ))?;

        for entry in std::fs::read_dir(source).context(format!(
            "Failed to read source directory {}",
            source.display()
        ))? {
            let entry = entry?;
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            let file_type = entry.file_type()?;

            if file_type.is_dir() {
                copy_dir_recursive(&source_path, &destination_path)?;
            } else if file_type.is_file() {
                std::fs::copy(&source_path, &destination_path).context(format!(
                    "Failed to copy {} to {}",
                    source_path.display(),
                    destination_path.display()
                ))?;
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    fn patch_suricata_config_for_local_install(install_dir: &std::path::Path) -> Result<()> {
        let config_path = install_dir.join("suricata.yaml");
        if !config_path.exists() {
            return Ok(());
        }

        let original = std::fs::read_to_string(&config_path)
            .context(format!("Failed to read {}", config_path.display()))?;

        let install_dir_str = install_dir.display().to_string().replace('/', "\\");
        let patched = original
            .replace(r"C:\Program Files\Suricata", &install_dir_str)
            .replace(r"C:\Program Files (x86)\Suricata", &install_dir_str);

        if patched != original {
            std::fs::write(&config_path, patched)
                .context(format!("Failed to write {}", config_path.display()))?;
            info!(
                "Patched Suricata config paths for local install at {}",
                config_path.display()
            );
        }

        Ok(())
    }

    #[cfg(windows)]
    fn extract_msi_package_to_dir(
        path: &std::path::Path,
        name: &str,
        destination: &std::path::Path,
    ) -> Result<()> {
        use std::process::Command;

        info!(
            "Extracting {} from {:?} into {}",
            name,
            path,
            destination.display()
        );

        let staging_dir =
            tempfile::tempdir().context("Failed to create MSI extraction directory")?;
        let log_path =
            std::env::temp_dir().join(format!("evectl-{}-extract.log", name.to_ascii_lowercase()));

        let msi_path = path.to_string_lossy().replace('\'', "''");
        let target_dir = staging_dir.path().to_string_lossy().replace('\'', "''");
        let log_path_str = log_path.to_string_lossy().replace('\'', "''");

        let script = format!(
            r#"
$ErrorActionPreference = 'Stop'
$msiPath = '{}'
$targetDir = '{}'
$logPath = '{}'
New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
$argumentList = @('/a', $msiPath, '/qn', '/norestart', ('TARGETDIR=' + $targetDir), '/L*v', $logPath)
$process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $argumentList -Wait -PassThru
exit $process.ExitCode
"#,
            msi_path, target_dir, log_path_str
        );

        let output = Command::new("powershell")
            .arg("-NoProfile")
            .arg("-Command")
            .arg(&script)
            .output()
            .context(format!("Failed to extract {} MSI", name))?;

        let stderr = String::from_utf8_lossy(&output.stderr);

        match output.status.code() {
            Some(0) => {
                info!("{} extraction completed successfully", name);
            }
            Some(3010) | Some(1641) => {
                warn!(
                    "{} extraction completed, but a system reboot was requested by Windows Installer",
                    name
                );
            }
            Some(1223) => bail!("{} extraction was cancelled at the UAC prompt", name),
            Some(code) => bail!(
                "{} extraction failed with code {}. MSI log: {:?}. {}",
                name,
                code,
                log_path,
                stderr.trim()
            ),
            None => bail!("{} extraction terminated unexpectedly", name),
        }

        let extracted_exe = find_file_recursive(staging_dir.path(), "suricata.exe")?
            .ok_or_else(|| anyhow!("Failed to locate suricata.exe in extracted MSI contents"))?;

        let extracted_root = extracted_exe.parent().ok_or_else(|| {
            anyhow!(
                "Failed to determine extracted Suricata root from {}",
                extracted_exe.display()
            )
        })?;

        if destination.exists() {
            std::fs::remove_dir_all(destination).context(format!(
                "Failed to remove existing Suricata directory {}",
                destination.display()
            ))?;
        }

        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .context(format!("Failed to create {}", parent.display()))?;
        }

        copy_dir_recursive(extracted_root, destination)?;

        Ok(())
    }

    #[cfg(windows)]
    fn is_npcap_installed() -> bool {
        let service_exists = ["npcap", "npf"].iter().any(|service| {
            std::process::Command::new("sc")
                .args(["query", service])
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
        });

        if !service_exists {
            return false;
        }

        [
            r"C:\Windows\System32\drivers\npcap.sys",
            r"C:\Windows\System32\drivers\npf.sys",
        ]
        .iter()
        .any(|path| std::path::Path::new(path).exists())
    }

    #[cfg(windows)]
    fn is_suricata_managed_installed() -> bool {
        get_suricata_exe_path()
            .map(|path| path.exists())
            .unwrap_or(false)
    }

    #[cfg(windows)]
    fn is_suricata_installed() -> bool {
        if find_suricata_executable().is_some() {
            return true;
        }

        // Check if Suricata service exists
        if let Ok(output) = std::process::Command::new("sc")
            .args(["query", "Suricata"])
            .output()
            && output.status.success()
        {
            return true;
        }

        false
    }

    #[cfg(windows)]
    fn install(evebox: bool, no_evebox: bool) -> Result<()> {
        use std::io::IsTerminal;

        if evebox && no_evebox {
            bail!("--evebox and --no-evebox cannot be used together");
        }

        install_suricata()?;

        let evebox_installed = find_evebox_exe(&get_evebox_data_dir()?)?.is_some();

        let should_install_evebox = if evebox {
            true
        } else if no_evebox {
            false
        } else if evebox_installed {
            info!("EveBox is already installed in the evectl-managed directory.");
            false
        } else if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            match inquire::Confirm::new("Install EveBox?")
                .with_default(false)
                .prompt()
            {
                Ok(choice) => choice,
                Err(err) => {
                    warn!(
                        "Unable to prompt for EveBox installation ({}). Skipping EveBox. Use --evebox to install without prompting.",
                        err
                    );
                    false
                }
            }
        } else {
            info!(
                "Non-interactive terminal detected; skipping EveBox prompt. Use --evebox to install EveBox without prompting."
            );
            false
        };

        if should_install_evebox {
            install_evebox()?;
        } else if !evebox_installed {
            info!("Skipping EveBox installation");
        }

        Ok(())
    }

    #[cfg(windows)]
    fn install_suricata() -> Result<()> {
        download_npcap()?;
        install_or_upgrade_suricata(false)
    }

    #[cfg(windows)]
    fn npcap_upgrade_needed() -> Result<bool> {
        if !is_npcap_installed() {
            return Ok(true);
        }

        let Some(installed_version) = get_npcap_installed_version()? else {
            return Ok(false);
        };

        let Some(comparison) = compare_versions(&installed_version, NPCAP_VERSION) else {
            return Ok(false);
        };

        Ok(comparison == std::cmp::Ordering::Less)
    }

    #[cfg(windows)]
    fn suricata_upgrade_needed() -> Result<bool> {
        let target_version = suricata_version_for_comparison();

        if !is_suricata_managed_installed() {
            return Ok(true);
        }

        let installed_version = match get_suricata_installed_version()? {
            Some(version) => version,
            None => return Ok(true),
        };

        let Some(comparison) = compare_versions(&installed_version, target_version) else {
            return Ok(false);
        };

        Ok(comparison == std::cmp::Ordering::Less)
    }

    #[cfg(windows)]
    fn evebox_upgrade_needed() -> Result<bool> {
        if find_evebox_exe(&get_evebox_data_dir()?)?.is_none() {
            return Ok(true);
        }

        let Some(installed_version) = get_evebox_installed_version()? else {
            return Ok(true);
        };

        let Some(comparison) = compare_versions(&installed_version, EVEBOX_VERSION) else {
            return Ok(false);
        };

        Ok(comparison == std::cmp::Ordering::Less)
    }

    #[cfg(windows)]
    fn build_upgrade_plan() -> Result<UpgradePlan> {
        let evectl = match crate::selfupdate::is_update_available() {
            Ok(available) => available,
            Err(err) => {
                warn!("Failed to check for EveCtl updates: {}", err);
                false
            }
        };

        Ok(UpgradePlan {
            npcap: npcap_upgrade_needed()?,
            suricata: suricata_upgrade_needed()?,
            evebox: evebox_upgrade_needed()?,
            evectl,
        })
    }

    #[cfg(windows)]
    fn get_managed_runtime_metadata(role: &str) -> Result<Option<RuntimeMetadata>> {
        if !managed_process_is_running(role)? {
            return Ok(None);
        }

        let (_, runtime_path) = role_paths(role)?;
        read_runtime_metadata(&runtime_path)
    }

    #[cfg(windows)]
    fn suricata_guid_from_metadata(metadata: &RuntimeMetadata) -> Option<String> {
        metadata.argv.windows(2).find_map(|window| {
            if window[0] == "-i" {
                normalize_interface_guid(&window[1])
            } else {
                None
            }
        })
    }

    #[cfg(windows)]
    fn capture_restart_plan() -> Result<RestartPlan> {
        let suricata_running = get_managed_runtime_metadata(ROLE_SURICATA)?;
        let suricata_guid = suricata_running
            .as_ref()
            .and_then(suricata_guid_from_metadata)
            .or_else(|| get_configured_interface_guid().ok().flatten());

        let evebox_running = get_managed_runtime_metadata(ROLE_EVEBOX)?.is_some();

        Ok(RestartPlan {
            suricata_running: suricata_running.is_some(),
            suricata_guid,
            evebox_running,
        })
    }

    #[cfg(windows)]
    fn restart_managed_components(plan: &RestartPlan) -> Result<()> {
        let mut suricata_started = false;

        if plan.suricata_running {
            let guid = plan.suricata_guid.as_deref().ok_or_else(|| {
                anyhow!(
                    "Failed to determine the interface GUID used by the previously running Suricata process"
                )
            })?;

            let suricata = start_suricata_background(guid)?;
            if let Err(err) = wait_for_suricata_readiness(&suricata) {
                let _ = stop_suricata_managed();
                return Err(err);
            }
            suricata_started = true;
        }

        if plan.evebox_running {
            let evebox = match start_evebox_background() {
                Ok(metadata) => metadata,
                Err(err) => {
                    if suricata_started {
                        let _ = stop_suricata_managed();
                    }
                    return Err(err);
                }
            };

            if let Err(err) = validate_background_process_started(&evebox) {
                let _ = stop_evebox_managed();
                if suricata_started {
                    let _ = stop_suricata_managed();
                }
                return Err(err);
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    fn upgrade_windows_components() -> Result<()> {
        let plan = build_upgrade_plan()?;
        if !plan.any() {
            info!("No upgrades are available.");
            return Ok(());
        }

        if plan.evectl {
            info!("An EveCtl update is available.");
            info!("To upgrade EveCtl on Windows, run:");
            info!("  irm https://evebox.org/evectl.ps1 | iex");
        }

        if !plan.any_components() {
            return Ok(());
        }

        let restart_plan = capture_restart_plan()?;
        if restart_plan.any() {
            info!("Stopping managed Windows services before upgrade");
            stop_stack()?;
        }

        let upgrade_result = (|| {
            maybe_upgrade_npcap()?;
            maybe_upgrade_suricata()?;
            maybe_upgrade_evebox()?;
            Ok(())
        })();

        if let Err(err) = upgrade_result {
            if restart_plan.any()
                && let Err(restart_err) = restart_managed_components(&restart_plan)
            {
                return Err(anyhow!(
                    "Upgrade failed: {}\nAdditionally failed to restart previously running services: {}",
                    err,
                    restart_err
                ));
            }
            return Err(err);
        }

        if restart_plan.any() {
            restart_managed_components(&restart_plan)?;
        }

        Ok(())
    }

    #[cfg(windows)]
    fn maybe_upgrade_npcap() -> Result<()> {
        if !is_npcap_installed() {
            info!(
                "Npcap was not detected. Installing version {} before Suricata upgrade...",
                NPCAP_VERSION
            );
            return install_or_upgrade_npcap(true);
        }

        let installed_version = match get_npcap_installed_version()? {
            Some(version) => version,
            None => {
                info!(
                    "Npcap is installed, but the installed version could not be determined. Skipping automatic Npcap upgrade."
                );
                return Ok(());
            }
        };

        let comparison = match compare_versions(&installed_version, NPCAP_VERSION) {
            Some(comparison) => comparison,
            None => {
                info!(
                    "Npcap version comparison failed (installed: {}, bundled: {}). Skipping automatic Npcap upgrade.",
                    installed_version, NPCAP_VERSION
                );
                return Ok(());
            }
        };

        match comparison {
            std::cmp::Ordering::Less => {
                info!(
                    "Npcap {} is older than bundled {}. Upgrading Npcap...",
                    installed_version, NPCAP_VERSION
                );
                install_or_upgrade_npcap(true)
            }
            std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {
                info!(
                    "Npcap {} meets or exceeds bundled {}. Skipping Npcap upgrade.",
                    installed_version, NPCAP_VERSION
                );
                Ok(())
            }
        }
    }

    #[cfg(windows)]
    fn get_npcap_installed_version() -> Result<Option<String>> {
        use std::process::Command;

        let script = r#"
$entry = @(
    Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
    Get-ItemProperty 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
) | Where-Object { $_.DisplayName -like 'Npcap*' } | Select-Object -First 1

if ($entry -and $entry.DisplayVersion) {
    Write-Output $entry.DisplayVersion
}
"#;

        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", script])
            .output()
            .context("Failed to query installed Npcap version")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                "Failed to determine installed Npcap version: {}",
                stderr.trim()
            );
            return Ok(None);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let version = stdout.trim();
        if version.is_empty() {
            Ok(None)
        } else {
            Ok(Some(version.to_string()))
        }
    }

    #[cfg(windows)]
    fn compare_versions(current: &str, target: &str) -> Option<std::cmp::Ordering> {
        let current_parts = parse_version_parts(current)?;
        let target_parts = parse_version_parts(target)?;
        let max_len = current_parts.len().max(target_parts.len());

        for idx in 0..max_len {
            let lhs = *current_parts.get(idx).unwrap_or(&0);
            let rhs = *target_parts.get(idx).unwrap_or(&0);
            let ord = lhs.cmp(&rhs);
            if ord != std::cmp::Ordering::Equal {
                return Some(ord);
            }
        }

        Some(std::cmp::Ordering::Equal)
    }

    #[cfg(windows)]
    fn parse_version_parts(version: &str) -> Option<Vec<u32>> {
        let mut parts = vec![];
        let mut current = String::new();

        for ch in version.trim().chars() {
            if ch.is_ascii_digit() {
                current.push(ch);
            } else if !current.is_empty() {
                let value = match current.parse::<u32>() {
                    Ok(value) => value,
                    Err(_) => return None,
                };
                parts.push(value);
                current.clear();
            }
        }

        if !current.is_empty() {
            let value = match current.parse::<u32>() {
                Ok(value) => value,
                Err(_) => return None,
            };
            parts.push(value);
        }

        if parts.is_empty() { None } else { Some(parts) }
    }

    #[cfg(windows)]
    fn maybe_upgrade_suricata() -> Result<()> {
        let target_version = suricata_version_for_comparison();
        let managed_installed = is_suricata_managed_installed();
        let any_installed = is_suricata_installed();

        if !managed_installed {
            if any_installed {
                info!(
                    "A non-evectl Suricata installation was detected. Installing evectl-managed version {}...",
                    SURICATA_VERSION
                );
            } else {
                info!(
                    "Suricata was not detected. Installing version {}...",
                    SURICATA_VERSION
                );
            }
            return install_or_upgrade_suricata(true);
        }

        let installed_version = match get_suricata_installed_version()? {
            Some(version) => version,
            None => {
                info!(
                    "Suricata is installed in the evectl-managed directory, but the version could not be determined. Reinstalling bundled version {}.",
                    SURICATA_VERSION
                );
                return install_or_upgrade_suricata(true);
            }
        };

        let comparison = match compare_versions(&installed_version, target_version) {
            Some(comparison) => comparison,
            None => {
                info!(
                    "Suricata version comparison failed (installed: {}, bundled: {}, comparison target: {}). Skipping automatic Suricata upgrade.",
                    installed_version, SURICATA_VERSION, target_version
                );
                return Ok(());
            }
        };

        match comparison {
            std::cmp::Ordering::Less => {
                info!(
                    "Suricata {} is older than bundled {} (package {}). Upgrading Suricata...",
                    installed_version, target_version, SURICATA_VERSION
                );
                install_or_upgrade_suricata(true)
            }
            std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {
                info!(
                    "Suricata {} meets or exceeds bundled {} (package {}). Skipping Suricata upgrade.",
                    installed_version, target_version, SURICATA_VERSION
                );
                Ok(())
            }
        }
    }

    #[cfg(windows)]
    fn maybe_upgrade_evebox() -> Result<()> {
        if find_evebox_exe(&get_evebox_data_dir()?)?.is_none() {
            info!(
                "EveBox was not detected. Installing version {}...",
                EVEBOX_VERSION
            );
            return install_or_upgrade_evebox(true);
        }

        let installed_version = match get_evebox_installed_version()? {
            Some(version) => version,
            None => {
                info!(
                    "EveBox is installed in the evectl-managed directory, but the version could not be determined. Reinstalling bundled version {}.",
                    EVEBOX_VERSION
                );
                return install_or_upgrade_evebox(true);
            }
        };

        let comparison = match compare_versions(&installed_version, EVEBOX_VERSION) {
            Some(comparison) => comparison,
            None => {
                info!(
                    "EveBox version comparison failed (installed: {}, bundled: {}). Skipping automatic EveBox upgrade.",
                    installed_version, EVEBOX_VERSION
                );
                return Ok(());
            }
        };

        match comparison {
            std::cmp::Ordering::Less => {
                info!(
                    "EveBox {} is older than bundled {}. Upgrading EveBox...",
                    installed_version, EVEBOX_VERSION
                );
                install_or_upgrade_evebox(true)
            }
            std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {
                info!(
                    "EveBox {} meets or exceeds bundled {}. Skipping EveBox upgrade.",
                    installed_version, EVEBOX_VERSION
                );
                Ok(())
            }
        }
    }

    #[cfg(windows)]
    fn suricata_version_for_comparison() -> &'static str {
        SURICATA_VERSION
            .split('-')
            .next()
            .unwrap_or(SURICATA_VERSION)
    }

    #[cfg(windows)]
    fn get_suricata_installed_version() -> Result<Option<String>> {
        if let Ok(marker_path) = get_suricata_version_marker_path()
            && marker_path.exists()
        {
            let version = std::fs::read_to_string(&marker_path).context(format!(
                "Failed to read Suricata version marker {}",
                marker_path.display()
            ))?;
            let version = version.trim();
            if !version.is_empty() {
                return Ok(Some(version.to_string()));
            }
        }

        Ok(None)
    }

    #[cfg(windows)]
    fn install_or_upgrade_suricata(upgrade: bool) -> Result<()> {
        let managed_installed = is_suricata_managed_installed();
        let any_installed = is_suricata_installed();

        if managed_installed && !upgrade {
            info!("Suricata is already installed in the evectl-managed directory.");
            return Ok(());
        }

        if any_installed
            && !managed_installed
            && !upgrade
            && let Ok(install_dir) = get_suricata_install_dir()
        {
            info!(
                "A system Suricata installation was detected. Installing an evectl-managed copy into {}.",
                install_dir.display()
            );
        }

        if upgrade {
            if managed_installed {
                info!("Upgrading Suricata to version {}...", SURICATA_VERSION);

                if let Err(err) = stop_suricata_managed() {
                    warn!("Failed to stop running Suricata processes: {}", err);
                }

                uninstall_suricata()?;
            } else if any_installed {
                info!(
                    "A non-evectl Suricata installation was detected. Installing evectl-managed version {} instead...",
                    SURICATA_VERSION
                );
            } else {
                info!(
                    "Suricata was not detected. Installing version {} instead...",
                    SURICATA_VERSION
                );
            }
        }

        let url = format!(
            "https://www.openinfosecfoundation.org/download/windows/Suricata-{}-64bit.msi",
            SURICATA_VERSION
        );
        let filename = format!("Suricata-{}-64bit.msi", SURICATA_VERSION);

        let cache_dir = get_evectl_data_dir()?.join("downloads");
        std::fs::create_dir_all(&cache_dir).context(format!(
            "Failed to create installer cache directory {}",
            cache_dir.display()
        ))?;

        let msi_path = cache_dir.join(&filename);

        if msi_path.exists() {
            info!("Suricata installer already exists at {:?}", msi_path);
            info!("Skipping download, using existing file");
        } else {
            download_file(&url, &msi_path, "Suricata")?;
        }

        let install_dir = get_suricata_install_dir()?;
        extract_msi_package_to_dir(&msi_path, "Suricata", &install_dir)?;
        patch_suricata_config_for_local_install(&install_dir)?;

        let marker_path = get_suricata_version_marker_path()?;
        std::fs::write(&marker_path, suricata_version_for_comparison()).context(format!(
            "Failed to write Suricata version marker {}",
            marker_path.display()
        ))?;

        let suricata_exe = get_suricata_exe_path()?;
        if !suricata_exe.exists() {
            bail!(
                "Suricata extraction completed, but executable not found at {}",
                suricata_exe.display()
            );
        }

        info!(
            "Suricata {} extracted to {}",
            SURICATA_VERSION,
            install_dir.display()
        );

        Ok(())
    }

    #[cfg(windows)]
    fn log_uninstall_process_diagnostics() -> Result<()> {
        let suricata_install_dir = get_suricata_install_dir()?;
        let suricata_exe_path = get_suricata_exe_path()?;
        log_processes_in_dir("suricata", &suricata_install_dir, Some(&suricata_exe_path))?;

        let evebox_data_dir = get_evebox_data_dir()?;
        let evebox_exe_path = find_evebox_exe(&evebox_data_dir)?;
        log_processes_in_dir("evebox", &evebox_data_dir, evebox_exe_path.as_deref())?;

        Ok(())
    }

    #[cfg(windows)]
    fn cleanup_suricata_leftovers() -> Result<()> {
        use std::process::Command;

        let mut errors = vec![];
        let install_dir = get_suricata_install_dir()?;

        if install_dir.exists() {
            info!("Removing Suricata directory {}", install_dir.display());

            if let Err(err) = std::fs::remove_dir_all(&install_dir) {
                warn!(
                    "Failed to remove {} directly: {}. Trying PowerShell cleanup...",
                    install_dir.display(),
                    err
                );

                let escaped = install_dir.to_string_lossy().replace('\'', "''");
                let script = format!(
                    "$ErrorActionPreference = 'Stop'; if (Test-Path -LiteralPath '{0}') {{ Remove-Item -LiteralPath '{0}' -Recurse -Force }}",
                    escaped
                );

                match Command::new("powershell")
                    .args(["-NoProfile", "-Command", &script])
                    .output()
                {
                    Ok(output) if output.status.success() => {}
                    Ok(output) => {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        errors.push(format!("{}: {}", install_dir.display(), stderr.trim()));
                    }
                    Err(ps_err) => {
                        errors.push(format!("{}: {}", install_dir.display(), ps_err));
                    }
                }
            }
        }

        if !errors.is_empty() {
            warn!(
                "Suricata uninstall cleanup hit file-lock or removal errors. This often means a non-Suricata process still has a handle open under the install directory (for example Explorer, antivirus, an editor, or another tool)."
            );
            bail!(
                "Failed to remove Suricata leftover files:\n- {}",
                errors.join("\n- ")
            );
        }

        let suricata_exe_path = get_suricata_exe_path()?;
        if suricata_exe_path.exists() {
            bail!(
                "Suricata uninstall completed, but this executable still exists:\n- {}",
                suricata_exe_path.display()
            );
        }

        Ok(())
    }

    #[cfg(windows)]
    fn uninstall_suricata() -> Result<()> {
        info!("Removing evectl-managed Suricata installation...");
        cleanup_suricata_leftovers()
    }

    #[cfg(windows)]
    fn uninstall_npcap() -> Result<()> {
        use std::process::Command;

        info!("Uninstalling existing Npcap installation...");

        let script = r#"
$ErrorActionPreference = 'Stop'
$entry = @(
    Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
    Get-ItemProperty 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
) | Where-Object { $_.DisplayName -like 'Npcap*' } | Select-Object -First 1

if (-not $entry) {
    Write-Output 'NOT_FOUND'
    exit 0
}

$productCode = $entry.PSChildName
if ($productCode -match '^\{[0-9A-Fa-f\-]+\}$') {
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList '/x', $productCode, '/qn', '/norestart' -Verb RunAs -Wait -PassThru
    exit $process.ExitCode
}

$command = $entry.QuietUninstallString
if ([string]::IsNullOrWhiteSpace($command)) {
    $command = $entry.UninstallString
}
if ([string]::IsNullOrWhiteSpace($command)) {
    throw 'Unable to determine Npcap uninstall command'
}

if ($command -match '(?i)msiexec(\.exe)?') {
    $command = $command -replace '(?i)\s/I(?=\s|\{)', ' /X'
    if ($command -notmatch '(?i)\s/(qn|quiet|passive)\b') {
        $command = "$command /qn"
    }
    if ($command -notmatch '(?i)\s/norestart\b') {
        $command = "$command /norestart"
    }
}

$process = Start-Process -FilePath 'cmd.exe' -ArgumentList '/C', $command -Verb RunAs -Wait -PassThru
exit $process.ExitCode
"#;

        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", script])
            .output()
            .context("Failed to execute Npcap uninstall command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Npcap uninstall failed: {}", stderr.trim());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("NOT_FOUND") {
            info!("Npcap uninstall entry not found. Skipping Npcap uninstall.");
            return Ok(());
        }

        info!("Npcap uninstall completed");
        Ok(())
    }

    #[cfg(windows)]
    fn get_evebox_data_dir() -> Result<std::path::PathBuf> {
        Ok(get_evectl_data_dir()?.join("evebox"))
    }

    #[cfg(windows)]
    fn find_evebox_exe(dir: &Path) -> Result<Option<PathBuf>> {
        let direct_path = dir.join("evebox.exe");
        if direct_path.exists() {
            return Ok(Some(direct_path));
        }

        if !dir.exists() {
            return Ok(None);
        }

        for entry in std::fs::read_dir(dir)
            .with_context(|| format!("Failed to read EveBox directory {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            if let Some(exe_path) = find_evebox_exe(&path)? {
                return Ok(Some(exe_path));
            }
        }

        Ok(None)
    }

    #[cfg(windows)]
    fn get_evebox_run_dir() -> Result<PathBuf> {
        Ok(get_evebox_data_dir()?.join("run"))
    }

    #[cfg(windows)]
    fn get_evebox_log_dir() -> Result<PathBuf> {
        Ok(get_evebox_data_dir()?.join("log"))
    }

    #[cfg(windows)]
    fn get_evebox_exe_path() -> Result<PathBuf> {
        find_evebox_exe(&get_evebox_data_dir()?)?
            .ok_or_else(|| anyhow!("EveBox is not installed. Run 'evectl install --evebox' first."))
    }

    #[cfg(windows)]
    fn get_evebox_version_marker_path() -> Result<PathBuf> {
        Ok(get_evebox_data_dir()?.join(EVEBOX_VERSION_MARKER))
    }

    #[cfg(windows)]
    fn is_evebox_install_dir_name(name: &str) -> bool {
        name.strip_prefix("evebox-")
            .and_then(|rest| rest.strip_suffix("-windows-x64"))
            .is_some_and(|version| !version.is_empty())
    }

    #[cfg(windows)]
    fn find_evebox_install_root(data_dir: &Path, exe_path: &Path) -> Option<PathBuf> {
        let mut current = exe_path.parent();
        while let Some(dir) = current {
            if dir == data_dir {
                break;
            }

            if dir
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(is_evebox_install_dir_name)
            {
                return Some(dir.to_path_buf());
            }

            current = dir.parent();
        }

        exe_path.parent().and_then(|parent| {
            if parent != data_dir && parent.starts_with(data_dir) {
                Some(parent.to_path_buf())
            } else {
                None
            }
        })
    }

    #[cfg(windows)]
    fn remove_existing_evebox_installation() -> Result<()> {
        let data_dir = get_evebox_data_dir()?;
        let Some(exe_path) = find_evebox_exe(&data_dir)? else {
            return Ok(());
        };

        if let Some(install_root) = find_evebox_install_root(&data_dir, &exe_path) {
            std::fs::remove_dir_all(&install_root).context(format!(
                "Failed to remove existing EveBox install directory {}",
                install_root.display()
            ))?;
            info!(
                "Removed previous EveBox install files from {} while preserving data in {}",
                install_root.display(),
                data_dir.display()
            );
        } else {
            remove_file_if_exists(&exe_path)?;
            info!(
                "Removed previous EveBox executable {} while preserving data in {}",
                exe_path.display(),
                data_dir.display()
            );
        }

        remove_file_if_exists(&get_evebox_version_marker_path()?)?;
        Ok(())
    }

    #[cfg(windows)]
    fn extract_evebox_version_from_path(path: &Path) -> Option<String> {
        for component in path.components() {
            let name = component.as_os_str().to_string_lossy();
            if let Some(version) = name
                .strip_prefix("evebox-")
                .and_then(|rest| rest.strip_suffix("-windows-x64"))
                && !version.is_empty()
            {
                return Some(version.to_string());
            }
        }

        None
    }

    #[cfg(windows)]
    fn get_evebox_installed_version() -> Result<Option<String>> {
        if let Ok(marker_path) = get_evebox_version_marker_path()
            && marker_path.exists()
        {
            let version = std::fs::read_to_string(&marker_path).context(format!(
                "Failed to read EveBox version marker {}",
                marker_path.display()
            ))?;
            let version = version.trim();
            if !version.is_empty() {
                return Ok(Some(version.to_string()));
            }
        }

        let Some(exe_path) = find_evebox_exe(&get_evebox_data_dir()?)? else {
            return Ok(None);
        };

        Ok(extract_evebox_version_from_path(&exe_path))
    }

    #[cfg(windows)]
    fn get_evebox_pid_path() -> Result<PathBuf> {
        Ok(get_evebox_run_dir()?.join("evebox.pid"))
    }

    #[cfg(windows)]
    fn get_evebox_runtime_path() -> Result<PathBuf> {
        Ok(get_evebox_run_dir()?.join("evebox.runtime.json"))
    }

    #[cfg(windows)]
    fn get_evebox_stdout_log_path() -> Result<PathBuf> {
        Ok(get_evebox_log_dir()?.join("evebox-stdout.log"))
    }

    #[cfg(windows)]
    fn get_evebox_stderr_log_path() -> Result<PathBuf> {
        Ok(get_evebox_log_dir()?.join("evebox-stderr.log"))
    }

    #[cfg(windows)]
    fn uninstall_evebox() -> Result<()> {
        let data_dir = get_evebox_data_dir()?;

        if !data_dir.exists() {
            info!(
                "EveBox is not installed in {:?}. Skipping EveBox uninstall.",
                data_dir
            );
            return Ok(());
        }

        std::fs::remove_dir_all(&data_dir)
            .context(format!("Failed to remove EveBox directory {:?}", data_dir))?;
        info!("EveBox uninstalled from {:?}", data_dir);
        Ok(())
    }

    #[cfg(windows)]
    fn ensure_managed_services_stopped_for_uninstall() -> Result<()> {
        let suricata_running = managed_process_is_running(ROLE_SURICATA)?;
        let evebox_running = managed_process_is_running(ROLE_EVEBOX)?;

        if !suricata_running && !evebox_running {
            return Ok(());
        }

        info!("Stopping managed Windows services before uninstall");
        stop_stack().context("Failed to stop managed Windows stack before uninstall")?;

        if managed_process_is_running(ROLE_SURICATA)? || managed_process_is_running(ROLE_EVEBOX)? {
            bail!("Managed Windows services are still running after stop was requested");
        }

        Ok(())
    }

    #[cfg(windows)]
    fn ensure_unmanaged_evectl_processes_stopped_for_uninstall() -> Result<()> {
        let suricata_install_dir = get_suricata_install_dir()?;
        let suricata_exe_path = get_suricata_exe_path()?;
        stop_named_processes_in_dir("suricata", &suricata_install_dir, Some(&suricata_exe_path))?;

        let evebox_data_dir = get_evebox_data_dir()?;
        let evebox_exe_path = find_evebox_exe(&evebox_data_dir)?;
        stop_named_processes_in_dir("evebox", &evebox_data_dir, evebox_exe_path.as_deref())?;

        Ok(())
    }

    #[cfg(windows)]
    fn uninstall_windows_components() -> Result<()> {
        ensure_managed_services_stopped_for_uninstall()?;
        ensure_unmanaged_evectl_processes_stopped_for_uninstall()?;
        log_uninstall_process_diagnostics()?;

        let mut errors: Vec<String> = vec![];

        if let Err(err) = uninstall_evebox() {
            errors.push(format!("EveBox uninstall failed: {}", err));
        }

        if let Err(err) = uninstall_suricata() {
            errors.push(format!("Suricata uninstall failed: {}", err));
        }

        if let Err(err) = uninstall_npcap() {
            errors.push(format!("Npcap uninstall failed: {}", err));
        }

        if errors.is_empty() {
            info!("Windows component uninstall completed");
            Ok(())
        } else {
            bail!(
                "Windows component uninstall completed with errors:\n- {}",
                errors.join("\n- ")
            )
        }
    }

    #[cfg(windows)]
    fn install_evebox() -> Result<()> {
        install_or_upgrade_evebox(false)
    }

    #[cfg(windows)]
    fn install_or_upgrade_evebox(upgrade: bool) -> Result<()> {
        let url = EVEBOX_URL;

        // Create project-specific data directory
        let data_dir = get_evebox_data_dir()?;

        // Create directory if it doesn't exist
        std::fs::create_dir_all(&data_dir).context("Failed to create EveBox data directory")?;

        // Check if EveBox is already installed in the data directory
        if find_evebox_exe(&data_dir)?.is_some() {
            if !upgrade {
                info!("EveBox is already installed in the evectl-managed directory.");
                return Ok(());
            }

            remove_existing_evebox_installation()?;
            std::fs::create_dir_all(&data_dir)
                .context("Failed to ensure EveBox data directory after upgrade cleanup")?;
        }

        // Download to temp directory
        let temp_dir = tempfile::tempdir()?;
        let zip_path = temp_dir
            .path()
            .join(format!("evebox-{}-windows-x64.zip", EVEBOX_VERSION));

        download_file(url, &zip_path, "EveBox")?;

        info!("Extracting EveBox to {:?}", data_dir);

        // Extract the zip file
        let zip_file =
            std::fs::File::open(&zip_path).context("Failed to open downloaded EveBox zip file")?;
        let mut archive =
            zip::ZipArchive::new(zip_file).context("Failed to read EveBox zip archive")?;

        // Extract all files to the data directory
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let outpath = data_dir.join(file.mangled_name());

            if file.name().ends_with('/') {
                std::fs::create_dir_all(&outpath)?;
            } else {
                if let Some(p) = outpath.parent()
                    && !p.exists()
                {
                    std::fs::create_dir_all(p)?;
                }
                let mut outfile = std::fs::File::create(&outpath)?;
                std::io::copy(&mut file, &mut outfile)?;
            }
        }

        let _ = get_evebox_exe_path()?;
        let marker_path = get_evebox_version_marker_path()?;
        std::fs::write(&marker_path, EVEBOX_VERSION).context(format!(
            "Failed to write EveBox version marker {}",
            marker_path.display()
        ))?;
        info!(
            "EveBox {} installed successfully at {:?}",
            EVEBOX_VERSION, data_dir
        );

        Ok(())
    }

    #[cfg(windows)]
    fn list_interfaces() -> Result<()> {
        use std::process::Command;

        // Use PowerShell to get network interface information
        let output = Command::new("powershell")
            .args([
                "-Command",
                "Get-NetAdapter | ForEach-Object { $adapter = $_; Get-NetIPAddress -InterfaceIndex $adapter.ifIndex | ForEach-Object { [PSCustomObject]@{ Name = $adapter.Name; IPAddress = $_.IPAddress; GUID = $adapter.InterfaceGuid } } } | Format-Table -AutoSize"
            ])
            .output()
            .context("Failed to execute PowerShell command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("PowerShell command failed: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("{}", stdout);

        Ok(())
    }

    #[cfg(windows)]
    fn build_suricata_command(guid: &str) -> Result<Command> {
        if !is_suricata_installed() {
            bail!("Suricata is not installed. Please install it first using 'evectl install'");
        }

        let suricata_path = find_suricata_executable()
            .ok_or_else(|| anyhow!("Suricata executable not found in expected locations"))?;
        let suricata_dir = suricata_path
            .parent()
            .ok_or_else(|| anyhow!("Failed to determine Suricata installation directory"))?
            .to_path_buf();

        let suricata_log_dir = get_suricata_log_dir()?;
        ensure_dir(&suricata_log_dir)?;

        let npcap_device = format!("\\Device\\NPF_{{{}}}", guid.trim_matches(['{', '}']));
        let rules_include_path = write_suricata_rules_include_stub()?;

        let mut command = Command::new(&suricata_path);
        let suricata_config = suricata_dir.join("suricata.yaml");
        if suricata_config.exists() {
            command.arg("-c");
            command.arg(&suricata_config);
        }
        command.arg("--include");
        command.arg(&rules_include_path);
        command.current_dir(&suricata_dir);
        command.arg("-i");
        command.arg(&npcap_device);
        command.arg("-l");
        command.arg(&suricata_log_dir);

        if let Some(classification_file) =
            find_suricata_install_file(&suricata_dir, "classification.config")
        {
            command.arg("--set");
            command.arg(format!(
                "classification-file={}",
                classification_file.display()
            ));
        } else {
            warn!(
                "Could not find classification.config under {}; relying on Suricata defaults",
                suricata_dir.display()
            );
        }

        if let Some(reference_config_file) =
            find_suricata_install_file(&suricata_dir, "reference.config")
        {
            command.arg("--set");
            command.arg(format!(
                "reference-config-file={}",
                reference_config_file.display()
            ));
        } else {
            warn!(
                "Could not find reference.config under {}; relying on Suricata defaults",
                suricata_dir.display()
            );
        }

        Ok(command)
    }

    #[cfg(windows)]
    fn process_line_reader<R: std::io::Read + Send + 'static>(output: R, label: &'static str) {
        let reader = BufReader::new(output).lines();
        for line in reader {
            match line {
                Ok(line) => {
                    let mut stdout = std::io::stdout().lock();
                    let _ = writeln!(&mut stdout, "{}: {}", label, line);
                    let _ = stdout.flush();
                }
                Err(err) => {
                    debug!("Failed to read {} output: {}", label, err);
                    break;
                }
            }
        }
    }

    #[cfg(windows)]
    fn process_output_handler(child: &mut Child, label: &'static str) {
        if let Some(stdout) = child.stdout.take() {
            std::thread::spawn(move || process_line_reader(stdout, label));
        }

        if let Some(stderr) = child.stderr.take() {
            std::thread::spawn(move || process_line_reader(stderr, label));
        }
    }

    #[cfg(windows)]
    fn ensure_suricata_start_allowed() -> Result<()> {
        if managed_process_is_running(ROLE_SURICATA)? {
            bail!("A managed Suricata process is already running. Use 'evectl stop' first.");
        }

        let process_count = count_named_processes("suricata")?;
        if process_count > 0 {
            bail!(
                "Suricata is already running ({} process(es) found). Use 'evectl stop-suricata' to stop it first.",
                process_count
            );
        }

        Ok(())
    }

    #[cfg(windows)]
    fn ensure_evebox_start_allowed() -> Result<()> {
        if managed_process_is_running(ROLE_EVEBOX)? {
            bail!("A managed EveBox process is already running. Use 'evectl stop' first.");
        }

        let process_count = count_named_processes("evebox")?;
        if process_count > 0 {
            bail!(
                "EveBox is already running ({} process(es) found). Use 'evectl stop' first.",
                process_count
            );
        }

        Ok(())
    }

    #[cfg(windows)]
    fn start_stack_foreground(guid: Option<String>) -> Result<()> {
        ensure_suricata_start_allowed()?;
        ensure_evebox_start_allowed()?;

        let guid = resolve_interface_guid(guid, true)?;
        let _ = get_evebox_exe_path()?;

        ensure_ctrlc_handler()?;
        CTRL_C_RECEIVED.store(false, Ordering::SeqCst);

        let mut suricata_command = build_suricata_command(&guid)?;
        let suricata_exe = PathBuf::from(suricata_command.get_program());
        suricata_command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        info!(
            "Running command: {}",
            format_command_line(&suricata_command)
        );
        let mut suricata = suricata_command
            .spawn()
            .context("Failed to start Suricata")?;
        process_output_handler(&mut suricata, ROLE_SURICATA);

        if let Err(err) = wait_for_suricata_pid_readiness(suricata.id(), &suricata_exe) {
            let _ = stop_pid(suricata.id());
            let _ = suricata.wait();
            return Err(err);
        }

        let mut evebox_command = build_evebox_command()?;
        evebox_command.stdout(Stdio::piped()).stderr(Stdio::piped());
        info!("Running command: {}", format_command_line(&evebox_command));
        let mut evebox = match evebox_command.spawn().context("Failed to start EveBox") {
            Ok(child) => child,
            Err(err) => {
                let _ = stop_pid(suricata.id());
                let _ = suricata.wait();
                return Err(err);
            }
        };
        process_output_handler(&mut evebox, ROLE_EVEBOX);

        println!("Foreground Windows stack started");
        println!("  Suricata PID: {}", suricata.id());
        println!("  EveBox PID:   {}", evebox.id());
        println!("  EveBox URL:   {}", EVEBOX_ACCESS_URL);
        println!("Press Ctrl-C to stop both processes.");

        let mut failure: Option<String> = None;
        let mut shutdown_requested = false;
        let mut suricata_status = None;
        let mut evebox_status = None;

        loop {
            if !shutdown_requested && CTRL_C_RECEIVED.swap(false, Ordering::SeqCst) {
                info!("Received Ctrl-C, stopping foreground Windows stack");
                shutdown_requested = true;
                let _ = stop_pid(evebox.id());
                let _ = stop_pid(suricata.id());
            }

            if suricata_status.is_none()
                && let Some(status) = suricata.try_wait()?
            {
                if !shutdown_requested {
                    failure = Some(format!("Suricata exited with status: {}", status));
                    shutdown_requested = true;
                    let _ = stop_pid(evebox.id());
                }
                suricata_status = Some(status);
            }

            if evebox_status.is_none()
                && let Some(status) = evebox.try_wait()?
            {
                if !shutdown_requested {
                    failure = Some(format!("EveBox exited with status: {}", status));
                    shutdown_requested = true;
                    let _ = stop_pid(suricata.id());
                }
                evebox_status = Some(status);
            }

            if suricata_status.is_some() && evebox_status.is_some() {
                break;
            }

            std::thread::sleep(Duration::from_millis(100));
        }

        if let Some(message) = failure {
            bail!(message);
        }

        Ok(())
    }

    #[cfg(windows)]
    fn start_suricata_background(guid: &str) -> Result<RuntimeMetadata> {
        ensure_suricata_start_allowed()?;

        let command = build_suricata_command(guid)?;
        info!("Running command: {}", format_command_line(&command));
        let pid = spawn_detached(&command)?;

        let command = build_suricata_command(guid)?;
        let metadata = build_runtime_metadata(ROLE_SURICATA, &command, pid, None, None)?;

        ensure_dir(&get_suricata_run_dir()?)?;
        write_pid(&get_suricata_pid_path()?, pid)?;
        write_runtime_metadata(&get_suricata_runtime_path()?, &metadata)?;

        Ok(metadata)
    }

    #[cfg(windows)]
    fn build_evebox_command() -> Result<Command> {
        let evebox_exe = get_evebox_exe_path()?;

        let evebox_data_dir = get_evebox_data_dir()?;
        ensure_dir(&evebox_data_dir)?;
        ensure_dir(&get_evebox_log_dir()?)?;
        ensure_dir(&get_evebox_run_dir()?)?;

        let mut command = Command::new(&evebox_exe);
        command.current_dir(&evebox_data_dir);
        command.arg("server");
        command.arg("--sqlite");
        command.arg("--no-auth");
        command.arg("--no-tls");
        command.arg("--host");
        command.arg(EVEBOX_HOST);
        command.arg("--port");
        command.arg(EVEBOX_PORT);
        command.arg("-D");
        command.arg(&evebox_data_dir);
        command.arg(get_suricata_eve_json_path()?);

        Ok(command)
    }

    #[cfg(windows)]
    fn start_evebox_background() -> Result<RuntimeMetadata> {
        ensure_evebox_start_allowed()?;

        let command = build_evebox_command()?;
        info!("Running command: {}", format_command_line(&command));
        let pid = spawn_detached(&command)?;

        let command = build_evebox_command()?;
        let metadata = build_runtime_metadata(ROLE_EVEBOX, &command, pid, None, None)?;

        write_pid(&get_evebox_pid_path()?, pid)?;
        write_runtime_metadata(&get_evebox_runtime_path()?, &metadata)?;

        Ok(metadata)
    }

    #[cfg(windows)]
    fn wait_for_suricata_pid_readiness(pid: u32, exe_path: &Path) -> Result<()> {
        let eve_json = get_suricata_eve_json_path()?;
        let started = std::time::Instant::now();

        while started.elapsed() < SURICATA_READY_TIMEOUT {
            if !is_pid_running(pid) {
                bail!("Suricata exited before EveBox could be started");
            }

            if process_matches_exe(pid, exe_path)? && eve_json.exists() {
                return Ok(());
            }

            std::thread::sleep(Duration::from_millis(250));
        }

        if !is_pid_running(pid) {
            bail!("Suricata exited before it became ready");
        }

        Ok(())
    }

    #[cfg(windows)]
    fn wait_for_suricata_readiness(metadata: &RuntimeMetadata) -> Result<()> {
        wait_for_suricata_pid_readiness(metadata.pid, Path::new(&metadata.exe_path))
    }

    #[cfg(windows)]
    fn validate_background_process_started(metadata: &RuntimeMetadata) -> Result<()> {
        std::thread::sleep(EVEBOX_STARTUP_GRACE_PERIOD);

        if !is_pid_running(metadata.pid) {
            bail!("{} exited immediately after startup", metadata.role);
        }

        if !process_matches_exe(metadata.pid, Path::new(&metadata.exe_path))? {
            bail!(
                "{} PID {} no longer matches {}",
                metadata.role,
                metadata.pid,
                metadata.exe_path
            );
        }

        Ok(())
    }

    #[cfg(windows)]
    fn stop_evebox_managed() -> Result<()> {
        stop_managed_process(ROLE_EVEBOX)
    }

    #[cfg(windows)]
    fn stop_suricata_managed() -> Result<()> {
        stop_managed_process(ROLE_SURICATA)
    }

    #[cfg(windows)]
    fn start_stack(background: bool, guid: Option<String>) -> Result<()> {
        if !background {
            return start_stack_foreground(guid);
        }

        let guid = resolve_interface_guid(guid, true)?;
        let _ = get_evebox_exe_path()?;

        if managed_process_is_running(ROLE_SURICATA)? || managed_process_is_running(ROLE_EVEBOX)? {
            bail!("The Windows-managed stack is already running. Use 'evectl stop' first.");
        }

        let suricata = start_suricata_background(&guid)?;
        if let Err(err) = wait_for_suricata_readiness(&suricata) {
            let _ = stop_suricata_managed();
            return Err(err);
        }

        let evebox = match start_evebox_background() {
            Ok(metadata) => metadata,
            Err(err) => {
                let _ = stop_suricata_managed();
                return Err(err);
            }
        };

        if let Err(err) = validate_background_process_started(&evebox) {
            let _ = stop_evebox_managed();
            let _ = stop_suricata_managed();
            return Err(err);
        }

        println!("Windows stack started in background");
        println!("  Suricata PID: {}", suricata.pid);
        println!("  EveBox PID:   {}", evebox.pid);
        println!("  Suricata log: {}", get_suricata_log_dir()?.display());
        println!("  EveBox log:   {}", get_evebox_log_dir()?.display());
        println!("  EveBox URL:   {}", EVEBOX_ACCESS_URL);

        Ok(())
    }

    #[cfg(windows)]
    fn stop_stack() -> Result<()> {
        let mut errors = vec![];

        if let Err(err) = stop_evebox_managed() {
            errors.push(format!("Failed to stop EveBox: {err}"));
        }

        if let Err(err) = stop_suricata_managed() {
            errors.push(format!("Failed to stop Suricata: {err}"));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            bail!("{}", errors.join("\n"))
        }
    }

    #[cfg(windows)]
    fn format_command_line(command: &std::process::Command) -> String {
        fn quote(arg: &str) -> String {
            if arg.contains([' ', '\t', '"']) {
                format!("\"{}\"", arg.replace('"', "\\\""))
            } else {
                arg.to_string()
            }
        }

        let mut parts = vec![quote(&command.get_program().to_string_lossy())];
        for arg in command.get_args() {
            parts.push(quote(&arg.to_string_lossy()));
        }
        parts.join(" ")
    }

    #[cfg(windows)]
    fn ensure_ctrlc_handler() -> Result<()> {
        let result = CTRL_C_HANDLER_SETUP.get_or_init(|| {
            ctrlc::set_handler(|| {
                CTRL_C_RECEIVED.store(true, Ordering::SeqCst);
            })
            .map_err(|err| err.to_string())
        });

        match result {
            Ok(()) => Ok(()),
            Err(err) => bail!("Failed to set Ctrl-C handler: {}", err),
        }
    }

    #[cfg(windows)]
    fn get_windows_interfaces() -> Result<Vec<WindowsInterface>> {
        use std::process::Command;

        // Use PowerShell to get network interface information
        let output = Command::new("powershell")
            .args([
                "-Command",
                "Get-NetAdapter | ForEach-Object { $adapter = $_; Get-NetIPAddress -InterfaceIndex $adapter.ifIndex | ForEach-Object { [PSCustomObject]@{ Name = $adapter.Name; IPAddress = $_.IPAddress; GUID = $adapter.InterfaceGuid } } } | ConvertTo-Json"
            ])
            .output()
            .context("Failed to execute PowerShell command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("PowerShell command failed: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse JSON output
        let interfaces: Vec<serde_json::Value> =
            serde_json::from_str(&stdout).context("Failed to parse PowerShell output as JSON")?;

        let mut result = Vec::new();
        for interface in interfaces {
            if let (Some(name), Some(ip), Some(guid)) = (
                interface["Name"].as_str(),
                interface["IPAddress"].as_str(),
                interface["GUID"].as_str(),
            ) {
                result.push(WindowsInterface {
                    name: name.to_string(),
                    ip_address: ip.to_string(),
                    guid: guid.to_string(),
                });
            }
        }

        Ok(result)
    }

    #[derive(Debug)]
    struct WindowsInterface {
        name: String,
        ip_address: String,
        guid: String,
    }
}

#[cfg(not(windows))]
mod imp {
    use clap::Parser;

    #[derive(Parser, Debug, Clone)]
    pub(crate) struct Args;
}

#[cfg(not(windows))]
pub(crate) use imp::Args;
#[cfg(windows)]
pub(crate) use imp::{Args, Commands, main};
