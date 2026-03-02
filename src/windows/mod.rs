// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

#[cfg(windows)]
mod imp {
    use crate::prelude::*;
    use clap::{Parser, Subcommand};
    use indicatif::{ProgressBar, ProgressStyle};
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    const NPCAP_VERSION: &str = "1.87";
    const SURICATA_VERSION: &str = "8.0.3-1";
    const EVEBOX_VERSION: &str = "0.23.0";
    const EVEBOX_URL: &str =
        "https://evebox.org/files/release/0.23.0/evebox-0.23.0-windows-x64.zip";
    const STATUS_CONTROL_C_EXIT: i32 = -1073741510;

    static CTRL_C_RECEIVED: AtomicBool = AtomicBool::new(false);
    static CTRL_C_HANDLER_SETUP: OnceLock<Result<(), String>> = OnceLock::new();

    #[derive(Parser, Debug, Clone)]
    pub(crate) struct Args {
        #[command(subcommand)]
        pub(crate) command: Commands,
    }

    #[derive(Subcommand, Debug, Clone)]
    pub(crate) enum Commands {
        /// Display project directories for config, rules, and logs.
        Info,

        /// Install Npcap (interactive) and then Suricata (non-interactive).
        InstallSuricata,

        /// Upgrade Suricata and upgrade Npcap when a newer bundled version is known.
        UpgradeSuricata,

        /// Uninstall EveBox (if installed), then Suricata, then Npcap.
        Uninstall,

        /// Install EveBox.
        InstallEvebox,

        /// List network interfaces with their IP addresses and GUIDs
        ListInterfaces,

        /// Start Suricata on Windows
        StartSuricata {
            /// Network interface GUID to listen on
            #[arg(long)]
            guid: Option<String>,
            /// Launch Suricata in the background
            #[arg(long)]
            background: bool,
        },

        /// Stop Suricata if running in the background
        StopSuricata,
    }

    impl Args {
        pub(crate) fn from_command(command: Commands) -> Self {
            Self { command }
        }
    }

    pub(crate) fn main(args: Args) -> Result<()> {
        match args.command {
            Commands::Info => project_info(),
            Commands::InstallSuricata => install_suricata(),
            Commands::UpgradeSuricata => upgrade_suricata(),
            Commands::Uninstall => uninstall_windows_components(),
            Commands::InstallEvebox => install_evebox(),
            Commands::ListInterfaces => list_interfaces(),
            Commands::StartSuricata { guid, background } => start_suricata(guid, background),
            Commands::StopSuricata => stop_suricata(),
        }
    }

    #[cfg(windows)]
    fn project_info() -> Result<()> {
        let config_root = dirs::config_dir()
            .ok_or_else(|| anyhow!("Could not find user config directory"))?
            .join("evectl");
        let data_root = dirs::data_local_dir()
            .ok_or_else(|| anyhow!("Could not find local data directory"))?
            .join("evectl");

        let evectl_config = config_root.join("evectl.toml");
        let suricata_config_dir = config_root.join("suricata");
        let suricata_rules_dir = suricata_config_dir.join("lib").join("rules");
        let suricata_update_dir = suricata_config_dir.join("lib").join("update");
        let suricata_update_cache_dir = suricata_update_dir.join("cache");
        let suricata_log_dir = data_root.join("suricata").join("log");
        let suricata_run_dir = data_root.join("suricata").join("run");
        let evebox_data_dir = data_root.join("evebox");

        println!("Windows path-based directories:");
        println!("  Config root:               {}", config_root.display());
        println!("  Data root:                 {}", data_root.display());
        println!();

        println!("Recommended config and rules paths:");
        println!("  EveCtl config file:        {}", evectl_config.display());
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

        println!("Recommended Suricata log/runtime paths:");
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
    fn install_msi_package(path: &std::path::Path, name: &str) -> Result<()> {
        use std::process::Command;

        info!("Installing {} from {:?}", name, path);

        let log_path =
            std::env::temp_dir().join(format!("evectl-{}-install.log", name.to_ascii_lowercase()));

        let msi_path = path.to_string_lossy().replace('\'', "''");
        let log_path_str = log_path.to_string_lossy().replace('\'', "''");

        let script = format!(
            r#"
$ErrorActionPreference = 'Stop'
$msiPath = '{}'
$logPath = '{}'
$argumentList = @('/i', $msiPath, '/qn', '/norestart', '/L*v', $logPath)
$process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $argumentList -Verb RunAs -Wait -PassThru
exit $process.ExitCode
"#,
            msi_path, log_path_str
        );

        let output = Command::new("powershell")
            .arg("-NoProfile")
            .arg("-Command")
            .arg(&script)
            .output()
            .context(format!("Failed to launch {} MSI installer", name))?;

        let stderr = String::from_utf8_lossy(&output.stderr);

        match output.status.code() {
            Some(0) => {
                info!("{} installation completed successfully", name);
                Ok(())
            }
            Some(3010) | Some(1641) => {
                warn!(
                    "{} installation completed, but a system reboot is required",
                    name
                );
                Ok(())
            }
            Some(1223) => bail!("{} installation was cancelled at the UAC prompt", name),
            Some(code) => bail!(
                "{} installer exited with code {}. MSI log: {:?}. {}",
                name,
                code,
                log_path,
                stderr.trim()
            ),
            None => bail!("{} installer terminated unexpectedly", name),
        }
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
    fn is_suricata_installed() -> bool {
        // Check if Suricata executable exists in common locations
        let common_paths = [
            r"C:\Program Files\Suricata\suricata.exe",
            r"C:\Program Files (x86)\Suricata\suricata.exe",
        ];

        for path in &common_paths {
            if std::path::Path::new(path).exists() {
                return true;
            }
        }

        // Check if Suricata service exists
        if let Ok(output) = std::process::Command::new("sc")
            .args(["query", "Suricata"])
            .output()
            && output.status.success()
        {
            return true;
        }

        // Check using where command
        if let Ok(output) = std::process::Command::new("where")
            .arg("suricata.exe")
            .output()
            && output.status.success()
        {
            return true;
        }

        false
    }

    #[cfg(windows)]
    fn install_suricata() -> Result<()> {
        download_npcap()?;
        install_or_upgrade_suricata(false)
    }

    #[cfg(windows)]
    fn upgrade_suricata() -> Result<()> {
        maybe_upgrade_npcap()?;
        maybe_upgrade_suricata()
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

        if !is_suricata_installed() {
            info!(
                "Suricata was not detected. Installing version {}...",
                SURICATA_VERSION
            );
            return install_or_upgrade_suricata(true);
        }

        let installed_version = match get_suricata_installed_version()? {
            Some(version) => version,
            None => {
                info!(
                    "Suricata is installed, but the installed version could not be determined. Skipping automatic Suricata upgrade."
                );
                return Ok(());
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
    fn suricata_version_for_comparison() -> &'static str {
        SURICATA_VERSION
            .split('-')
            .next()
            .unwrap_or(SURICATA_VERSION)
    }

    #[cfg(windows)]
    fn get_suricata_installed_version() -> Result<Option<String>> {
        use std::process::Command;

        let script = r#"
$entry = @(
    Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
    Get-ItemProperty 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
) | Where-Object { $_.DisplayName -like 'Suricata*' } | Select-Object -First 1

if ($entry -and $entry.DisplayVersion) {
    Write-Output $entry.DisplayVersion
}
"#;

        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", script])
            .output()
            .context("Failed to query installed Suricata version")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                "Failed to determine installed Suricata version: {}",
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
    fn install_or_upgrade_suricata(upgrade: bool) -> Result<()> {
        let installed = is_suricata_installed();
        if installed && !upgrade {
            info!("Suricata is already installed on this system.");
            return Ok(());
        }

        if upgrade {
            if installed {
                info!("Upgrading Suricata to version {}...", SURICATA_VERSION);

                if let Err(err) = stop_suricata() {
                    warn!("Failed to stop running Suricata processes: {}", err);
                }

                uninstall_suricata()?;
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

        // Get the user's Downloads folder
        let downloads_dir = dirs::download_dir()
            .ok_or_else(|| anyhow!("Could not find user's Downloads folder"))?;
        let msi_path = downloads_dir.join(&filename);

        // Check if file already exists
        if msi_path.exists() {
            info!("Suricata installer already exists at {:?}", msi_path);
            info!("Skipping download, using existing file");
        } else {
            download_file(&url, &msi_path, "Suricata")?;
        }

        install_msi_package(&msi_path, "Suricata")?;

        Ok(())
    }

    #[cfg(windows)]
    fn uninstall_suricata() -> Result<()> {
        use std::process::Command;

        info!("Uninstalling existing Suricata installation...");

        let script = r#"
$ErrorActionPreference = 'Stop'
$entry = @(
    Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
    Get-ItemProperty 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
) | Where-Object { $_.DisplayName -like 'Suricata*' } | Select-Object -First 1

if (-not $entry) {
    Write-Output 'NOT_FOUND'
    exit 0
}

$productCode = $entry.PSChildName
if ($productCode -match '^\{[0-9A-Fa-f\-]+\}$') {
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList '/x', $productCode, '/qn' -Wait -NoNewWindow -PassThru
    exit $process.ExitCode
}

$command = $entry.QuietUninstallString
if ([string]::IsNullOrWhiteSpace($command)) {
    $command = $entry.UninstallString
}
if ([string]::IsNullOrWhiteSpace($command)) {
    throw 'Unable to determine Suricata uninstall command'
}

if ($command -match '(?i)msiexec(\.exe)?') {
    $command = $command -replace '(?i)\s/I(?=\s|\{)', ' /X'
    if ($command -notmatch '(?i)\s/(qn|quiet|passive)\b') {
        $command = "$command /qn"
    }
}

$process = Start-Process -FilePath 'cmd.exe' -ArgumentList '/C', $command -Wait -NoNewWindow -PassThru
exit $process.ExitCode
"#;

        let output = Command::new("powershell")
            .args(["-Command", script])
            .output()
            .context("Failed to execute Suricata uninstall command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Suricata uninstall failed: {}", stderr.trim());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("NOT_FOUND") {
            info!("Suricata uninstall entry not found. Skipping Suricata uninstall.");
            return Ok(());
        }

        info!("Existing Suricata uninstall completed");
        Ok(())
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
        Ok(dirs::data_local_dir()
            .ok_or_else(|| anyhow!("Could not find local data directory"))?
            .join("evectl")
            .join("evebox"))
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
    fn uninstall_windows_components() -> Result<()> {
        let mut errors: Vec<String> = vec![];

        if let Err(err) = uninstall_evebox() {
            errors.push(format!("EveBox uninstall failed: {}", err));
        }

        if let Err(err) = stop_suricata() {
            warn!(
                "Failed to stop Suricata before uninstall, continuing: {}",
                err
            );
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
        let url = EVEBOX_URL;

        // Create project-specific data directory
        let data_dir = get_evebox_data_dir()?;

        // Create directory if it doesn't exist
        std::fs::create_dir_all(&data_dir).context("Failed to create EveBox data directory")?;

        // Check if EveBox is already installed in the data directory
        let evebox_exe = data_dir.join("evebox.exe");
        if evebox_exe.exists() {
            info!(
                "EveBox {} is already installed at {:?}",
                EVEBOX_VERSION, evebox_exe
            );
            return Ok(());
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

        info!(
            "EveBox {} installed successfully at {:?}",
            EVEBOX_VERSION, data_dir
        );
        info!("You can run EveBox from: {:?}", evebox_exe);

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
    fn start_suricata(guid: Option<String>, background: bool) -> Result<()> {
        use std::process::Command;

        // Check if Suricata is already running
        let output = Command::new("powershell")
            .args([
                "-Command",
                "try { Get-Process -Name 'suricata' -ErrorAction Stop | Select-Object Id, ProcessName, StartTime | ConvertTo-Json } catch { '[]' }"
            ])
            .output()
            .context("Failed to execute PowerShell command")?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let processes_json = stdout.trim();

            if processes_json != "[]" && !processes_json.is_empty() {
                let process_count = if processes_json.starts_with('{') {
                    1
                } else {
                    let processes: Vec<serde_json::Value> =
                        serde_json::from_str(processes_json).unwrap_or_default();
                    processes.len()
                };

                if process_count > 0 {
                    bail!(
                        "Suricata is already running ({} process(es) found). Use 'evectl stop-suricata' to stop it first.",
                        process_count
                    );
                }
            }
        }

        // Check if Suricata is installed
        if !is_suricata_installed() {
            bail!(
                "Suricata is not installed. Please install it first using 'evectl install-suricata'"
            );
        }

        let suricata_path = r"C:\Program Files\Suricata\suricata.exe";
        if !std::path::Path::new(suricata_path).exists() {
            bail!("Suricata executable not found at {}", suricata_path);
        }

        // Get the interface GUID to use
        let interface_guid = match guid {
            Some(g) => g,
            None => {
                // Prompt user to select an interface
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

                let choices: Vec<String> =
                    selections.iter().map(|(_, name)| name.clone()).collect();
                let selection =
                    inquire::Select::new("Select network interface to listen on:", choices)
                        .prompt()?;

                // Find the GUID for the selected interface

                selections
                    .iter()
                    .find(|(_, name)| name == &selection)
                    .map(|(guid, _)| guid.clone())
                    .ok_or_else(|| anyhow!("Failed to find GUID for selected interface"))?
            }
        };

        info!("Starting Suricata on interface GUID: {}", interface_guid);

        let suricata_log_dir = dirs::data_local_dir()
            .ok_or_else(|| anyhow!("Could not find local data directory"))?
            .join("evectl")
            .join("suricata")
            .join("log");
        std::fs::create_dir_all(&suricata_log_dir).context(format!(
            "Failed to create Suricata log directory {}",
            suricata_log_dir.display()
        ))?;
        info!("Logs will be written to {}", suricata_log_dir.display());

        // Convert GUID to NPCAP device name format
        let npcap_device = format!("\\Device\\NPF_{}", interface_guid);
        info!("Using NPCAP device: {}", npcap_device);

        // Build the Suricata command
        let mut command = Command::new(suricata_path);
        command.arg("-i");
        command.arg(&npcap_device);
        command.arg("-l");
        command.arg(&suricata_log_dir);
        info!("Running command: {}", format_command_line(&command));

        // Run Suricata
        if background {
            let child = command.spawn()?;
            println!("Suricata started in background with PID {}", child.id());
            Ok(())
        } else {
            ensure_ctrlc_handler()?;
            CTRL_C_RECEIVED.store(false, Ordering::SeqCst);

            let mut child = command.spawn().context("Failed to start Suricata")?;

            loop {
                if let Some(status) = child.try_wait()? {
                    let ctrl_c = CTRL_C_RECEIVED.swap(false, Ordering::SeqCst);
                    let ctrl_c_exit = status
                        .code()
                        .is_some_and(|code| code == STATUS_CONTROL_C_EXIT);

                    if status.success() || (ctrl_c && ctrl_c_exit) {
                        return Ok(());
                    }

                    bail!("Suricata exited with status: {}", status);
                }

                std::thread::sleep(Duration::from_millis(100));
            }
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

    #[cfg(windows)]
    fn stop_suricata() -> Result<()> {
        use std::process::Command;

        info!("Looking for running Suricata processes...");

        // Use PowerShell to find Suricata processes
        let output = Command::new("powershell")
            .args([
                "-Command",
                "try { Get-Process -Name 'suricata' -ErrorAction Stop | Select-Object Id, ProcessName, StartTime | ConvertTo-Json } catch { '[]' }"
            ])
            .output()
            .context("Failed to execute PowerShell command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("PowerShell command failed: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Check if any Suricata processes were found
        if stdout.trim() == "[]" || stdout.trim().is_empty() {
            info!("No running Suricata processes found");
            return Ok(());
        }

        // Parse the JSON output to get process IDs
        let processes_json = stdout.trim();
        let processes: Vec<serde_json::Value> = if processes_json.starts_with('{') {
            // Single process returned as an object
            vec![serde_json::from_str(processes_json)?]
        } else {
            serde_json::from_str(processes_json)?
        };

        if processes.is_empty() {
            info!("No running Suricata processes found");
            return Ok(());
        }

        info!("Found {} Suricata process(es)", processes.len());

        // Stop each Suricata process
        for process in processes {
            if let Some(pid) = process["Id"].as_u64() {
                info!("Stopping Suricata process with PID: {}", pid);

                // Use taskkill to stop the process
                let status = Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F"])
                    .status()
                    .context(format!("Failed to stop process {}", pid))?;

                if status.success() {
                    info!("Successfully stopped Suricata process with PID: {}", pid);
                } else {
                    warn!("Failed to stop Suricata process with PID: {}", pid);
                }
            }
        }

        info!("Suricata stop operation completed");
        Ok(())
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
