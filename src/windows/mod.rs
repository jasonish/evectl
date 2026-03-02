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
    const SURICATA_SYSTEM_EXE_PATHS: [&str; 2] = [
        r"C:\Program Files\Suricata\suricata.exe",
        r"C:\Program Files (x86)\Suricata\suricata.exe",
    ];
    const SURICATA_SYSTEM_INSTALL_DIRS: [&str; 2] = [
        r"C:\Program Files\Suricata",
        r"C:\Program Files (x86)\Suricata",
    ];
    const SURICATA_VERSION_MARKER: &str = ".evectl-suricata-version";
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

        /// Upgrade EveCtl itself, and bundled Windows components (Npcap and Suricata) when newer.
        #[command(alias = "upgrade-suricata")]
        Upgrade,

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
            Commands::Upgrade => upgrade_suricata(),
            Commands::Uninstall => uninstall_windows_components(),
            Commands::InstallEvebox => install_evebox(),
            Commands::ListInterfaces => list_interfaces(),
            Commands::StartSuricata { guid, background } => start_suricata(guid, background),
            Commands::StopSuricata => stop_suricata(),
        }
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
        let evebox_exe = evebox_data_dir.join("evebox.exe");
        let evectl_exe = std::env::current_exe().ok();

        println!("Windows path-based directories:");
        println!("  Data root:                 {}", data_root.display());
        if let Some(evectl_exe) = &evectl_exe {
            println!("  Current EveCtl binary:     {}", evectl_exe.display());
        } else {
            println!("  Current EveCtl binary:     <unknown>");
        }
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

        println!("Recommended Suricata paths:");
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
        if evebox_exe.exists() {
            println!("  Current EveBox binary:     {}", evebox_exe.display());
        } else {
            println!(
                "  Current EveBox binary:     {} (not installed)",
                evebox_exe.display()
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
    fn get_suricata_data_dir() -> Result<std::path::PathBuf> {
        Ok(get_evectl_data_dir()?.join("suricata"))
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
    fn install_suricata() -> Result<()> {
        download_npcap()?;
        install_or_upgrade_suricata(false)
    }

    #[cfg(windows)]
    fn upgrade_suricata() -> Result<()> {
        maybe_upgrade_npcap()?;
        maybe_upgrade_suricata()?;

        if let Err(err) = crate::selfupdate::self_update() {
            warn!("Failed to self-upgrade EveCtl: {}", err);
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
                let evectl_install_exists = get_suricata_exe_path()
                    .map(|path| path.exists())
                    .unwrap_or(false);

                if evectl_install_exists {
                    info!(
                        "Suricata is installed in the evectl-managed directory, but the version could not be determined. Reinstalling bundled version {}.",
                        SURICATA_VERSION
                    );
                    return install_or_upgrade_suricata(true);
                }

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
        let evectl_install_exists = get_suricata_exe_path()
            .map(|path| path.exists())
            .unwrap_or(false);

        if evectl_install_exists && !upgrade {
            info!("Suricata is already installed in the evectl-managed directory.");
            return Ok(());
        }

        if installed
            && !upgrade
            && let Ok(install_dir) = get_suricata_install_dir()
        {
            info!(
                "A system Suricata installation was detected. Installing an evectl-managed copy into {}.",
                install_dir.display()
            );
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
    fn cleanup_suricata_leftovers() -> Result<()> {
        use std::process::Command;

        let mut errors = vec![];
        let mut install_dirs: Vec<std::path::PathBuf> = SURICATA_SYSTEM_INSTALL_DIRS
            .iter()
            .map(std::path::PathBuf::from)
            .collect();

        if let Ok(evectl_install_dir) = get_suricata_install_dir() {
            install_dirs.push(evectl_install_dir);
        }

        for path in &install_dirs {
            if !path.exists() {
                continue;
            }

            info!("Removing Suricata directory {}", path.display());

            if let Err(err) = std::fs::remove_dir_all(path) {
                warn!(
                    "Failed to remove {} directly: {}. Trying PowerShell cleanup...",
                    path.display(),
                    err
                );

                let escaped = path.to_string_lossy().replace('\'', "''");
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
                        errors.push(format!("{}: {}", path.display(), stderr.trim()));
                    }
                    Err(ps_err) => {
                        errors.push(format!("{}: {}", path.display(), ps_err));
                    }
                }
            }
        }

        if !errors.is_empty() {
            bail!(
                "Failed to remove Suricata leftover files:\n- {}",
                errors.join("\n- ")
            );
        }

        let mut leftover_paths: Vec<String> = SURICATA_SYSTEM_EXE_PATHS
            .iter()
            .filter(|path| std::path::Path::new(path).exists())
            .map(|path| path.to_string())
            .collect();

        if let Ok(path) = get_suricata_exe_path()
            && path.exists()
        {
            leftover_paths.push(path.display().to_string());
        }

        if !leftover_paths.is_empty() {
            bail!(
                "Suricata uninstall completed, but these executables still exist:\n- {}",
                leftover_paths.join("\n- ")
            );
        }

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
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList '/x', $productCode, '/qn' -Verb RunAs -Wait -PassThru
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

$process = Start-Process -FilePath 'cmd.exe' -ArgumentList '/C', $command -Verb RunAs -Wait -PassThru
exit $process.ExitCode
"#;

        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", script])
            .output()
            .context("Failed to execute Suricata uninstall command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Suricata uninstall failed: {}", stderr.trim());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("NOT_FOUND") {
            info!(
                "Suricata uninstall entry not found. Attempting file-system cleanup of known install paths."
            );
        } else {
            info!("Existing Suricata uninstall completed");
        }

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

        let suricata_path = find_suricata_executable()
            .ok_or_else(|| anyhow!("Suricata executable not found in expected locations"))?;
        let suricata_dir = suricata_path
            .parent()
            .ok_or_else(|| anyhow!("Failed to determine Suricata installation directory"))?
            .to_path_buf();

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

        let suricata_log_dir = get_suricata_data_dir()?.join("log");
        std::fs::create_dir_all(&suricata_log_dir).context(format!(
            "Failed to create Suricata log directory {}",
            suricata_log_dir.display()
        ))?;
        info!("Logs will be written to {}", suricata_log_dir.display());

        // Convert GUID to NPCAP device name format
        let npcap_device = format!("\\Device\\NPF_{}", interface_guid);
        info!("Using NPCAP device: {}", npcap_device);

        // Build the Suricata command
        let mut command = Command::new(&suricata_path);
        let suricata_config = suricata_dir.join("suricata.yaml");
        if suricata_config.exists() {
            command.arg("-c");
            command.arg(&suricata_config);
        }
        command.current_dir(&suricata_dir);
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
