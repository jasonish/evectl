// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

#[cfg(windows)]
mod imp {
    use crate::prelude::*;
    use clap::{Parser, Subcommand};
    use indicatif::{ProgressBar, ProgressStyle};
    use inquire;
    use serde_json;

    const NPCAP_VERSION: &str = "1.82";
    const SURICATA_VERSION: &str = "7.0.10-1";
    const EVEBOX_VERSION: &str = "0.20.5";

    #[derive(Parser, Debug, Clone)]
    pub(crate) struct Args {
        #[command(subcommand)]
        command: Commands,
    }

    #[derive(Subcommand, Debug, Clone)]
    enum Commands {
        /// Install Npcap on Windows
        InstallNpcap,

        /// Install Suricata.
        InstallSuricata,

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

    pub(crate) fn main(args: Args) -> Result<()> {
        match args.command {
            Commands::InstallNpcap => download_npcap(),
            Commands::InstallSuricata => install_suricata(),
            Commands::InstallEvebox => install_evebox(),
            Commands::ListInterfaces => list_interfaces(),
            Commands::StartSuricata { guid, background } => start_suricata(guid, background),
            Commands::StopSuricata => stop_suricata(),
        }
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
        #[cfg(windows)]
        {
            // Check if Npcap is already installed
            if is_npcap_installed() {
                info!("Npcap is already installed on this system.");
                return Ok(());
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
        use windows::core::PCWSTR;
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

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
    fn is_npcap_installed() -> bool {
        // Check if npcap driver service exists
        if let Ok(output) = std::process::Command::new("sc")
            .args(["query", "npcap"])
            .output()
        {
            if output.status.success() {
                return true;
            }
        }

        // Check for Npcap installation folder
        let npcap_paths = [r"C:\Program Files\Npcap", r"C:\Program Files (x86)\Npcap"];

        for path in &npcap_paths {
            if std::path::Path::new(path).exists() {
                return true;
            }
        }

        false
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
        {
            if output.status.success() {
                return true;
            }
        }

        // Check using where command
        if let Ok(output) = std::process::Command::new("where")
            .arg("suricata.exe")
            .output()
        {
            if output.status.success() {
                return true;
            }
        }

        false
    }

    #[cfg(windows)]
    fn install_suricata() -> Result<()> {
        #[cfg(windows)]
        {
            // Check if Suricata is already installed
            if is_suricata_installed() {
                info!("Suricata is already installed on this system.");
                return Ok(());
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

        info!("Launching Suricata installer...");

        #[cfg(windows)]
        {
            launch_windows_installer(&msi_path, "Suricata", false)?;
            wait_for_installer_completion()?;
        }

        #[cfg(not(windows))]
        {
            bail!("Not supported on non-Windows platforms.");
        }

        Ok(())
    }

    #[cfg(windows)]
    fn install_evebox() -> Result<()> {
        let url = format!(
            "https://evebox.org/files/release/latest/evebox-{}-windows-x64.zip",
            EVEBOX_VERSION
        );

        // Create project-specific data directory
        let data_dir = dirs::data_local_dir()
            .ok_or_else(|| anyhow!("Could not find local data directory"))?
            .join("evectl")
            .join("evebox");

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

        download_file(&url, &zip_path, "EveBox")?;

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
                if let Some(p) = outpath.parent() {
                    if !p.exists() {
                        std::fs::create_dir_all(p)?;
                    }
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
                    let processes: Vec<serde_json::Value> = serde_json::from_str(processes_json)
                        .unwrap_or_default();
                    processes.len()
                };
                
                if process_count > 0 {
                    bail!("Suricata is already running ({} process(es) found). Use 'evectl windows stop-suricata' to stop it first.", process_count);
                }
            }
        }

        // Check if Suricata is installed
        if !is_suricata_installed() {
            bail!("Suricata is not installed. Please install it first using 'evectl windows install-suricata'");
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

                let choices: Vec<String> = selections.iter().map(|(_, name)| name.clone()).collect();
                let selection = inquire::Select::new("Select network interface to listen on:", choices).prompt()?;
                
                // Find the GUID for the selected interface
                let selected_guid = selections.iter()
                    .find(|(_, name)| name == &selection)
                    .map(|(guid, _)| guid.clone())
                    .ok_or_else(|| anyhow!("Failed to find GUID for selected interface"))?;
                
                selected_guid
            }
        };

        info!("Starting Suricata on interface GUID: {}", interface_guid);
        info!("Logs will be written to current directory");

        // Convert GUID to NPCAP device name format
        let npcap_device = format!("\\Device\\NPF_{}", interface_guid);
        info!("Using NPCAP device: {}", npcap_device);

        // Build the Suricata command
        let mut command = Command::new(suricata_path);
        command.arg("-i");
        command.arg(&npcap_device);
        command.arg("-l");
        command.arg(".");

        // Run Suricata
        if background {
            let child = command.spawn()?;
            println!("Suricata started in background with PID {}", child.id());
            Ok(())
        } else {
            let status = command.status()?;
            if !status.success() {
                bail!("Suricata exited with status: {}", status);
            }
            Ok(())
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
        let interfaces: Vec<serde_json::Value> = serde_json::from_str(&stdout)
            .context("Failed to parse PowerShell output as JSON")?;

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

    pub(crate) fn main(_args: Args) -> crate::Result<()> {
        Ok(())
    }
}

pub(crate) use imp::{main, Args};
