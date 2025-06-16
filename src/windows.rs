// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

#[cfg(windows)]
mod imp {
    use crate::prelude::*;
    use clap::{Parser, Subcommand};
    use indicatif::{ProgressBar, ProgressStyle};

    const NPCAP_VERSION: &str = "1.82";
    const SURICATA_VERSION: &str = "8.0.2-1";
    const EVEBOX_VERSION: &str = "0.22.0";

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
    }

    pub(crate) fn main(args: Args) -> Result<()> {
        match args.command {
            Commands::InstallNpcap => download_npcap(),
            Commands::InstallSuricata => install_suricata(),
            Commands::InstallEvebox => install_evebox(),
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
