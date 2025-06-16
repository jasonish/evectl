// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

#[cfg(windows)]
mod imp {
    use crate::prelude::*;
    use clap::{Parser, Subcommand};
    use indicatif::{ProgressBar, ProgressStyle};

    const NPCAP_VERSION: &str = "1.82";
    const SURICATA_VERSION: &str = "7.0.10-1";

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
    }

    pub(crate) fn main(args: Args) -> Result<()> {
        match args.command {
            Commands::InstallNpcap => download_npcap(),
            Commands::InstallSuricata => install_suricata(),
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
        let downloads_dir =
            dirs::download_dir().ok_or_else(|| anyhow!("Could not find user's Downloads folder"))?;
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

pub(crate) use imp::{Args, main};
