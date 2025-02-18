// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use std::io::Write;

const SURICATA_URL: &str =
    "https://www.openinfosecfoundation.org/download/windows/Suricata-7.0.8-1-64bit.msi";

const NPCAP_URL: &str = "https://npcap.com/dist/npcap-1.80.exe";

pub(crate) fn main() -> Result<()> {
    unsafe {
        let is_admin = windows_sys::Win32::UI::Shell::IsUserAnAdmin() == 1;
        if !is_admin {
            bail!("This command must be run as an administrator.");
        }
    }

    let path = "C:\\Program Files\\Suricata\\suricata.exe";
    if std::path::Path::new(path).exists() {
        let output = std::process::Command::new(path).arg("-V").output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let re = regex::Regex::new(r"(\d+\.\d+\.\d+)")?;
        let version = re.captures(&stdout).unwrap();
        let version = version.get(1).unwrap().as_str();
        info!("Found Suricata version: {}", version);
        info!("Suricata already installed.");
        return Ok(());
    }

    //fetch_install_npcap()?;
    fetch_install_suricata()?;
    Ok(())
}

fn get_suricata_version() -> Option<String> {
    let path = "C:\\Program Files\\Suricata\\suricata.exe";
    None
}

fn fetch_install_suricata() -> Result<()> {
    let mut file = std::fs::File::create("suricata.msi")?;
    reqwest::blocking::get(SURICATA_URL)?
        .error_for_status()?
        .copy_to(&mut file)?;
    file.flush()?;
    std::mem::drop(file);
    std::process::Command::new("msiexec")
        .args(&["/i", "suricata.msi"])
        .status()?;

    Ok(())
}

fn fetch_install_npcap() -> Result<()> {
    // Check if C:\Program Files\Npcap\Uninstall.exe exists.
    if std::path::Path::new("C:\\Program Files\\Npcap\\Uninstall.exe").exists() {
        info!("npcap already installed.");
        return Ok(());
    }

    let mut file = std::fs::File::create("npcap.exe")?;
    reqwest::blocking::get(NPCAP_URL)?
        .error_for_status()?
        .copy_to(&mut file)?;
    file.flush()?;
    std::mem::drop(file);
    info!("npcap downloaded, installing...");
    std::process::Command::new(".\\npcap.exe").status()?;

    Ok(())
}

fn print_directories() {
    let pd = directories::ProjectDirs::from("org", "evebox", "evectl");
    dbg!(&pd);

    let ud = directories::UserDirs::new();
    dbg!(ud);

    let bd = directories::BaseDirs::new();
    dbg!(bd);
}
