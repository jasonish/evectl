// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use std::io::Write;

const SURICATA_URL: &str =
    "https://www.openinfosecfoundation.org/download/windows/Suricata-7.0.8-1-64bit.msi";
const SURICATA_PATH: &str = "C:\\Program Files\\Suricata\\suricata.exe";

const NPCAP_URL: &str = "https://npcap.com/dist/npcap-1.80.exe";

const NPCAP_TEST_PATH: &str = "C:\\Program Files\\Npcap\\Uninstall.exe";

pub(crate) fn main() -> Result<()> {
    if !evectl::system::is_admin() {
        bail!("This command must be run as an administrator.");
    }

    let mut require_npcap_intall = true;
    if std::path::Path::new(NPCAP_TEST_PATH).exists() {
        info!("Npcap already installed.");
        require_npcap_intall = false;
    }
    if require_npcap_intall {
        fetch_install_npcap()?;
    }

    let mut require_suricata_install = true;
    if let Some(version) = get_suricata_version() {
        info!("Found Suricata version: {}", version);
        require_suricata_install = false;
    }
    if require_suricata_install {
        fetch_install_suricata()?;
    }

    Ok(())
}

fn get_suricata_version() -> Option<String> {
    if std::path::Path::new(SURICATA_PATH).exists() {
        let output = std::process::Command::new(SURICATA_PATH)
            .arg("-V")
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let re = regex::Regex::new(r"(\d+\.\d+\.\d+)").ok()?;
        let version = re.captures(&stdout).unwrap();
        let version = version.get(1).unwrap().as_str();
        return Some(version.to_string());
    }
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
        .args(["/i", "suricata.msi"])
        .status()?;
    let _ = std::fs::remove_file(".\\suricata.msi");
    Ok(())
}

fn fetch_install_npcap() -> Result<()> {
    let mut file = std::fs::File::create("npcap.exe")?;
    reqwest::blocking::get(NPCAP_URL)?
        .error_for_status()?
        .copy_to(&mut file)?;
    file.flush()?;
    std::mem::drop(file);
    info!("npcap downloaded, installing...");
    std::process::Command::new(".\\npcap.exe").status()?;
    let _ = std::fs::remove_file(".\\npcap.exe");
    Ok(())
}

fn _print_directories() {
    let pd = directories::ProjectDirs::from("org", "evebox", "evectl");
    dbg!(&pd);

    let ud = directories::UserDirs::new();
    dbg!(ud);

    let bd = directories::BaseDirs::new();
    dbg!(bd);
}
