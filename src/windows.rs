// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use std::io::Write;

const SURICATA_URL: &str =
    "https://www.openinfosecfoundation.org/download/windows/Suricata-7.0.8-1-64bit.msi";

const NPCAP_URL: &str = "https://npcap.com/dist/npcap-1.80.exe";

pub(crate) fn main() -> Result<()> {
    fetch_install_npcap()?;
    Ok(())
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
    let mut file = std::fs::File::create("npcap.exe")?;
    reqwest::blocking::get(NPCAP_URL)?
        .error_for_status()?
        .copy_to(&mut file)?;
    file.flush()?;
    std::mem::drop(file);
    std::process::Command::new("npcap.exe").status()?;

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
