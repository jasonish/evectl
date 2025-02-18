// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT


use crate::prelude::*;

const URL: &str =
    "https://www.openinfosecfoundation.org/download/windows/Suricata-7.0.8-1-64bit.msi";

pub(crate) fn main() -> Result<()> {
    let pd = directories::ProjectDirs::from("org", "evebox", "evectl");
    dbg!(&pd);

    let ud = directories::UserDirs::new();
    dbg!(ud);

    let bd = directories::BaseDirs::new();
    dbg!(bd);

    evectl::system::get_interfaces()?;

    // let mut file = std::fs::File::create("suricata.msi")?;
    // reqwest::blocking::get(URL)?
    //     .error_for_status()?
    //     .copy_to(&mut file)?;
    // file.flush()?;
    // std::mem::drop(file);
    // std::process::Command::new("msiexec")
    //     .args(&["/i", "suricata.msi"])
    //     .status()?;

    Ok(())
}
