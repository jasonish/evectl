// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use std::{
    env,
    fs::{self, File},
    io::{self, Seek, SeekFrom},
    path::Path,
};

#[cfg(target_os = "windows")]
use anyhow::{Context as _, anyhow};
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};

// Ok, the return type is a bit odd as this handles a lot of the error
// handling itself. An `Err` is an error that should be logged by the
// caller.  Ok(()) is success, including "no update available".
pub(crate) fn self_update() -> Result<()> {
    // If we're running from cargo, don't self update.
    if env::var("CARGO").is_ok() {
        info!("Not self updating as we are running from Cargo");
        return Ok(());
    }

    let url = release_url();
    let hash_url = format!("{}.sha256", url);
    let current_exe = if let Ok(exe) = env::current_exe() {
        exe
    } else {
        bail!("Failed to determine executable name, cannot self-update");
    };

    info!("Current running executable: {}", current_exe.display());

    info!("Calculating checksum of current executable");
    let current_hash = match current_checksum(&current_exe) {
        Err(err) => {
            warn!("Failed to calculate checksum of current exec: {}", err);
            None
        }
        Ok(checksum) => Some(checksum),
    };

    info!("Downloading {}", &hash_url);
    let response = reqwest::blocking::get(&hash_url)?;
    if response.status().as_u16() != 200 {
        error!(
            "Failed to fetch remote checksum: HTTP status code={}",
            response.status(),
        );
        return Ok(());
    }

    let remote_hash_text = response.text()?;
    let remote_hash = match parse_sha256_hash(&remote_hash_text) {
        Some(checksum) => checksum,
        None => {
            error!("Remote checksum response was invalid");
            return Ok(());
        }
    };
    debug!("Remote SHA256 checksum: {}", &remote_hash);

    match current_hash {
        None => {
            info!("Failed to determine checksum of current exe, updating");
        }
        Some(checksum) => {
            if checksum != remote_hash {
                info!("Remote checksum different than current exe, will update");
            } else {
                info!("No update available");
                return Ok(());
            }
        }
    }

    info!("Downloading {}", &url);
    let mut download_exe = download_release(&url)?;

    // Verify the checksum.
    let hash = file_checksum(&mut download_exe)?;
    debug!(
        "Locally calculated SHA256 checksum for downloaded file: {}",
        &hash
    );
    if hash != remote_hash {
        error!("Downloaded file has invalid checksum, not updating");
        error!("- Expected {}", remote_hash);
        return Ok(());
    }

    info!("Preparing updated executable");
    download_exe.seek(SeekFrom::Start(0))?;
    replace_current_executable(&current_exe, &mut download_exe)?;

    #[cfg(target_os = "windows")]
    {
        warn!(
            "An EveCtl update has been downloaded and staged. It will be applied on the next start."
        );
        return Ok(());
    }

    #[cfg(not(target_os = "windows"))]
    {
        warn!("The EveCtl program has been updated. Please restart.");
        std::process::exit(0);
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn apply_staged_update_on_startup() -> Result<bool> {
    use std::process::Command;

    let current_exe = match env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            warn!("Failed to determine executable path for staged update: {}", err);
            return Ok(false);
        }
    };

    let file_name = current_exe
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("Failed to determine executable filename"))?;

    let staged_path = current_exe.with_file_name(format!("{}.new", file_name));
    if !staged_path.exists() {
        return Ok(false);
    }

    let relaunch_args: Vec<String> = env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let relaunch_args_json = serde_json::to_string(&relaunch_args)?;

    let script = r#"
$target = $env:EVECTL_SELF_UPDATE_TARGET
$staged = $env:EVECTL_SELF_UPDATE_STAGED
$workingDir = $env:EVECTL_SELF_UPDATE_WORKDIR
$argsJson = $env:EVECTL_SELF_UPDATE_ARGS_JSON
$argList = @()

if ($argsJson) {
    try {
        $parsed = ConvertFrom-Json -InputObject $argsJson
        if ($null -ne $parsed) {
            if ($parsed -is [System.Array]) {
                $argList = @($parsed)
            } else {
                $argList = @([string]$parsed)
            }
        }
    } catch {
    }
}

for ($i = 0; $i -lt 120; $i++) {
    try {
        Copy-Item -LiteralPath $staged -Destination $target -Force
        Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        if ($workingDir) {
            Start-Process -FilePath $target -ArgumentList $argList -WorkingDirectory $workingDir | Out-Null
        } else {
            Start-Process -FilePath $target -ArgumentList $argList | Out-Null
        }
        exit 0
    } catch {
        Start-Sleep -Milliseconds 250
    }
}

exit 1
"#;

    let mut command = Command::new("powershell");
    command
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", script])
        .env("EVECTL_SELF_UPDATE_TARGET", &current_exe)
        .env("EVECTL_SELF_UPDATE_STAGED", &staged_path)
        .env("EVECTL_SELF_UPDATE_ARGS_JSON", &relaunch_args_json);

    if let Ok(working_dir) = env::current_dir() {
        command.env("EVECTL_SELF_UPDATE_WORKDIR", working_dir);
    }

    command
        .spawn()
        .context("Failed to launch Windows staged self-update helper")?;

    Ok(true)
}

#[cfg(target_os = "windows")]
fn release_url() -> String {
    // Windows builds are published as evectl.exe under the GNU target path.
    "https://evebox.org/files/evectl/x86_64-pc-windows-gnu/evectl.exe".to_string()
}

#[cfg(not(target_os = "windows"))]
fn release_url() -> String {
    let target = env!("TARGET");
    format!("https://evebox.org/files/evectl/{}/evectl", target)
}

fn parse_sha256_hash(input: &str) -> Option<String> {
    let hash = input.split_whitespace().next()?.trim();
    if hash.len() != 64 || !hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    Some(hash.to_lowercase())
}

fn download_release(url: &str) -> Result<File> {
    let mut response = reqwest::blocking::get(url)?;
    let mut dest = tempfile::tempfile()?;
    io::copy(&mut response, &mut dest)?;
    dest.seek(SeekFrom::Start(0))?;
    Ok(dest)
}

fn file_checksum(file: &mut File) -> Result<String> {
    let mut hash = Sha256::new();
    io::copy(file, &mut hash)?;
    let hash = hash.finalize();
    Ok(format!("{:x}", hash))
}

fn current_checksum(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    file_checksum(&mut file)
}

#[cfg(target_os = "windows")]
fn replace_current_executable(current_exe: &Path, download_exe: &mut File) -> Result<()> {
    let file_name = current_exe
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("Failed to determine executable filename"))?;

    let staged_path = current_exe.with_file_name(format!("{}.new", file_name));
    let mut staged_exe = fs::File::create(&staged_path)?;
    io::copy(download_exe, &mut staged_exe)?;
    staged_exe.sync_all()?;

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn replace_current_executable(current_exe: &Path, download_exe: &mut File) -> Result<()> {
    if let Err(err) = fs::remove_file(current_exe) {
        warn!(
            "Failed to remove current exe: {}: {}",
            current_exe.display(),
            err
        );
    }

    let mut final_exec = fs::File::create(current_exe)?;
    io::copy(download_exe, &mut final_exec)?;
    make_executable(current_exe)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::prelude::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o0755))?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}
