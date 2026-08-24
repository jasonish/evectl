// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use std::{
    env,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

#[cfg(target_os = "windows")]
use anyhow::{Context as _, anyhow};
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum SelfUpdate {
    Unchanged,
    Updated(PathBuf),
}

/// True if the executable lives in this project's Cargo target
/// directory, i.e. is a development build.
pub(crate) fn is_cargo_target_exe(exe: &Path) -> bool {
    let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") else {
        return false;
    };

    let target_dir = match fs::canonicalize(Path::new(manifest_dir).join("target")) {
        Ok(path) => path,
        Err(_) => return false,
    };

    match fs::canonicalize(exe) {
        Ok(exe) => exe.starts_with(&target_dir),
        Err(_) => false,
    }
}

/// The running executable, if it's one uninstall may remove: a
/// development build in the Cargo target directory is left alone.
pub(crate) fn removable_exe() -> Option<PathBuf> {
    let exe = env::current_exe().ok()?;
    if is_cargo_target_exe(&exe) {
        info!(
            "Not removing development binary {}, remove it manually",
            exe.display()
        );
        return None;
    }
    Some(exe)
}

fn should_skip_update_check() -> bool {
    if env::var("CARGO").is_ok() || env::var_os("EVECTL_SKIP_UPDATE_CHECK").is_some() {
        return true;
    }

    match env::current_exe() {
        Ok(exe) => is_cargo_target_exe(&exe),
        Err(_) => false,
    }
}

pub(crate) fn self_update() -> Result<SelfUpdate> {
    if should_skip_update_check() {
        info!("Skipping self-update check for this executable");
        return Ok(SelfUpdate::Unchanged);
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
    let response = crate::http::client_builder()
        .build()?
        .get(&hash_url)
        .send()?;
    if response.status().as_u16() != 200 {
        error!(
            "Failed to fetch remote checksum: HTTP status code={}",
            response.status(),
        );
        bail!("Failed to fetch remote checksum");
    }

    let remote_hash_text = response.text()?;
    let remote_hash = parse_sha256_hash(&remote_hash_text)
        .ok_or_else(|| anyhow::anyhow!("Remote checksum response was invalid"))?;
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
                return Ok(SelfUpdate::Unchanged);
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
        bail!("Downloaded file has invalid checksum");
    }

    info!("Preparing updated executable");
    download_exe.seek(SeekFrom::Start(0))?;
    replace_current_executable(&current_exe, &mut download_exe)?;

    #[cfg(target_os = "windows")]
    warn!(
        "An EveCtl update has been downloaded and staged. It will be applied on the next start. Re-run your command after that run completes."
    );

    #[cfg(not(target_os = "windows"))]
    warn!("The EveCtl program has been updated.");

    Ok(SelfUpdate::Updated(current_exe))
}

#[cfg(target_os = "windows")]
pub(crate) fn apply_staged_update_on_startup() -> Result<bool> {
    use std::process::Command;

    let current_exe = match env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            warn!(
                "Failed to determine executable path for staged update: {}",
                err
            );
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

    let script = r#"
$target = $env:EVECTL_SELF_UPDATE_TARGET
$staged = $env:EVECTL_SELF_UPDATE_STAGED

for ($i = 0; $i -lt 120; $i++) {
    try {
        Copy-Item -LiteralPath $staged -Destination $target -Force
        Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        exit 0
    } catch {
        Start-Sleep -Milliseconds 250
    }
}

exit 1
"#;

    Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", script])
        .env("EVECTL_SELF_UPDATE_TARGET", &current_exe)
        .env("EVECTL_SELF_UPDATE_STAGED", &staged_path)
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
    let mut response = crate::http::client_builder().build()?.get(url).send()?;
    let mut dest = tempfile::tempfile()?;
    io::copy(&mut response, &mut dest)?;
    dest.seek(SeekFrom::Start(0))?;
    Ok(dest)
}

fn file_checksum(file: &mut File) -> Result<String> {
    let mut hash = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
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

#[cfg(all(not(target_os = "windows"), not(target_os = "linux")))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}
