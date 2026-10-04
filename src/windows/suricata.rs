// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Suricata installation, configuration, and launch.

use super::install::download_file;
use super::paths::{Paths, ensure_dir, load_evectl_config};
use super::runtime::{
    Role, RuntimeMetadata, is_pid_running, launch_managed, list_named_processes,
    managed_process_is_running, powershell, powershell_output, process_matches_exe,
    stop_managed_process,
};
use super::version::compare_versions;
use crate::prelude::*;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const SURICATA_VERSION: &str = "8.0.6-1";
const SURICATA_SYSTEM_EXE_PATHS: [&str; 2] = [
    r"C:\Program Files\Suricata\suricata.exe",
    r"C:\Program Files (x86)\Suricata\suricata.exe",
];
pub(super) const SURICATA_VERSION_MARKER: &str = ".evectl-suricata-version";

const SURICATA_READY_TIMEOUT: Duration = Duration::from_secs(5);

fn write_suricata_rules_include_stub(paths: &Paths) -> Result<PathBuf> {
    let rules_dir = paths.suricata_rules_dir();
    std::fs::create_dir_all(&rules_dir).context(format!(
        "Failed to create Suricata rules directory {}",
        rules_dir.display()
    ))?;

    let run_dir = paths.suricata_run_dir();
    std::fs::create_dir_all(&run_dir).context(format!(
        "Failed to create Suricata runtime directory {}",
        run_dir.display()
    ))?;

    let include_path = run_dir.join("rules-include.yaml");
    let rules_dir = rules_dir.to_string_lossy().replace('\'', "''");

    let stub = format!(
        "%YAML 1.1\n---\ndefault-rule-path: '{}'\nrule-files:\n  - suricata.rules\n",
        rules_dir
    );

    std::fs::write(&include_path, stub).context(format!(
        "Failed to write Suricata rules include file {}",
        include_path.display()
    ))?;

    Ok(include_path)
}

fn ensure_suricata_threshold_config(paths: &Paths) -> Result<PathBuf> {
    let path = paths.suricata_threshold_config();
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }

    if !path.exists() {
        std::fs::write(&path, b"").context(format!(
            "Failed to create Suricata threshold config {}",
            path.display()
        ))?;
    }

    Ok(path)
}

pub(super) fn find_suricata_executable(paths: &Paths) -> Option<PathBuf> {
    let path = paths.suricata_exe();
    if path.exists() {
        return Some(path);
    }

    for path in &SURICATA_SYSTEM_EXE_PATHS {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }

    if let Ok(output) = Command::new("where").arg("suricata.exe").output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(path) = stdout.lines().map(str::trim).find(|line| !line.is_empty()) {
            let path = PathBuf::from(path);
            if path.exists() {
                return Some(path);
            }
        }
    }

    None
}

fn find_file_recursive(root: &Path, target_filename: &str) -> Result<Option<PathBuf>> {
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

fn find_suricata_install_file(install_dir: &Path, filename: &str) -> Option<PathBuf> {
    let candidates = [
        install_dir.join(filename),
        install_dir.join("etc").join(filename),
    ];

    for candidate in candidates {
        if candidate.exists() {
            return Some(candidate);
        }
    }

    match find_file_recursive(install_dir, filename) {
        Ok(path) => path,
        Err(err) => {
            warn!(
                "Failed to search for {} under {}: {}",
                filename,
                install_dir.display(),
                err
            );
            None
        }
    }
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<()> {
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

fn patch_suricata_config_for_local_install(install_dir: &Path) -> Result<()> {
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

fn extract_msi_package_to_dir(path: &Path, name: &str, destination: &Path) -> Result<()> {
    info!(
        "Extracting {} from {:?} into {}",
        name,
        path,
        destination.display()
    );

    let staging_dir = tempfile::tempdir().context("Failed to create MSI extraction directory")?;
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

    let output = powershell_output(&script).context(format!("Failed to extract {} MSI", name))?;

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

fn is_suricata_managed_installed(paths: &Paths) -> bool {
    paths.suricata_exe().exists()
}

fn is_suricata_installed(paths: &Paths) -> bool {
    if find_suricata_executable(paths).is_some() {
        return true;
    }

    // Check if Suricata service exists
    if let Ok(output) = Command::new("sc").args(["query", "Suricata"]).output()
        && output.status.success()
    {
        return true;
    }

    false
}

pub(super) fn suricata_upgrade_needed(paths: &Paths) -> Result<bool> {
    let target_version = suricata_version_for_comparison();

    if !is_suricata_managed_installed(paths) {
        return Ok(true);
    }

    let installed_version = match suricata_installed_version(paths)? {
        Some(version) => version,
        None => return Ok(true),
    };

    let Some(comparison) = compare_versions(&installed_version, target_version) else {
        return Ok(false);
    };

    Ok(comparison == std::cmp::Ordering::Less)
}

pub(super) fn maybe_upgrade_suricata(paths: &Paths) -> Result<()> {
    let target_version = suricata_version_for_comparison();
    let managed_installed = is_suricata_managed_installed(paths);
    let any_installed = is_suricata_installed(paths);

    if !managed_installed {
        if any_installed {
            info!(
                "A non-evectl Suricata installation was detected. Installing evectl-managed version {}...",
                SURICATA_VERSION
            );
        } else {
            info!(
                "Suricata was not detected. Installing version {}...",
                SURICATA_VERSION
            );
        }
        return install_or_upgrade_suricata(paths, true);
    }

    let installed_version = match suricata_installed_version(paths)? {
        Some(version) => version,
        None => {
            info!(
                "Suricata is installed in the evectl-managed directory, but the version could not be determined. Reinstalling bundled version {}.",
                SURICATA_VERSION
            );
            return install_or_upgrade_suricata(paths, true);
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
            install_or_upgrade_suricata(paths, true)
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

pub(super) fn suricata_version_for_comparison() -> &'static str {
    SURICATA_VERSION
        .split('-')
        .next()
        .unwrap_or(SURICATA_VERSION)
}

fn version_marker_path(paths: &Paths) -> PathBuf {
    paths.suricata_install_dir().join(SURICATA_VERSION_MARKER)
}

pub(super) fn suricata_installed_version(paths: &Paths) -> Result<Option<String>> {
    let marker_path = version_marker_path(paths);
    if marker_path.exists() {
        let version = std::fs::read_to_string(&marker_path).context(format!(
            "Failed to read Suricata version marker {}",
            marker_path.display()
        ))?;
        let version = version.trim();
        if !version.is_empty() {
            return Ok(Some(version.to_string()));
        }
    }

    Ok(None)
}

pub(super) fn install_or_upgrade_suricata(paths: &Paths, upgrade: bool) -> Result<()> {
    let managed_installed = is_suricata_managed_installed(paths);
    let any_installed = is_suricata_installed(paths);

    if managed_installed && !upgrade {
        info!("Suricata is already installed in the evectl-managed directory.");
        return Ok(());
    }

    if any_installed && !managed_installed && !upgrade {
        info!(
            "A system Suricata installation was detected. Installing an evectl-managed copy into {}.",
            paths.suricata_install_dir().display()
        );
    }

    if upgrade {
        if managed_installed {
            info!("Upgrading Suricata to version {}...", SURICATA_VERSION);

            if let Err(err) = stop_managed_process(paths, Role::Suricata) {
                warn!("Failed to stop running Suricata processes: {}", err);
            }

            uninstall_suricata(paths)?;
        } else if any_installed {
            info!(
                "A non-evectl Suricata installation was detected. Installing evectl-managed version {} instead...",
                SURICATA_VERSION
            );
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

    let cache_dir = paths.downloads_dir();
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

    let install_dir = paths.suricata_install_dir();
    extract_msi_package_to_dir(&msi_path, "Suricata", &install_dir)?;
    patch_suricata_config_for_local_install(&install_dir)?;

    let marker_path = version_marker_path(paths);
    std::fs::write(&marker_path, suricata_version_for_comparison()).context(format!(
        "Failed to write Suricata version marker {}",
        marker_path.display()
    ))?;

    let suricata_exe = paths.suricata_exe();
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

pub(super) fn uninstall_suricata(paths: &Paths) -> Result<()> {
    info!("Removing evectl-managed Suricata installation...");

    let mut errors = vec![];
    let install_dir = paths.suricata_install_dir();

    if install_dir.exists() {
        info!("Removing Suricata directory {}", install_dir.display());

        if let Err(err) = std::fs::remove_dir_all(&install_dir) {
            warn!(
                "Failed to remove {} directly: {}. Trying PowerShell cleanup...",
                install_dir.display(),
                err
            );

            let escaped = install_dir.to_string_lossy().replace('\'', "''");
            let script = format!(
                "$ErrorActionPreference = 'Stop'; if (Test-Path -LiteralPath '{0}') {{ Remove-Item -LiteralPath '{0}' -Recurse -Force }}",
                escaped
            );

            if let Err(err) = powershell(&script, "PowerShell cleanup failed") {
                errors.push(format!("{}: {}", install_dir.display(), err));
            }
        }
    }

    if !errors.is_empty() {
        warn!(
            "Suricata uninstall cleanup hit file-lock or removal errors. This often means a non-Suricata process still has a handle open under the install directory (for example Explorer, antivirus, an editor, or another tool)."
        );
        bail!(
            "Failed to remove Suricata leftover files:\n- {}",
            errors.join("\n- ")
        );
    }

    let suricata_exe_path = paths.suricata_exe();
    if suricata_exe_path.exists() {
        bail!(
            "Suricata uninstall completed, but this executable still exists:\n- {}",
            suricata_exe_path.display()
        );
    }

    Ok(())
}

pub(super) fn build_suricata_command(paths: &Paths, guid: &str) -> Result<Command> {
    if !is_suricata_installed(paths) {
        bail!("Suricata is not installed. Please install it first using 'evectl install'");
    }

    let suricata_path = find_suricata_executable(paths)
        .ok_or_else(|| anyhow!("Suricata executable not found in expected locations"))?;
    let suricata_dir = suricata_path
        .parent()
        .ok_or_else(|| anyhow!("Failed to determine Suricata installation directory"))?
        .to_path_buf();

    let suricata_log_dir = paths.suricata_log_dir();
    ensure_dir(&suricata_log_dir)?;
    let threshold_config = ensure_suricata_threshold_config(paths)?;

    let npcap_device = format!("\\Device\\NPF_{{{}}}", guid.trim_matches(['{', '}']));
    let rules_include_path = write_suricata_rules_include_stub(paths)?;

    let mut command = Command::new(&suricata_path);
    let suricata_config = suricata_dir.join("suricata.yaml");
    if suricata_config.exists() {
        command.arg("-c");
        command.arg(&suricata_config);
    }
    command.arg("--include");
    command.arg(&rules_include_path);
    command.current_dir(&suricata_dir);
    command.arg("-i");
    command.arg(&npcap_device);
    command.arg("-l");
    command.arg(&suricata_log_dir);
    command.arg("--set");
    command.arg(format!("threshold-file={}", threshold_config.display()));

    if let Some(classification_file) =
        find_suricata_install_file(&suricata_dir, "classification.config")
    {
        command.arg("--set");
        command.arg(format!(
            "classification-file={}",
            classification_file.display()
        ));
    } else {
        warn!(
            "Could not find classification.config under {}; relying on Suricata defaults",
            suricata_dir.display()
        );
    }

    if let Some(reference_config_file) =
        find_suricata_install_file(&suricata_dir, "reference.config")
    {
        command.arg("--set");
        command.arg(format!(
            "reference-config-file={}",
            reference_config_file.display()
        ));
    } else {
        warn!(
            "Could not find reference.config under {}; relying on Suricata defaults",
            suricata_dir.display()
        );
    }

    let config = load_evectl_config(paths)?;

    if let Some(sensor_name) = &config.suricata.sensor_name {
        command.arg("--set");
        command.arg(format!("sensor-name={}", sensor_name));
    }

    let spool = paths.suricata_pcap_dir();
    let mut dump_command = Command::new(command.get_program());
    dump_command.args(command.get_args());
    dump_command.arg("--dump-config");
    dump_command.current_dir(&suricata_dir);
    let output = dump_command
        .output()
        .context("Failed to dump Suricata configuration for packet capture and file extraction")?;
    if !output.status.success() {
        bail!(
            "Failed to dump Suricata configuration for packet capture and file extraction ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let fpc = super::fpc::effective_config(&config);
    if config.fpc.enabled && !fpc.enabled {
        warn!("Full packet capture requires Suricata and either the EveBox server or agent");
    }
    super::fpc::configure_command(
        &mut command,
        std::str::from_utf8(&output.stdout)?,
        &fpc,
        &spool,
    )?;
    if fpc.enabled {
        ensure_dir(&spool)?;
    }
    let extraction = crate::config::FileExtractionConfig {
        enabled: super::file_extraction::enabled(&config),
        ..config.suricata.file_extraction.clone()
    };
    super::file_extraction::configure_command(
        &mut command,
        std::str::from_utf8(&output.stdout)?,
        &extraction,
        &paths.suricata_filestore_dir(),
    )?;

    // The BPF filter is a trailing positional argument.
    if let Some(bpf) = &config.suricata.bpf {
        command.arg(bpf);
    }

    Ok(command)
}

pub(super) fn ensure_suricata_start_allowed(paths: &Paths) -> Result<()> {
    if managed_process_is_running(paths, Role::Suricata)? {
        bail!("A managed Suricata process is already running. Use 'evectl stop' first.");
    }

    let process_count = list_named_processes("suricata")?.len();
    if process_count > 0 {
        bail!(
            "Suricata is already running ({} process(es) found). Stop the external Suricata process or service first.",
            process_count
        );
    }

    Ok(())
}

pub(super) fn start_suricata_background(paths: &Paths, guid: &str) -> Result<RuntimeMetadata> {
    ensure_suricata_start_allowed(paths)?;

    let mut command = build_suricata_command(paths, guid)?;
    launch_managed(paths, Role::Suricata, &mut command, None)
}

pub(super) fn wait_for_suricata_pid_readiness(
    paths: &Paths,
    pid: u32,
    exe_path: &Path,
) -> Result<()> {
    let eve_json = paths.suricata_eve_json();
    let started = std::time::Instant::now();

    while started.elapsed() < SURICATA_READY_TIMEOUT {
        if !is_pid_running(pid) {
            bail!("Suricata exited before EveBox could be started");
        }

        if process_matches_exe(pid, exe_path)? && eve_json.exists() {
            return Ok(());
        }

        std::thread::sleep(Duration::from_millis(250));
    }

    if !is_pid_running(pid) {
        bail!("Suricata exited before it became ready");
    }

    Ok(())
}
