// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Durable file-extraction cleanup, using the selected Suricata image.

use std::process::Command;

use sha2::{Digest, Sha256};

use crate::container::{CommandExt, Container};
use crate::prelude::*;

const WORKER: &str = include_str!("housekeeper/jobs.py");
const WORKER_PATH: &str = "/usr/local/bin/evectl-housekeeper";
const CONFIG_PATH: &str = "/housekeeping/config.json";
const SPEC_LABEL: &str = "org.evebox.evectl.housekeeping-spec";

pub(crate) fn container_name(context: &Context) -> String {
    format!("{}-housekeeper", context.container_prefix())
}

/// Previous service name, retained only to retire workers during upgrades.
pub(crate) fn legacy_container_name(context: &Context) -> String {
    format!("{}-housekeeping", context.container_prefix())
}

pub(crate) fn enabled(context: &Context) -> bool {
    crate::uses_file_extraction(context)
        && context.config.suricata.file_extraction.max_age_days() > 0
}

fn configuration(context: &Context) -> String {
    serde_json::json!({
        "file_extraction": {
            "retention_days": context.config.suricata.file_extraction.max_age_days(),
            "interval_seconds": 300,
            // Bound a cleanup pass to four minutes, leaving room before the
            // next five-minute interval. Shutdown allows five seconds to reap.
            "timeout_seconds": 240,
        }
    })
    .to_string()
}

fn write_assets(context: &Context) -> Result<()> {
    let directory = context.config_dir().join("housekeeping");
    std::fs::create_dir_all(&directory).with_context(|| {
        format!(
            "Cannot create housekeeper assets in {}",
            directory.display()
        )
    })?;
    // Only create the bind-mount root. Suricata owns creation of filestore;
    // its entrypoint may already have taken ownership of the log directory.
    let log_directory = context.data_dir().join("suricata/log");
    std::fs::create_dir_all(&log_directory)
        .with_context(|| format!("Cannot prepare log mount {}", log_directory.display()))?;
    let worker = directory.join("jobs.py");
    std::fs::write(&worker, WORKER)
        .with_context(|| format!("Cannot write housekeeper script {}", worker.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o755)).with_context(
            || {
                format!(
                    "Cannot make housekeeper script executable: {}",
                    worker.display()
                )
            },
        )?;
    }
    let config = directory.join("config.json");
    std::fs::write(&config, configuration(context)).with_context(|| {
        format!(
            "Cannot write housekeeper configuration {}",
            config.display()
        )
    })?;
    Ok(())
}

/// Explicitly bypass the image entrypoint: no Suricata setup, cron, or capture
/// privileges. Container root plus DAC_OVERRIDE permits pruning directories
/// owned by Suricata without chowning the shared data (including rootless
/// Podman's mapped Suricata user). No other capabilities are needed.
fn command(context: &Context, spec: Option<&str>) -> Command {
    let mut command = context.manager.command();
    command.args([
        "run",
        "--pull=never",
        "--network=none",
        "--user=0",
        "--cap-drop=ALL",
        "--cap-add=DAC_OVERRIDE",
        "--security-opt=no-new-privileges",
        "--entrypoint=evectl-housekeeper",
        "--env=PYTHONUNBUFFERED=1",
    ]);
    if let Some(spec) = spec {
        command.args(["--detach", "--restart=unless-stopped", "--stop-timeout=15"]);
        command.arg(format!("--name={}", container_name(context)));
        command.arg(format!("--label={SPEC_LABEL}={spec}"));
    } else {
        command.arg("--rm");
    }
    for (file, target) in [("jobs.py", WORKER_PATH), ("config.json", CONFIG_PATH)] {
        command.arg(format!(
            "--volume={}",
            context.manager.bind_mount_with_options(
                &context.config_dir().join("housekeeping").join(file),
                target,
                &["ro"],
            )
        ));
    }
    command.arg(format!(
        "--volume={}",
        context.manager.bind_mount(
            &context.data_dir().join("suricata/log"),
            "/var/log/suricata",
        )
    ));
    command.arg(context.image_name(Container::Suricata));
    command.arg(CONFIG_PATH);
    if spec.is_none() {
        command.arg("--check");
    }
    command
}

/// Include the resolved image ID, not just its tag, so an image pull also
/// invalidates a running worker. Include mount paths/options and worker code
/// so upgrades and moved instances cannot silently keep stale settings.
fn specification(context: &Context, image_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(WORKER);
    digest.update(configuration(context));
    digest.update(image_id);
    for arg in command(context, Some("")).get_args() {
        digest.update(arg.to_string_lossy().as_bytes());
        digest.update([0]);
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn assets_match(context: &Context) -> bool {
    let directory = context.config_dir().join("housekeeping");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !std::fs::metadata(directory.join("jobs.py"))
            .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 == 0o111)
        {
            return false;
        }
    }
    std::fs::read_to_string(directory.join("jobs.py"))
        .ok()
        .as_deref()
        == Some(WORKER)
        && std::fs::read_to_string(directory.join("config.json"))
            .ok()
            .as_deref()
            == Some(configuration(context).as_str())
}

/// Inspect through a container listing first so daemon/permission failures
/// are not mistaken for an absent container, even when cleanup is disabled.
fn inspect(context: &Context, name: &str) -> Result<Option<serde_json::Value>> {
    let names = context
        .manager
        .command()
        .args(["ps", "--all", "--format", "{{.Names}}"])
        .status_output()?;
    if !String::from_utf8_lossy(&names)
        .lines()
        .any(|line| line == name)
    {
        return Ok(None);
    }
    let bytes = context
        .manager
        .command()
        .args(["inspect", name])
        .status_output()?;
    let entries: Vec<serde_json::Value> = serde_json::from_slice(&bytes)?;
    Ok(Some(entries.into_iter().next().ok_or_else(|| {
        anyhow!("Empty housekeeping inspect result")
    })?))
}

pub(crate) fn remove(context: &Context) -> Result<()> {
    remove_named(context, &legacy_container_name(context))?;
    remove_named(context, &container_name(context))
}

fn remove_named(context: &Context, name: &str) -> Result<()> {
    if let Some(state) = inspect(context, name)? {
        if state["State"]["Running"].as_bool() == Some(true)
            || state["State"]["Restarting"].as_bool() == Some(true)
        {
            context.manager.stop(name, None)?;
        }
        context
            .manager
            .command()
            .args(["rm", name])
            .status_output()?;
    }
    Ok(())
}

fn is_current(state: &serde_json::Value, spec: &str) -> bool {
    state["State"]["Running"].as_bool() == Some(true)
        && state["State"]["Restarting"].as_bool() != Some(true)
        && state["Config"]["Labels"][SPEC_LABEL].as_str() == Some(spec)
}

/// Called independently of Suricata startup, including its already-running
/// fast path. A stopped or stale container is recreated, never exec'd into.
pub(crate) fn reconcile(context: &Context) -> Result<()> {
    if !enabled(context) {
        return remove(context);
    }
    // Never leave the old worker pruning alongside the renamed service.
    remove_named(context, &legacy_container_name(context))?;
    let image = context.image_name(Container::Suricata);
    let bytes = context
        .manager
        .command()
        .args(["image", "inspect", "--format", "{{.Id}}", &image])
        .status_output()
        .with_context(|| format!("Cannot inspect housekeeping image {image}"))?;
    let image_id = String::from_utf8(bytes)?.trim().to_string();
    if image_id.is_empty() {
        bail!("Missing housekeeping image ID");
    }
    let spec = specification(context, &image_id);
    if inspect(context, &container_name(context))?
        .as_ref()
        .is_some_and(|state| is_current(state, &spec))
        && assets_match(context)
    {
        info!("Housekeeper is already running");
        return Ok(());
    }

    remove_named(context, &container_name(context))?;
    write_assets(context)?;
    // Check the actual selected image and mounted filesystem, not local
    // source availability. Use the same configured image name as Suricata;
    // the resolved ID above is only used to detect image updates.
    let check = command(context, None)
        .output()
        .context("Failed to run housekeeping compatibility check")?;
    if !check.status.success() {
        bail!(
            "Housekeeping requires Python 3, suricatactl filestore prune and writable filestore mounts in {image}:\n{}{}",
            String::from_utf8_lossy(&check.stdout),
            String::from_utf8_lossy(&check.stderr),
        );
    }
    info!("Starting housekeeper");
    command(context, Some(&spec)).status_output()?;
    if !context.manager.is_running(&container_name(context)) {
        bail!("Housekeeping exited at startup; check evectl logs");
    }
    Ok(())
}

/// Foreground debug sessions also use one durable container, but own its
/// lifetime: stop it on every return path, including a later startup error.
pub(crate) struct ForegroundGuard<'a>(pub(crate) &'a Context);

impl Drop for ForegroundGuard<'_> {
    fn drop(&mut self) {
        if let Err(err) = remove(self.0) {
            error!("Failed to stop foreground housekeeping: {err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::{ContainerManager, DockerManager, PodmanManager};

    fn context(manager: ContainerManager) -> Context {
        Context::new(Config::default(), "/tmp/sensor".into(), manager)
    }

    #[test]
    fn enabled_only_with_suricata_extraction_and_positive_retention() {
        let mut ctx = context(ContainerManager::Docker(DockerManager::new()));
        for suricata in [false, true] {
            for extraction in [false, true] {
                for age in [None, Some(0), Some(19)] {
                    ctx.config.suricata.enabled = suricata;
                    ctx.config.suricata.file_extraction.enabled = extraction;
                    ctx.config.suricata.file_extraction.max_age_days = age;
                    assert_eq!(enabled(&ctx), suricata && extraction && age != Some(0));
                }
            }
        }
    }

    #[test]
    fn restricted_startup_command_for_both_runtimes() {
        for manager in [
            ContainerManager::Docker(DockerManager::new()),
            ContainerManager::Podman(PodmanManager::new()),
        ] {
            let mut ctx = context(manager);
            ctx.config.suricata.image = Some("custom-suricata:testing".to_string());
            let cmd = command(&ctx, Some("fingerprint"));
            let args: Vec<_> = cmd
                .get_args()
                .map(|s| s.to_string_lossy().into_owned())
                .collect();
            assert_eq!(cmd.get_program(), manager.bin());
            for arg in [
                "run",
                "--detach",
                "--restart=unless-stopped",
                "--network=none",
                "--user=0",
                "--cap-drop=ALL",
                "--cap-add=DAC_OVERRIDE",
                "--entrypoint=evectl-housekeeper",
                "--env=PYTHONUNBUFFERED=1",
                "--name=sensor-evectl-housekeeper",
            ] {
                assert!(args.iter().any(|a| a == arg), "missing {arg}");
            }
            let mounts: Vec<_> = args.iter().filter(|a| a.starts_with("--volume=")).collect();
            assert_eq!(mounts.len(), 3);
            assert!(
                mounts[0]
                    .contains("/config/housekeeping/jobs.py:/usr/local/bin/evectl-housekeeper:ro")
            );
            assert!(
                mounts[1].contains("/config/housekeeping/config.json:/housekeeping/config.json:ro")
            );
            assert!(mounts[2].contains("/data/suricata/log:/var/log/suricata"));
            assert!(!mounts[2].contains(":ro"));
            assert_eq!(
                &args[args.len() - 2..],
                ["custom-suricata:testing", CONFIG_PATH]
            );
            assert!(!args.iter().any(|a| a == "exec"
                || a.contains("privileged")
                || a.contains("net_admin")
                || a.contains("docker.sock")
                || a.contains("suricata/run")
                || a.contains("suricata/lib")));
            let check = command(&ctx, None);
            assert!(check.get_args().any(|a| a == "custom-suricata:testing"));
            assert!(check.get_args().any(|a| a == "--check"));
            assert!(check.get_args().any(|a| a == "--rm"));
            assert!(!check.get_args().any(|a| a == "--detach"));
        }
    }

    #[test]
    fn settings_assets_and_image_changes_invalidate_specification() {
        let root = tempfile::tempdir().unwrap();
        let mut ctx = context(ContainerManager::Docker(DockerManager::new()));
        ctx.root = root.path().to_path_buf();
        let original = specification(&ctx, "image1");
        assert_ne!(original, specification(&ctx, "image2"));
        ctx.config.suricata.image = Some("custom-suricata:testing".to_string());
        assert_ne!(original, specification(&ctx, "image1"));
        ctx.config.suricata.image = None;
        ctx.config.suricata.file_extraction.max_age_days = Some(19);
        assert_ne!(original, specification(&ctx, "image1"));
        let config: serde_json::Value = serde_json::from_str(&configuration(&ctx)).unwrap();
        assert_eq!(config["file_extraction"]["retention_days"], 19);
        assert_eq!(config["file_extraction"]["interval_seconds"], 300);
        write_assets(&ctx).unwrap();
        assert!(assets_match(&ctx));
        assert!(WORKER.starts_with("#!/usr/bin/env python3\n"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let worker = ctx.config_dir().join("housekeeping/jobs.py");
            assert_eq!(
                std::fs::metadata(&worker).unwrap().permissions().mode() & 0o777,
                0o755
            );
            std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(!assets_match(&ctx));
            write_assets(&ctx).unwrap();
            assert!(assets_match(&ctx));
        }
        assert!(ctx.data_dir().join("suricata/log").is_dir());
        assert!(!ctx.data_dir().join("suricata/log/filestore").exists());
        std::fs::write(ctx.config_dir().join("housekeeping/jobs.py"), "stale").unwrap();
        assert!(!assets_match(&ctx));
    }

    #[test]
    fn stopped_restarting_and_stale_workers_need_recreation() {
        let mut state = serde_json::json!({
            "State": {"Running": true, "Restarting": false},
            "Config": {"Labels": {SPEC_LABEL: "current"}}
        });
        assert!(is_current(&state, "current"));
        assert!(!is_current(&state, "changed"));
        state["State"]["Running"] = false.into();
        assert!(!is_current(&state, "current"));
        state["State"]["Running"] = true.into();
        state["State"]["Restarting"] = true.into();
        assert!(!is_current(&state, "current"));
        assert!(!is_current(&serde_json::Value::Null, "current"));
    }
}
