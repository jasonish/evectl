// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Update EveCtl itself, then the container images. A self-update launches
//! the new binary to finish updating before offering to restart services.

use std::path::{Path, PathBuf};
use std::process;

use semver::Version;

use crate::container::Container;
use crate::prelude::*;
use crate::{elastic, housekeeper, restart_notice, selfupdate, services, suricata};

/// Runtime flags to preserve across self-update and manual service restart.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct UpdateContinuationArgs {
    pub(crate) podman: bool,
    pub(crate) no_root: bool,
    pub(crate) data_directory: Option<PathBuf>,
    pub(crate) verbose: u8,
}

impl UpdateContinuationArgs {
    pub(crate) fn new(
        manager: crate::container::ContainerManager,
        args: &crate::cli::Args,
        root: &Path,
    ) -> Self {
        Self {
            podman: manager.is_podman(),
            no_root: args.no_root,
            // Pin the resolved instance, even when selected from the cwd
            // or XDG_CONFIG_HOME, across self-update and manual restart.
            data_directory: Some(root.to_path_buf()),
            verbose: args.verbose,
        }
    }

    fn runtime_args(&self) -> Vec<String> {
        let mut args = vec![];
        if self.podman {
            args.push("--podman".to_string());
        }
        if self.no_root {
            args.push("--no-root".to_string());
        }
        if let Some(directory) = &self.data_directory {
            args.push("--data-directory".to_string());
            args.push(directory.to_string_lossy().to_string());
        }
        for _ in 0..self.verbose {
            args.push("-v".to_string());
        }
        args
    }

    fn to_args(&self, return_to_menu: bool, restart: bool) -> Vec<String> {
        let mut args = self.runtime_args();
        args.push("update".to_string());
        args.push("--containers-only".to_string());
        if return_to_menu {
            args.push("--return-to-menu".to_string());
        }
        if restart {
            args.push("--restart".to_string());
        }
        args
    }

    fn restart_command(&self, executable: &Path) -> String {
        std::iter::once(executable.to_string_lossy().into_owned())
            .chain(self.runtime_args())
            .chain(std::iter::once("restart".to_string()))
            .map(|arg| shell_quote(&arg))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Quote a POSIX shell argument so the displayed command is safe to paste,
/// even when the executable or an ancestor of the instance has spaces.
fn shell_quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
    {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

pub(crate) fn update(
    context: &Context,
    update_continuation_args: &UpdateContinuationArgs,
    containers_only: bool,
    return_to_menu: bool,
    restart: bool,
) -> bool {
    let self_update_ok = if containers_only {
        true
    } else {
        match selfupdate::self_update() {
            Ok(selfupdate::SelfUpdate::Unchanged) => true,
            Ok(selfupdate::SelfUpdate::Updated(current_exe)) => {
                if let Err(err) = restart_notice::recommend(&context.root) {
                    warn!("Failed to save the restart recommendation: {err}");
                }
                warn!("EveCtl was updated, but services have not been restarted.");
                std::process::exit(continue_update_with_new_binary(
                    &current_exe,
                    update_continuation_args,
                    return_to_menu,
                    restart,
                ));
            }
            Err(err) => {
                error!("Failed to update EveCtl: {err}");
                info!("Continuing with container updates");
                false
            }
        }
    };
    let containers_ok = update_containers(context);
    let executable = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("evectl"));
    finish_update(
        &context.root,
        &update_continuation_args.restart_command(&executable),
        UpdateCompletion {
            successful: self_update_ok && containers_ok,
            interactive: return_to_menu,
            restart,
        },
        || {
            crate::prompt::confirm_with_help(
                "Updates applied, but services have not been restarted. Restart all enabled services now?",
                "This briefly interrupts monitoring. Declining keeps the restart reminder.",
            )
        },
        || services::restart(context),
    )
}

#[derive(Clone, Copy)]
struct UpdateCompletion {
    successful: bool,
    interactive: bool,
    restart: bool,
}

/// One restart decision after all updates: never interrupt services unless
/// explicitly requested or confirmed, and never restart an incomplete update.
fn finish_update(
    root: &Path,
    restart_command: &str,
    completion: UpdateCompletion,
    confirm: impl FnOnce() -> bool,
    restart: impl FnOnce() -> Result<()>,
) -> bool {
    let pending = restart_notice::pending(root);
    if !pending && !completion.restart {
        return completion.successful;
    }
    if !completion.successful {
        warn!("Updates were incomplete; services have not been restarted.");
    } else if completion.restart || (completion.interactive && confirm()) {
        // Retain a reminder if an explicitly requested restart fails, even
        // if there was no self-update or Suricata version change.
        if let Err(err) = restart_notice::recommend(root) {
            warn!("Failed to save the restart recommendation: {err}");
        }
        match restart() {
            Ok(()) => return true,
            Err(err) => {
                error!("Failed to restart services: {err:#}");
                warn!("Restart is still recommended. Run: {restart_command}");
                return false;
            }
        }
    } else {
        warn!("Updates applied, but services have not been restarted. Restart is recommended.");
    }
    warn!("Restart all enabled services with: {restart_command}");
    completion.successful
}

/// If Suricata is running and its version differs from the version
/// in the configured image, return the running and image versions.
fn suricata_update_pending(context: &Context) -> Option<(Version, Version)> {
    if !context.config.suricata.enabled
        || !context
            .manager
            .is_running(&suricata::container_name(context))
    {
        return None;
    }
    let running = match suricata::running_version(context) {
        Ok(Some(version)) => version,
        Ok(None) => return None,
        Err(err) => {
            debug!("Failed to determine the running Suricata version: {err}");
            return None;
        }
    };
    let image = match suricata::image_version(context) {
        Ok(Some(version)) => version,
        Ok(None) => return None,
        Err(err) => {
            debug!("Failed to determine the Suricata image version: {err}");
            return None;
        }
    };
    if running != image {
        Some((running, image))
    } else {
        None
    }
}

/// Pull the images and remember a pending Suricata version change.
/// The caller handles the single restart decision after all updates.
fn update_containers(context: &Context) -> bool {
    let mut ok = true;
    for image in [
        context.image_name(Container::Suricata),
        context.image_name(Container::EveBox),
    ] {
        if let Err(err) = context.manager.pull(&image) {
            error!("Failed to pull {image}: {err}");
            ok = false;
        }
    }
    if context.config.elasticsearch_enabled() {
        let image = elastic::docker_image(context);
        if let Err(err) = context.manager.pull(image) {
            error!("Failed to pull {image}: {err}");
            ok = false;
        }
    }
    if housekeeper::enabled(context) {
        info!("Housekeeper will use the updated Suricata image on the next evectl start/restart");
    }
    if let Some((running, image)) = suricata_update_pending(context) {
        info!("Suricata updated from {running} to {image}, restart required");
        if let Err(err) = restart_notice::recommend(&context.root) {
            warn!("Failed to save the restart recommendation: {err}");
            ok = false;
        }
    }
    ok
}

fn continue_update_with_new_binary(
    current_exe: &Path,
    update_continuation_args: &UpdateContinuationArgs,
    return_to_menu: bool,
    restart: bool,
) -> i32 {
    let args = update_continuation_args.to_args(return_to_menu, restart);
    info!("Continuing update with {}", current_exe.display());
    let status = process::Command::new(current_exe).args(&args).status();
    match status {
        Ok(status) if status.success() => 0,
        Ok(status) => status.code().unwrap_or(1),
        Err(err) => {
            error!("Failed to continue update with new EveCtl: {err}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Args, Commands};
    use crate::container::ContainerManager;
    use clap::Parser;

    #[test]
    fn update_continuation_args_preserve_runtime_flags_and_restart() {
        let args = Args::try_parse_from([
            "evectl",
            "--no-root",
            "-vv",
            "-D",
            "/var/lib/evectl-test",
            "update",
            "--restart",
        ])
        .expect("parse args");
        let root = Path::new("/var/lib/evectl-test");
        let continuation = UpdateContinuationArgs::new(ContainerManager::Podman, &args, root);
        assert_eq!(
            continuation,
            UpdateContinuationArgs {
                podman: true,
                no_root: true,
                data_directory: Some(root.to_path_buf()),
                verbose: 2,
            }
        );
        assert_eq!(
            continuation.to_args(false, false),
            vec![
                "--podman",
                "--no-root",
                "--data-directory",
                "/var/lib/evectl-test",
                "-v",
                "-v",
                "update",
                "--containers-only",
            ]
        );
        let parsed = Args::try_parse_from(
            std::iter::once("evectl".to_string()).chain(continuation.to_args(true, true)),
        )
        .unwrap();
        assert!(parsed.podman);
        assert!(parsed.no_root);
        assert_eq!(parsed.data_directory, Some(root.to_path_buf()));
        assert_eq!(parsed.verbose, 2);
        assert!(matches!(
            parsed.command,
            Some(Commands::Update {
                containers_only: true,
                return_to_menu: true,
                restart: true,
            })
        ));
    }

    #[test]
    fn continuation_pins_implicitly_selected_instance() {
        let args = Args::try_parse_from(["evectl", "update"]).unwrap();
        let root = Path::new("/var/lib/sensor1");
        let continuation = UpdateContinuationArgs::new(ContainerManager::Docker, &args, root);
        assert_eq!(continuation.data_directory, Some(root.to_path_buf()));
        assert_eq!(
            continuation.to_args(false, false),
            [
                "--data-directory",
                "/var/lib/sensor1",
                "update",
                "--containers-only"
            ]
        );
    }

    #[test]
    fn restart_command_preserves_flags_and_quotes_paths() {
        let args = UpdateContinuationArgs {
            podman: true,
            no_root: true,
            data_directory: Some(PathBuf::from("/srv/Jason's sensors/sensor1")),
            verbose: 1,
        };
        assert_eq!(
            args.restart_command(Path::new("/opt/EveCtl tools/evectl")),
            "'/opt/EveCtl tools/evectl' --podman --no-root --data-directory '/srv/Jason'\\''s sensors/sensor1' -v restart"
        );
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("$(touch /tmp/no)"), "'$(touch /tmp/no)'");
    }

    fn completion(interactive: bool, restart: bool) -> UpdateCompletion {
        UpdateCompletion {
            successful: true,
            interactive,
            restart,
        }
    }

    #[test]
    fn declined_or_noninteractive_update_retains_reminder() {
        for interactive in [false, true] {
            let root = tempfile::tempdir().unwrap();
            restart_notice::recommend(root.path()).unwrap();
            assert!(finish_update(
                root.path(),
                "evectl restart",
                completion(interactive, false),
                || {
                    assert!(interactive, "CLI must never prompt");
                    false
                },
                || panic!("Declined or CLI updates must not restart services"),
            ));
            assert!(restart_notice::pending(root.path()));
        }
    }

    #[test]
    fn confirmed_or_explicit_restart_clears_reminder() {
        for explicit in [false, true] {
            let root = tempfile::tempdir().unwrap();
            // An explicit restart also works when no update changed versions.
            if !explicit {
                restart_notice::recommend(root.path()).unwrap();
            }
            let mut restarted = false;
            assert!(finish_update(
                root.path(),
                "evectl restart",
                completion(!explicit, explicit),
                || {
                    assert!(!explicit, "--restart must never prompt");
                    true
                },
                || restart_notice::complete_restart(root.path(), || {
                    restarted = true;
                    Ok(())
                }),
            ));
            assert!(restarted);
            assert!(!restart_notice::pending(root.path()));
        }
    }

    #[test]
    fn incomplete_updates_never_restart_even_when_requested() {
        for explicit in [false, true] {
            let root = tempfile::tempdir().unwrap();
            restart_notice::recommend(root.path()).unwrap();
            assert!(!finish_update(
                root.path(),
                "evectl restart",
                UpdateCompletion {
                    successful: false,
                    ..completion(true, explicit)
                },
                || panic!("Incomplete updates must not prompt"),
                || panic!("Incomplete updates must not restart"),
            ));
            assert!(restart_notice::pending(root.path()));
        }
    }

    #[test]
    fn failed_explicit_restart_returns_failure_and_saves_reminder() {
        let root = tempfile::tempdir().unwrap();
        assert!(!finish_update(
            root.path(),
            "evectl restart",
            completion(false, true),
            || panic!("--restart must not prompt"),
            || restart_notice::complete_restart(root.path(), || bail!("Stop failed")),
        ));
        assert!(restart_notice::pending(root.path()));
    }

    #[test]
    fn unchanged_updates_do_not_prompt_or_restart() {
        let root = tempfile::tempdir().unwrap();
        assert!(finish_update(
            root.path(),
            "evectl restart",
            completion(true, false),
            || panic!("Unchanged updates must not prompt"),
            || panic!("Unchanged updates must not restart"),
        ));
        assert!(!restart_notice::pending(root.path()));
    }
}
