// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Stop an upgrade as soon as EveCtl itself changes, and remember to recommend
//! a full stack restart when the user next opens the menu.

use std::path::Path;

use anyhow::Result;
use tracing::{error, info, warn};

use crate::selfupdate::{self, SelfUpdate};

pub(super) const RESTART_MARKER: &str = ".evectl-restart-recommended";
pub(super) const RESTART_REMINDER: &str = "EveCtl was updated. Choosing Restart from this menu to restart all enabled services is recommended.";

#[derive(Debug, Eq, PartialEq)]
pub(super) enum UpdateOutcome {
    Completed,
    RestartEveCtl,
}

pub(super) fn restart_recommended(data_dir: &Path) -> bool {
    data_dir.join(RESTART_MARKER).exists()
}

pub(super) fn clear_restart_recommendation(data_dir: &Path) -> Result<()> {
    match std::fs::remove_file(data_dir.join(RESTART_MARKER)) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

pub(super) fn run(
    self_update: Result<SelfUpdate>,
    data_dir: &Path,
    update_components: impl FnOnce() -> Result<()>,
) -> Result<UpdateOutcome> {
    match self_update {
        Ok(SelfUpdate::Updated(current_exe)) => {
            // Write the cookie before launching the helper. Keep it until a
            // full stack restart succeeds, not merely until the next launch.
            if let Err(err) = std::fs::create_dir_all(data_dir)
                .and_then(|_| std::fs::write(data_dir.join(RESTART_MARKER), b""))
            {
                warn!("Failed to save the restart recommendation: {err}");
            }
            if let Err(err) = selfupdate::schedule_staged_update(&current_exe) {
                warn!(
                    "Failed to schedule the EveCtl update: {err}. It will be retried on the next start."
                );
            }
            warn!("EveCtl update downloaded. Exiting now so it can be applied. Run evectl again.");
            info!(
                "Run Update again to finish component updates, then choose Restart from the menu to restart all enabled services (recommended)."
            );
            // No component updates, service changes, Enter prompt, or return
            // to the old binary's menu after a self-update.
            return Ok(UpdateOutcome::RestartEveCtl);
        }
        Ok(SelfUpdate::Unchanged) => {}
        Err(err) => {
            error!("Failed to update EveCtl: {err}");
            info!("Continuing with component updates");
        }
    }

    update_components()?;
    Ok(UpdateOutcome::Completed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;
    use std::time::{Duration, Instant};

    #[test]
    fn self_update_exits_before_components_and_schedules_replacement_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("evectl.exe");
        let staged = dir.path().join("evectl.exe.new");
        let data_dir = dir.path().join("data");
        std::fs::write(&target, b"old executable").unwrap();
        std::fs::write(&staged, b"new executable").unwrap();
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&target)
            .unwrap();

        let started = Instant::now();
        let outcome = run(Ok(SelfUpdate::Updated(target.clone())), &data_dir, || {
            panic!("The old binary must not update components or restart services")
        })
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(outcome, UpdateOutcome::RestartEveCtl);
        assert!(restart_recommended(&data_dir));
        assert!(staged.exists());
        drop(lock);

        // No second EveCtl launch is needed to apply the downloaded binary.
        let deadline = Instant::now() + Duration::from_secs(10);
        while staged.exists() {
            assert!(Instant::now() < deadline, "Update helper did not finish");
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(std::fs::read(&target).unwrap(), b"new executable");
        assert!(restart_recommended(&data_dir));
        clear_restart_recommendation(&data_dir).unwrap();
        assert!(!restart_recommended(&data_dir));
        clear_restart_recommendation(&data_dir).unwrap();
    }

    #[test]
    fn unchanged_or_failed_self_update_still_updates_components() {
        let dir = tempfile::tempdir().unwrap();
        for result in [
            Ok(SelfUpdate::Unchanged),
            Err(anyhow::anyhow!("Update check failed")),
        ] {
            let mut called = false;
            let outcome = run(result, dir.path(), || {
                called = true;
                Ok(())
            })
            .unwrap();
            assert!(called);
            assert_eq!(outcome, UpdateOutcome::Completed);
            assert!(!restart_recommended(dir.path()));
        }
    }

    #[test]
    fn component_updates_do_not_clear_the_restart_cookie() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(RESTART_MARKER), b"").unwrap();
        assert!(
            run(Ok(SelfUpdate::Unchanged), dir.path(), || {
                anyhow::bail!("Component update failed")
            })
            .is_err()
        );
        assert!(restart_recommended(dir.path()));
        assert_eq!(
            run(Ok(SelfUpdate::Unchanged), dir.path(), || Ok(())).unwrap(),
            UpdateOutcome::Completed
        );
        assert!(restart_recommended(dir.path()));
    }
}
