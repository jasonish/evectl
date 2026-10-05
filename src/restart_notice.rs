// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Per-instance update reminders, shared by Linux and Windows.

use std::path::Path;

use crate::prelude::*;

pub(crate) const RESTART_MARKER: &str = ".evectl-restart-recommended";

pub(crate) fn pending(root: &Path) -> bool {
    root.join(RESTART_MARKER).exists()
}

pub(crate) fn recommend(root: &Path) -> Result<()> {
    std::fs::create_dir_all(root)?;
    std::fs::write(root.join(RESTART_MARKER), b"")?;
    Ok(())
}

fn clear(root: &Path) -> Result<()> {
    match std::fs::remove_file(root.join(RESTART_MARKER)) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Keep the reminder until the full restart succeeds, including stopping
/// old services. A failed reminder cleanup does not fail a successful restart.
pub(crate) fn complete_restart(root: &Path, restart: impl FnOnce() -> Result<()>) -> Result<()> {
    restart()?;
    if let Err(err) = clear(root) {
        warn!("Services restarted, but failed to clear the restart recommendation: {err}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reminder_is_per_instance_and_survives_failed_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("sensor1");
        assert!(!pending(&root));
        recommend(&root).unwrap();
        recommend(&root).unwrap();
        assert!(pending(&root));
        assert!(!pending(&dir.path().join("sensor2")));

        for stage in ["stop", "start"] {
            assert!(complete_restart(&root, || bail!("{stage} failed")).is_err());
            assert!(pending(&root));
        }
        complete_restart(&root, || Ok(())).unwrap();
        assert!(!pending(&root));
        complete_restart(&root, || Ok(())).unwrap();
    }
}
