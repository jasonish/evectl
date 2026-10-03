// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Rules-management operations independent of the interactive menu.

use std::path::PathBuf;

use crate::container::{CommandExt, Container, RunCommandBuilder};
use crate::prelude::*;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Ruleset {
    pub id: String,
    pub summary: Option<String>,
    /// False for obsolete sources or sources requiring parameters that
    /// the interactive enable workflow cannot supply.
    pub can_enable: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum OverrideFile {
    Enable,
    Disable,
    Modify,
}

impl OverrideFile {
    pub(crate) const ALL: [Self; 3] = [Self::Enable, Self::Disable, Self::Modify];

    pub(crate) fn filename(self) -> &'static str {
        match self {
            Self::Enable => "enable.conf",
            Self::Disable => "disable.conf",
            Self::Modify => "modify.conf",
        }
    }
}

pub(crate) trait Backend {
    fn available_rulesets(&self) -> Result<Vec<Ruleset>>;
    /// Must include enabled sources absent from the index. Index summaries
    /// are optional; disabling a source must not require downloading an index.
    fn enabled_rulesets(&self) -> Result<Vec<Ruleset>>;
    fn enable_ruleset(&self, id: &str) -> Result<()>;
    fn disable_ruleset(&self, id: &str) -> Result<()>;
    fn update_sources(&self) -> Result<()>;
    /// Includes the backend's existing reload/restart behavior.
    fn update_rules(&self) -> Result<()>;

    fn override_path(&self, _file: OverrideFile) -> Option<PathBuf> {
        None
    }

    fn write_override_template(&self, _file: OverrideFile) -> Result<()> {
        bail!("Rule override files are not supported by this backend")
    }
}

pub(crate) struct ContainerBackend<'a>(pub(crate) &'a Context);

impl Backend for ContainerBackend<'_> {
    fn available_rulesets(&self) -> Result<Vec<Ruleset>> {
        Ok(crate::actions::load_rule_index(self.0)?
            .sources
            .into_iter()
            .map(|(id, source)| Ruleset {
                id,
                summary: Some(source.summary),
                can_enable: source.obsolete.is_none() && source.parameters.is_none(),
            })
            .collect())
    }

    fn enabled_rulesets(&self) -> Result<Vec<Ruleset>> {
        let enabled = crate::actions::get_enabled_ruleset(self.0)?;
        if enabled.is_empty() {
            return Ok(vec![]);
        }
        let index = crate::actions::load_rule_index(self.0).ok();
        Ok(enabled
            .into_iter()
            .map(|id| {
                let summary = index
                    .as_ref()
                    .and_then(|index| index.sources.get(&id))
                    .map(|source| source.summary.clone());
                Ruleset {
                    id,
                    summary,
                    can_enable: false,
                }
            })
            .collect())
    }

    fn enable_ruleset(&self, id: &str) -> Result<()> {
        crate::actions::enable_ruleset(self.0, id)
    }

    fn disable_ruleset(&self, id: &str) -> Result<()> {
        crate::actions::disable_ruleset(self.0, id)
    }

    fn update_sources(&self) -> Result<()> {
        crate::actions::update_sources(self.0)
    }

    fn update_rules(&self) -> Result<()> {
        crate::actions::update_rules(self.0, &[])
    }

    fn override_path(&self, file: OverrideFile) -> Option<PathBuf> {
        Some(self.0.config_dir().join(file.filename()))
    }

    fn write_override_template(&self, file: OverrideFile) -> Result<()> {
        let source = format!(
            "/usr/lib/suricata/python/suricata/update/configs/{}",
            file.filename()
        );
        let output = RunCommandBuilder::new(self.0.manager, self.0.image_name(Container::Suricata))
            .rm()
            .args(&["cat", &source])
            .build()
            .status_output()?;
        std::fs::create_dir_all(self.0.config_dir())?;
        std::fs::write(self.0.config_dir().join(file.filename()), output)?;
        Ok(())
    }
}
