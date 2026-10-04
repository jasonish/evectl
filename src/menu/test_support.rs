// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! One fake platform for the menu tests, implementing every backend
//! trait the menus are written against. Fields default to the least
//! surprising value; tests set only what they exercise.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;

use crate::config::EveOutput;
use crate::evebox::configuration::BindAddress;
use crate::menu::configure::PlatformOption;
use crate::menu::main::{Status, UpdateOutcome};
use crate::prelude::*;
use crate::rules::{OverrideFile, Ruleset};
use crate::suricata::configuration::Interface;

#[derive(Clone)]
pub(crate) struct FakePlatform {
    /// The packet capture spool and extracted files directory.
    pub(crate) dir: PathBuf,
    pub(crate) outputs: &'static [EveOutput],
    pub(crate) fail_interfaces: bool,
    pub(crate) search_engines: bool,
    pub(crate) addresses: Vec<BindAddress>,
    /// Services are running: leftover data cannot be removed.
    pub(crate) blocked: Cell<bool>,
    pub(crate) removed: Cell<bool>,
    pub(crate) available: Vec<Ruleset>,
    pub(crate) enabled: Vec<Ruleset>,
    pub(crate) overrides: bool,
    pub(crate) options: Vec<PlatformOption>,
    pub(crate) acknowledge_channel: bool,
    pub(crate) saves: Cell<usize>,
    /// The recorded operation that fails, e.g. "update" or "remove".
    pub(crate) fail: Option<&'static str>,
    /// Recorded operations as "operation:id".
    pub(crate) calls: RefCell<Vec<String>>,
}

impl Default for FakePlatform {
    fn default() -> Self {
        Self {
            dir: PathBuf::new(),
            outputs: &[EveOutput::File],
            fail_interfaces: false,
            search_engines: false,
            addresses: vec![],
            blocked: Cell::new(false),
            removed: Cell::new(false),
            available: vec![],
            enabled: vec![],
            overrides: false,
            options: vec![],
            acknowledge_channel: false,
            saves: Cell::new(0),
            fail: None,
            calls: RefCell::new(vec![]),
        }
    }
}

impl FakePlatform {
    pub(crate) fn with_dir(dir: &std::path::Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            ..Default::default()
        }
    }

    pub(crate) fn record(&self, operation: &str, id: &str) -> Result<()> {
        self.calls.borrow_mut().push(format!("{operation}:{id}"));
        if self.fail == Some(operation) {
            bail!("{operation} failed");
        }
        Ok(())
    }

    pub(crate) fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    pub(crate) fn as_fpc(&self) -> &dyn crate::fpc::Backend {
        self
    }

    pub(crate) fn as_suricata(&self) -> &dyn crate::suricata::configuration::Backend {
        self
    }

    fn check_remove(&self) -> Result<()> {
        if self.blocked.get() {
            bail!("Service is running or cannot be inspected");
        }
        Ok(())
    }

    fn remove(&self) -> Result<()> {
        self.check_remove()?;
        self.record("remove", "")?;
        self.removed.set(true);
        Ok(())
    }
}

impl crate::suricata::configuration::Backend for FakePlatform {
    fn interfaces(&self) -> Result<Vec<Interface>> {
        if self.fail_interfaces {
            bail!("Interface discovery failed");
        }
        Ok(vec![])
    }
    fn eve_outputs(&self) -> &'static [EveOutput] {
        self.outputs
    }
    fn filestore_dir(&self) -> Result<PathBuf> {
        Ok(self.dir.clone())
    }
    fn check_remove_extracted_files(&self) -> Result<()> {
        self.check_remove()
    }
    fn remove_extracted_files(&self) -> Result<()> {
        self.remove()
    }
}

impl crate::fpc::Backend for FakePlatform {
    fn spool_dir(&self) -> Result<PathBuf> {
        Ok(self.dir.clone())
    }
    fn check_remove_spool(&self) -> Result<()> {
        self.check_remove()
    }
    fn remove_spool(&self) -> Result<()> {
        self.remove()
    }
}

impl crate::evebox::configuration::Backend for FakePlatform {
    fn supports_search_engines(&self) -> bool {
        self.search_engines
    }
    fn bind_addresses(&self) -> Result<Vec<BindAddress>> {
        Ok(self.addresses.clone())
    }
    fn reset_password(&self) -> Result<()> {
        self.record("reset_password", "")
    }
}

impl crate::rules::Backend for FakePlatform {
    fn available_rulesets(&self) -> Result<Vec<Ruleset>> {
        self.record("available", "")?;
        Ok(self.available.clone())
    }
    fn enabled_rulesets(&self) -> Result<Vec<Ruleset>> {
        self.record("enabled", "")?;
        Ok(self.enabled.clone())
    }
    fn enable_ruleset(&self, id: &str) -> Result<()> {
        self.record("enable", id)
    }
    fn disable_ruleset(&self, id: &str) -> Result<()> {
        self.record("disable", id)
    }
    fn update_rules(&self) -> Result<()> {
        self.record("update", "")
    }
    fn update_sources(&self) -> Result<()> {
        self.record("sources", "")
    }
    fn override_path(&self, file: OverrideFile) -> Option<PathBuf> {
        self.overrides.then(|| PathBuf::from(file.filename()))
    }
}

/// Sub-backends are snapshots; the Configure tests do not exercise them.
impl crate::menu::configure::Backend for FakePlatform {
    fn suricata(&self) -> Box<dyn crate::suricata::configuration::Backend + '_> {
        Box::new(self.clone())
    }
    fn fpc(&self) -> Box<dyn crate::fpc::Backend + '_> {
        Box::new(self.clone())
    }
    fn configure_evebox_server(&mut self, config: &mut Config) -> Result<()> {
        self.calls.borrow_mut().push("server".to_string());
        config.evebox_server.enabled = true;
        Ok(())
    }
    /// A "conditional" option appears while packet capture is enabled.
    fn platform_options(&self, config: &Config) -> Vec<PlatformOption> {
        let mut options = self.options.clone();
        if config.fpc.enabled {
            options.push(PlatformOption {
                id: "conditional",
                label: "Conditional".to_string(),
            });
        }
        options
    }
    /// Only the "ok" option succeeds, selecting the eth1 interface.
    fn run_platform_option(&mut self, config: &mut Config, id: &str) -> Result<()> {
        self.calls.borrow_mut().push(format!("platform:{id}"));
        match id {
            "ok" => {
                config.suricata.interfaces = vec!["eth1".to_string()];
                Ok(())
            }
            _ => bail!("Unsupported option {id}"),
        }
    }
}

impl crate::menu::main::Backend for FakePlatform {
    fn status(&mut self, _config: &Config) -> Status {
        Status::default()
    }
    fn save_config(&mut self, _config: &Config) -> Result<()> {
        self.saves.set(self.saves.get() + 1);
        Ok(())
    }
    fn acknowledge_saved_changes(&mut self, original: &mut Config, current: &Config) {
        if self.acknowledge_channel {
            original.windows.evebox_channel = current.windows.evebox_channel;
        }
    }
    fn start(&mut self, _config: &Config) -> Result<()> {
        unreachable!()
    }
    fn stop(&mut self, _config: &Config) -> Result<()> {
        unreachable!()
    }
    fn restart(&mut self, _config: &Config) -> Result<()> {
        unreachable!()
    }
    fn install(&mut self, _config: &mut Config) -> Result<()> {
        unreachable!()
    }
    fn update_rules(&mut self, _config: &Config) -> Result<()> {
        unreachable!()
    }
    fn rules(&mut self, _config: &Config) -> Box<dyn crate::rules::Backend + '_> {
        Box::new(self.clone())
    }
    fn update(&mut self, _config: &Config) -> Result<UpdateOutcome> {
        unreachable!()
    }
    fn configure(&mut self, _config: &mut Config) -> Result<()> {
        unreachable!()
    }
    fn other(&mut self, _config: &mut Config) -> Result<()> {
        unreachable!()
    }
}
