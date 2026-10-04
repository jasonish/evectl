// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use super::*;
use std::path::PathBuf;

struct UnusedSuricata;

impl crate::suricata::configuration::Backend for UnusedSuricata {
    fn interfaces(&self) -> Result<Vec<crate::suricata::configuration::Interface>> {
        unreachable!()
    }
    fn eve_outputs(&self) -> &'static [crate::config::EveOutput] {
        unreachable!()
    }
    fn filestore_dir(&self) -> Result<PathBuf> {
        unreachable!()
    }
    fn check_remove_extracted_files(&self) -> Result<()> {
        unreachable!()
    }
    fn remove_extracted_files(&self) -> Result<()> {
        unreachable!()
    }
}

struct UnusedFpc;

impl crate::fpc::Backend for UnusedFpc {
    fn spool_dir(&self) -> Result<PathBuf> {
        unreachable!()
    }
    fn check_remove_spool(&self) -> Result<()> {
        unreachable!()
    }
    fn remove_spool(&self) -> Result<()> {
        unreachable!()
    }
}

#[derive(Default)]
struct FakeBackend {
    options: Vec<PlatformOption>,
    calls: Vec<String>,
}

impl Backend for FakeBackend {
    fn suricata(&self) -> Box<dyn crate::suricata::configuration::Backend + '_> {
        Box::new(UnusedSuricata)
    }

    fn fpc(&self) -> Box<dyn crate::fpc::Backend + '_> {
        Box::new(UnusedFpc)
    }

    fn configure_evebox_server(&mut self, config: &mut Config) -> Result<()> {
        self.calls.push("server".to_string());
        config.evebox_server.enabled = true;
        Ok(())
    }

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

    fn run_platform_option(&mut self, config: &mut Config, id: &str) -> Result<()> {
        self.calls.push(format!("platform:{id}"));
        match id {
            "ok" => {
                config.suricata.interfaces = vec!["eth1".to_string()];
                Ok(())
            }
            _ => bail!("Unsupported option {id}"),
        }
    }
}

fn labels(selections: &Selections<Options>) -> Vec<String> {
    selections
        .to_vec()
        .into_iter()
        .map(|item| item.value)
        .collect()
}

#[test]
fn shared_options_reflect_config_and_platform_options_precede_return() {
    let backend = FakeBackend {
        options: vec![PlatformOption {
            id: "ok",
            label: "Platform Only".to_string(),
        }],
        calls: vec![],
    };

    let mut config = Config::default();
    let items = labels(&menu_options(&config, &backend));
    assert_eq!(
        items,
        [
            "Configure Suricata [enabled=false, interface=None]",
            "Configure EveBox Agent [enabled=false]",
            "Configure EveBox Server [enabled=false]",
            "Configure Full Packet Capture [enabled=false]",
            "Platform Only",
            "Return",
        ]
    );

    config.suricata.enabled = true;
    config.suricata.interfaces = vec!["eth0".to_string(), "eth1".to_string()];
    config.evebox_agent.enabled = true;
    config.evebox_server.enabled = true;
    config.fpc.enabled = true;
    let selections = menu_options(&config, &backend);
    let items = labels(&selections);
    assert_eq!(
        items,
        [
            "Configure Suricata [enabled=true, interface=eth0]",
            "Configure EveBox Agent [enabled=true]",
            "Configure EveBox Server [enabled=true]",
            "Configure Full Packet Capture [enabled=true]",
            "Platform Only",
            "Conditional",
            "Return",
        ]
    );
    let tags: Vec<Options> = selections
        .to_vec()
        .into_iter()
        .map(|item| item.tag)
        .collect();
    assert_eq!(tags[4], Options::Platform("ok"));
    assert_eq!(tags[5], Options::Platform("conditional"));
    assert_eq!(tags.last(), Some(&Options::Return));
}

#[test]
fn actions_dispatch_to_backend_and_report_failures() {
    let mut backend = FakeBackend::default();
    let mut config = Config::default();

    run_action(&mut config, &mut backend, &Options::EveBoxServer).unwrap();
    assert!(config.evebox_server.enabled);

    run_action(&mut config, &mut backend, &Options::Platform("ok")).unwrap();
    assert_eq!(config.suricata.interfaces, ["eth1"]);

    let err = run_action(&mut config, &mut backend, &Options::Platform("missing")).unwrap_err();
    assert!(err.to_string().contains("missing"));

    run_action(&mut config, &mut backend, &Options::Return).unwrap();
    assert_eq!(backend.calls, ["server", "platform:ok", "platform:missing"]);
}
