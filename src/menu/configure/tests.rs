// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use super::*;
use crate::menu::test_support::FakePlatform;

#[test]
fn shared_options_reflect_config_and_platform_options_precede_return() {
    let backend = FakePlatform {
        options: vec![PlatformOption {
            id: "ok",
            label: "Platform Only".to_string(),
        }],
        ..Default::default()
    };

    let mut config = Config::default();
    assert_eq!(
        menu_options(&config, &backend).labels(),
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
    assert_eq!(
        selections.labels(),
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
    let tags = selections.tags();
    assert_eq!(tags[4], Options::Platform("ok"));
    assert_eq!(tags[5], Options::Platform("conditional"));
    assert_eq!(tags.last(), Some(&Options::Return));
}

#[test]
fn actions_dispatch_to_backend_and_report_failures() {
    let mut backend = FakePlatform::default();
    let mut config = Config::default();

    run_action(&mut config, &mut backend, &Options::EveBoxServer).unwrap();
    assert!(config.evebox_server.enabled);

    run_action(&mut config, &mut backend, &Options::Platform("ok")).unwrap();
    assert_eq!(config.suricata.interfaces, ["eth1"]);

    let err = run_action(&mut config, &mut backend, &Options::Platform("missing")).unwrap_err();
    assert!(err.to_string().contains("missing"));

    run_action(&mut config, &mut backend, &Options::Return).unwrap();
    assert_eq!(
        backend.calls(),
        ["server", "platform:ok", "platform:missing"]
    );
}
