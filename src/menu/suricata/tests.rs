// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use super::*;
use crate::menu::test_support::FakePlatform;

#[test]
fn shared_options_gate_output_selection_and_extraction_settings() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    for outputs in [
        &[EveOutput::File][..],
        &[EveOutput::UnixStream, EveOutput::File][..],
    ] {
        let backend = FakePlatform {
            outputs,
            ..FakePlatform::with_dir(dir.path())
        };
        for enabled in [false, true] {
            config.suricata.file_extraction.enabled = enabled;
            let options = menu_options(&config, &backend).unwrap().tags();
            let mut expected = vec![
                Options::Toggle,
                Options::Interface,
                Options::SensorName,
                Options::Bpf,
            ];
            if outputs.len() > 1 {
                expected.push(Options::EveOutput);
            }
            expected.push(Options::FileExtraction);
            if enabled {
                expected.extend([
                    Options::FileExtractionForceFilestore,
                    Options::FileExtractionMaxSize,
                    Options::FileExtractionRetention,
                ]);
            }
            expected.push(Options::Exit);
            assert_eq!(options, expected);
        }
    }
}

#[test]
fn menu_labels_reflect_config_and_backend_filestore() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("extracted"), b"fixture").unwrap();
    let backend = FakePlatform::with_dir(dir.path());
    let mut config = Config::default();
    config.suricata.enabled = true;
    config.suricata.interfaces = vec!["Ethernet 2".into()];
    config.suricata.sensor_name = Some("sensor".into());
    config.suricata.bpf = Some("not port 22".into());
    let items = menu_options(&config, &backend).unwrap().to_vec();
    assert_eq!(items[0].value, "Disable Suricata");
    assert_eq!(items[1].value, "Select Interface (current: Ethernet 2)");
    assert_eq!(items[2].value, "Sensor Name (current: sensor)");
    assert_eq!(items[3].value, "BPF filter (current: \"not port 22\")");
    let removal = items
        .iter()
        .find(|item| item.tag == Options::FileExtractionRemove)
        .unwrap();
    assert!(removal.value.contains(&dir.path().display().to_string()));
    config.suricata.file_extraction.enabled = true;
    assert!(
        !menu_options(&config, &backend)
            .unwrap()
            .tags()
            .contains(&Options::FileExtractionRemove)
    );
    assert!(run_action(&mut config, &backend, Options::FileExtractionRemove).is_err());
}

#[test]
fn toggle_selects_only_when_enabling_without_an_interface() {
    let mut config = Config::default();
    toggle_enabled(&mut config, || Ok("Ethernet 2".into())).unwrap();
    assert!(config.suricata.enabled);
    assert_eq!(config.suricata.interfaces, ["Ethernet 2"]);
    toggle_enabled(&mut config, || panic!("Must not prompt when disabling")).unwrap();
    assert!(!config.suricata.enabled);
    toggle_enabled(&mut config, || panic!("Must keep configured interface")).unwrap();
    assert!(config.suricata.enabled);
    assert_eq!(config.suricata.interfaces, ["Ethernet 2"]);
}

#[test]
fn cancelled_interface_prompt_preserves_existing_toggle_behavior() {
    for error in [
        inquire::InquireError::OperationCanceled,
        inquire::InquireError::OperationInterrupted,
    ] {
        let mut config = Config::default();
        let error = toggle_enabled(&mut config, || Err(error.into())).unwrap_err();
        assert!(crate::prompt::cancelled(&error));
        // Both old menus left Suricata enabled after canceling this prompt.
        assert!(config.suricata.enabled);
        assert!(config.suricata.interfaces.is_empty());
    }
    assert!(!crate::prompt::cancelled(&anyhow!("Discovery failed")));
}

#[test]
fn interface_discovery_failures_and_empty_lists_keep_existing_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.suricata.interfaces = vec!["existing".into()];
    for fail_interfaces in [false, true] {
        let backend = FakePlatform {
            fail_interfaces,
            ..FakePlatform::with_dir(dir.path())
        };
        let err = run_action(&mut config, &backend, Options::Interface).unwrap_err();
        assert!(!crate::prompt::cancelled(&err));
        assert_eq!(config.suricata.interfaces, ["existing"]);
    }
}

#[test]
fn interface_choices_store_names_not_display_labels() {
    let choices = interface_choices(vec![
        Interface {
            name: "eth0".into(),
            address: Some("192.0.2.1".into()),
        },
        Interface {
            name: "Ethernet 2".into(),
            address: None,
        },
    ])
    .unwrap()
    .to_vec();
    assert_eq!(choices[0].tag, "eth0");
    assert!(choices[0].value.contains("192.0.2.1"));
    assert_eq!(choices[1].tag, "Ethernet 2");
    assert!(!choices[1].value.contains("--"));
    assert!(interface_choices(vec![]).is_err());
}

#[test]
fn fixed_output_backend_does_not_offer_or_change_output_configuration() {
    let mut config = Config::default();
    let previous = config.suricata.eve_output;
    set_eve_output(&mut config, &[EveOutput::File]).unwrap();
    assert_eq!(config.suricata.eve_output, previous);
}
