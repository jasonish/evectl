// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use super::*;
use crate::menu::test_support::FakePlatform;
use std::cell::Cell;

#[test]
fn menu_shares_credentials_and_gates_spool_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    for has_captures in [false, true] {
        if has_captures {
            std::fs::write(dir.path().join("log.0.1.pcap"), b"fixture").unwrap();
        }
        for agent in [false, true] {
            config.evebox_agent.enabled = agent;
            config.evebox_agent.key = Some("never-show-this-key".into());
            for enabled in [false, true] {
                config.fpc.enabled = enabled;
                let items = menu_options(&config, dir.path()).to_vec();
                let mut expected = vec![Options::Toggle, Options::MaxFiles];
                if agent {
                    expected.extend([Options::AgentId, Options::Key]);
                }
                if has_captures && !enabled {
                    expected.push(Options::RemoveSpool);
                }
                expected.push(Options::Return);
                assert_eq!(
                    items.iter().map(|item| item.tag).collect::<Vec<_>>(),
                    expected
                );
                assert_eq!(
                    items[0].value,
                    if enabled {
                        "Disable Full Packet Capture"
                    } else {
                        "Enable Full Packet Capture"
                    }
                );
                assert!(items[1].value.contains(&config.fpc.disk_usage()));
                assert!(
                    items
                        .iter()
                        .all(|item| !item.value.contains("never-show-this-key"))
                );
                if let Some(item) = items.iter().find(|item| item.tag == Options::RemoveSpool) {
                    assert!(item.value.contains(&dir.path().display().to_string()));
                }
            }
        }
    }
}

#[test]
fn enabling_requires_suricata_and_a_local_retrieval_service() {
    for suricata in [false, true] {
        for server in [false, true] {
            for agent in [false, true] {
                let mut config = Config::default();
                config.suricata.enabled = suricata;
                config.evebox_server.enabled = server;
                config.evebox_agent.enabled = agent;
                let allowed = suricata && (server || agent);
                let setup_called = Cell::new(false);
                let confirm_called = Cell::new(false);
                let usage = config.fpc.disk_usage();
                let result = enable_capture(
                    &mut config,
                    |_| {
                        setup_called.set(true);
                        true
                    },
                    |message| {
                        assert!(message.contains(&usage));
                        confirm_called.set(true);
                        true
                    },
                );
                assert_eq!(result.is_ok(), allowed);
                assert_eq!(setup_called.get(), allowed && agent);
                assert_eq!(confirm_called.get(), allowed);
                assert_eq!(config.fpc.enabled, allowed);
            }
        }
    }
}

#[test]
fn enabling_can_be_cancelled_during_credentials_or_confirmation() {
    let mut config = Config::default();
    config.suricata.enabled = true;
    config.evebox_agent.enabled = true;
    enable_capture(&mut config, |_| false, |_| panic!("Must not confirm")).unwrap();
    assert!(!config.fpc.enabled);
    enable_capture(&mut config, |_| true, |_| false).unwrap();
    assert!(!config.fpc.enabled);
}

#[test]
fn disabling_does_not_require_services_or_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.fpc.enabled = true;
    config.fpc.max_files = Some(123);
    toggle_enabled(&mut config, dir.path()).unwrap();
    assert!(!config.fpc.enabled);
    assert_eq!(config.fpc.max_files, Some(123));
}

#[test]
fn retention_validation_preserves_total_file_count_and_rejects_invalid_values() {
    for threads in [1, 4, 128] {
        for input in ["", "0", "-1", "invalid", "1.5", "4294967296"] {
            assert!(parse_max_files(input, threads).is_err());
        }
        assert!(parse_max_files(&(threads - 1).to_string(), threads).is_err());
        let total = threads as u32 * 3 + 1;
        assert_eq!(
            parse_max_files(&format!(" {total} "), threads).unwrap(),
            total
        );
        let fpc = FpcConfig {
            enabled: true,
            max_files: Some(total),
        };
        assert_eq!(
            fpc.effective_max_files_for(threads),
            total / threads as u32 * threads as u32
        );
    }
    assert_eq!(
        parse_max_files("100", 4).unwrap(),
        FpcConfig::DEFAULT_MAX_FILES
    );
}

#[test]
fn cleanup_requires_disabled_capture_and_stopped_suricata() {
    let dir = tempfile::tempdir().unwrap();
    let backend = FakePlatform::with_dir(dir.path());
    let mut config = Config::default();
    config.fpc.enabled = true;
    assert!(run_action(&mut config, &backend, dir.path(), Options::RemoveSpool).is_err());
    assert!(!backend.removed.get());
    backend.blocked.set(true);
    assert!(
        cleanup::remove_with_confirmation(backend.as_fpc(), |_| panic!("Must not prompt")).is_err()
    );
    backend.blocked.set(false);
    cleanup::remove_with_confirmation(backend.as_fpc(), |message| {
        assert!(message.contains("packet captures"));
        assert!(message.contains(&dir.path().display().to_string()));
        true
    })
    .unwrap();
    assert!(backend.removed.get());
}
