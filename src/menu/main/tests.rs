// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use super::*;
use crate::menu::test_support::FakePlatform;

#[test]
fn service_actions_follow_status() {
    let mut config = Config::default();
    let tail = [
        Options::Update,
        Options::Configure,
        Options::Other,
        Options::Exit,
    ];
    let tags = |config: &Config, status: Status| menu_options(config, status).tags();

    let stopped = Status {
        running: false,
        ready_to_start: true,
        restart_recommended: false,
    };
    let mut expected = vec![Options::Refresh, Options::Start];
    expected.extend(tail);
    assert_eq!(tags(&config, stopped), expected);

    let running = Status {
        running: true,
        ..stopped
    };
    let mut expected = vec![Options::Refresh, Options::Restart, Options::Stop];
    expected.extend(tail);
    assert_eq!(tags(&config, running), expected);

    let not_installed = Status {
        ready_to_start: false,
        ..stopped
    };
    let mut expected = vec![Options::Refresh, Options::Install];
    expected.extend(tail);
    assert_eq!(tags(&config, not_installed), expected);

    // After an EveCtl update, a restart is offered even when stopped,
    // but only if the services can start.
    let updated = Status {
        restart_recommended: true,
        ..stopped
    };
    let mut expected = vec![Options::Refresh, Options::Restart, Options::Start];
    expected.extend(tail);
    assert_eq!(tags(&config, updated), expected);
    let updated_not_installed = Status {
        restart_recommended: true,
        ..not_installed
    };
    let mut expected = vec![Options::Refresh, Options::Install];
    expected.extend(tail);
    assert_eq!(tags(&config, updated_not_installed), expected);

    config.suricata.enabled = true;
    let items = tags(&config, stopped);
    assert_eq!(
        &items[2..4],
        [Options::UpdateRules, Options::ManageRules],
        "{items:?}"
    );
    assert_eq!(&items[4..], tail);
}

#[test]
fn unchanged_configuration_is_not_saved() {
    let mut backend = FakePlatform::default();
    let config = Config::default();
    let mut original = config.clone();
    assert!(!save_changes(&config, &mut original, &mut backend).unwrap());
    assert_eq!(backend.saves.get(), 0);
}

#[test]
fn changed_configuration_is_saved_and_needs_a_restart() {
    let mut backend = FakePlatform::default();
    let mut config = Config::default();
    let original_config = config.clone();
    let mut original = config.clone();
    config.suricata.enabled = true;
    assert!(save_changes(&config, &mut original, &mut backend).unwrap());
    assert_eq!(backend.saves.get(), 1);
    // Still pending until a restart happens.
    assert_eq!(original, original_config);
}

#[test]
fn acknowledged_changes_are_saved_without_a_restart() {
    let mut backend = FakePlatform {
        acknowledge_channel: true,
        ..Default::default()
    };
    let mut config = Config::default();
    let mut original = config.clone();
    config.windows.evebox_channel = crate::config::EveBoxChannel::Release;
    assert!(!save_changes(&config, &mut original, &mut backend).unwrap());
    assert_eq!(backend.saves.get(), 1);
    assert_eq!(original, config);

    // Other changes alongside still need a restart.
    config.suricata.enabled = true;
    assert!(save_changes(&config, &mut original, &mut backend).unwrap());
    assert_eq!(backend.saves.get(), 2);
    assert!(!original.suricata.enabled);
    assert_eq!(
        original.windows.evebox_channel,
        config.windows.evebox_channel
    );
}
