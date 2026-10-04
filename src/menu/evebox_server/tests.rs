// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use super::*;
use std::cell::Cell;

struct FakeBackend {
    search_engines: bool,
    addresses: Vec<BindAddress>,
    resets: Cell<usize>,
}

impl FakeBackend {
    fn new(search_engines: bool) -> Self {
        Self {
            search_engines,
            addresses: vec![],
            resets: Cell::new(0),
        }
    }
}

impl Backend for FakeBackend {
    fn supports_search_engines(&self) -> bool {
        self.search_engines
    }

    fn bind_addresses(&self) -> Result<Vec<BindAddress>> {
        Ok(self.addresses.clone())
    }

    fn reset_password(&self) -> Result<()> {
        self.resets.set(self.resets.get() + 1);
        Ok(())
    }
}

fn tags(config: &Config, backend: &dyn Backend) -> Vec<Options> {
    menu_options(config, backend)
        .to_vec()
        .into_iter()
        .map(|item| item.tag)
        .collect()
}

#[test]
fn datastore_options_are_only_offered_with_search_engine_support() {
    let mut config = Config::default();
    config.evebox_server.enabled = true;

    assert_eq!(
        tags(&config, &FakeBackend::new(false)),
        [
            Options::EnableToggle,
            Options::EnableRemote,
            Options::ToggleTls,
            Options::ToggleAuth,
            Options::ResetPassword,
            Options::Return,
        ]
    );
    assert_eq!(
        tags(&config, &FakeBackend::new(true)),
        [
            Options::EnableToggle,
            Options::EnableRemote,
            Options::ToggleTls,
            Options::ToggleAuth,
            Options::Datastore,
            Options::ResetPassword,
            Options::Return,
        ]
    );

    config.elasticsearch.enabled = true;
    assert!(tags(&config, &FakeBackend::new(true)).contains(&Options::Memory));
    assert!(!tags(&config, &FakeBackend::new(false)).contains(&Options::Memory));

    config.evebox_server.use_external_elasticsearch = true;
    assert!(tags(&config, &FakeBackend::new(true)).contains(&Options::ElasticsearchUrl));
    let without = tags(&config, &FakeBackend::new(false));
    assert!(!without.contains(&Options::ElasticsearchUrl));
    assert!(!without.contains(&Options::Datastore));

    for action in [
        Options::Datastore,
        Options::Memory,
        Options::ElasticsearchUrl,
    ] {
        assert!(run_action(&mut config, &FakeBackend::new(false), &action).is_err());
    }
}

#[test]
fn labels_reflect_remote_access_tls_and_authentication_state() {
    let mut config = Config::default();
    let backend = FakeBackend::new(false);
    let labels = |config: &Config| -> Vec<String> {
        menu_options(config, &backend)
            .to_vec()
            .into_iter()
            .map(|item| item.value)
            .collect()
    };

    let items = labels(&config);
    assert!(items[0].ends_with("Enable EveBox Server [disabled]"));
    assert!(items[1].ends_with("Enable Remote Access [disabled]"));
    assert!(items[2].ends_with("Toggle TLS [enabled]"));
    assert!(items[3].ends_with("Toggle authentication [enabled]"));

    config.evebox_server.enabled = true;
    config.evebox_server.allow_remote = true;
    config.evebox_server.no_tls = true;
    config.evebox_server.no_auth = true;
    let items = labels(&config);
    assert!(items[0].ends_with("Disable EveBox Server [enabled]"));
    assert!(items[1].ends_with("Disable Remote Access [enabled]"));
    assert!(items[2].ends_with("Bind Address [all interfaces]"));
    assert!(items[3].ends_with("Toggle TLS [disabled]"));
    assert!(items[4].ends_with("Toggle authentication [disabled]"));

    config.evebox_server.bind_address = Some("192.0.2.1".to_string());
    assert!(labels(&config)[2].ends_with("Bind Address [192.0.2.1]"));
    config.evebox_server.bind_address = Some("eth0".to_string());
    assert!(labels(&config)[2].ends_with("Bind Address [interface: eth0]"));
}

#[test]
fn toggles_without_remote_access_do_not_prompt() {
    let mut server = EveBoxServerConfig::default();
    toggle_tls(&mut server);
    assert!(server.no_tls);
    toggle_tls(&mut server);
    assert!(!server.no_tls);

    toggle_auth(&mut server);
    assert!(server.no_auth);
    toggle_auth(&mut server);
    assert!(!server.no_auth);
    assert!(!server.no_tls);

    // Re-enabling only touches its own setting.
    server.no_tls = true;
    server.no_auth = true;
    toggle_auth(&mut server);
    assert!(server.no_tls);
    assert!(!server.no_auth);
}

#[test]
fn bind_address_choices_start_with_all_interfaces_and_track_current_value() {
    let addresses = vec![
        BindAddress {
            interface: "eth0".to_string(),
            address: "192.0.2.1".to_string(),
        },
        BindAddress {
            interface: "eth0".to_string(),
            address: "192.0.2.2".to_string(),
        },
        BindAddress {
            interface: "eth1".to_string(),
            address: "198.51.100.1".to_string(),
        },
    ];
    let options = bind_address_options(&addresses);
    assert_eq!(
        options.iter().map(|o| o.label.as_str()).collect::<Vec<_>>(),
        [
            "All interfaces",
            "192.0.2.1 (eth0)",
            "192.0.2.2 (eth0)",
            "198.51.100.1 (eth1)",
        ]
    );
    assert_eq!(options[0].address, None);
    assert_eq!(options[3].address.as_deref(), Some("198.51.100.1"));

    assert_eq!(bind_address_cursor(&addresses, None), 0);
    assert_eq!(bind_address_cursor(&addresses, Some("192.0.2.2")), 2);
    assert_eq!(bind_address_cursor(&addresses, Some("eth1")), 3);
    assert_eq!(bind_address_cursor(&addresses, Some("eth0")), 1);
    assert_eq!(bind_address_cursor(&addresses, Some("203.0.113.1")), 0);
    assert_eq!(bind_address_cursor(&addresses, Some("missing")), 0);
}

#[test]
fn bind_address_requires_an_available_ipv4_address() {
    let mut server = EveBoxServerConfig {
        bind_address: Some("eth0".to_string()),
        ..Default::default()
    };
    let err = set_bind_address(&mut server, &FakeBackend::new(false)).unwrap_err();
    assert!(err.to_string().contains("No network interfaces"));
    assert_eq!(server.bind_address.as_deref(), Some("eth0"));
}

#[test]
fn disabling_remote_access_and_password_reset_dispatch_to_backend() {
    let backend = FakeBackend::new(false);
    let mut config = Config::default();
    config.evebox_server.allow_remote = true;
    run_action(&mut config, &backend, &Options::DisableRemote).unwrap();
    assert!(!config.evebox_server.allow_remote);

    run_action(&mut config, &backend, &Options::ResetPassword).unwrap();
    assert_eq!(backend.resets.get(), 1);

    run_action(&mut config, &backend, &Options::EnableToggle).unwrap();
    assert!(config.evebox_server.enabled);
    run_action(&mut config, &backend, &Options::Return).unwrap();
    assert_eq!(backend.resets.get(), 1);
}
