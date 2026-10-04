// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! The services EveCtl manages, and starting and stopping them as a
//! set. The per-service details (commands, images, directories) live
//! in each service's own module; this module only knows the table.

use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use crate::UpdateContinuationArgs;
use crate::prelude::*;
use crate::{elastic, evebox, housekeeper, menu, rules, suricata};

/// A service EveCtl may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Service {
    SearchEngine,
    EveBoxServer,
    EveBoxAgent,
    Suricata,
    Housekeeper,
}

impl Service {
    /// Every service, in the order they are started.
    pub(crate) const ALL: [Service; 5] = [
        Service::SearchEngine,
        Service::EveBoxServer,
        Service::EveBoxAgent,
        Service::Suricata,
        Service::Housekeeper,
    ];

    /// Every service, in the order they are stopped. The housekeeper
    /// goes first as it works on Suricata's output.
    pub(crate) const STOP_ORDER: [Service; 5] = [
        Service::Housekeeper,
        Service::Suricata,
        Service::EveBoxServer,
        Service::EveBoxAgent,
        Service::SearchEngine,
    ];

    /// The name used in status and log messages.
    pub(crate) fn label(self, config: &Config) -> &'static str {
        match self {
            Service::SearchEngine => config.elasticsearch.engine.name(),
            Service::EveBoxServer => "EveBox-Server",
            Service::EveBoxAgent => "EveBox-Agent",
            Service::Suricata => "Suricata",
            Service::Housekeeper => "Housekeeper",
        }
    }

    /// The name of the container the service runs in.
    pub(crate) fn container_name(self, context: &Context) -> String {
        match self {
            Service::SearchEngine => elastic::container_name(context),
            Service::EveBoxServer => evebox::server::container_name(context),
            Service::EveBoxAgent => evebox::agent::container_name(context),
            Service::Suricata => suricata::container_name(context),
            Service::Housekeeper => housekeeper::container_name(context),
        }
    }

    /// Every container name the service may have used, including
    /// those of previous configurations and versions, for cleaning up.
    pub(crate) fn container_names(self, context: &Context) -> Vec<String> {
        match self {
            Service::SearchEngine => crate::config::SearchEngine::ALL
                .iter()
                .map(|engine| elastic::container_name_for(context, *engine))
                .collect(),
            Service::Housekeeper => vec![
                housekeeper::legacy_container_name(context),
                housekeeper::container_name(context),
            ],
            _ => vec![self.container_name(context)],
        }
    }

    /// The signal to stop the container with, if not the default.
    pub(crate) fn stop_signal(self) -> Option<&'static str> {
        match self {
            Service::EveBoxServer => Some("SIGINT"),
            _ => None,
        }
    }

    pub(crate) fn enabled(self, config: &Config) -> bool {
        match self {
            Service::SearchEngine => config.elasticsearch_enabled(),
            Service::EveBoxServer => config.evebox_server.enabled,
            Service::EveBoxAgent => config.evebox_agent.enabled,
            Service::Suricata => config.suricata.enabled,
            Service::Housekeeper => housekeeper::enabled_for(config),
        }
    }

    /// Start the service detached, or for the housekeeper, bring it
    /// in line with the configuration.
    fn start_detached(self, context: &Context) -> Result<()> {
        match self {
            Service::SearchEngine => elastic::start_elasticsearch(context),
            Service::EveBoxServer => evebox::server::start(context),
            Service::EveBoxAgent => evebox::agent::start(context),
            Service::Suricata => suricata::start_detached(context),
            Service::Housekeeper => housekeeper::reconcile(context),
        }
    }

    /// Stop and remove the service's containers.
    fn stop(self, context: &Context) -> bool {
        match self {
            Service::Housekeeper => match housekeeper::remove(context) {
                Ok(()) => true,
                Err(err) => {
                    error!("Failed to stop housekeeping: {err}");
                    false
                }
            },
            Service::SearchEngine => {
                // Stop both search engine container names even when the
                // service is disabled, in case it was disabled or changed
                // since the last start.
                let existing_engines = elastic::existing_engines(context);
                if existing_engines.is_empty() {
                    debug!("No search engine containers are running");
                } else {
                    for engine in existing_engines {
                        info!("Stopping {}", engine.name());
                    }
                }
                elastic::stop_elasticsearch(context);
                true
            }
            _ => {
                let name = self.container_name(context);
                if context.manager.container_exists(&name) {
                    info!("Stopping {}", self.label(&context.config));
                    stop_container(context, &name, self.stop_signal())
                } else {
                    debug!("Container {name} is not running");
                    true
                }
            }
        }
    }
}

/// Run when "start" is run from the command line.
pub(crate) fn command_start(context: &Context, debug: bool) -> i32 {
    if debug {
        if let Err(err) = start_foreground(context) {
            error!("Failed to run foreground services: {err:#}");
            return 1;
        }
    } else if !start(context) {
        return 1;
    }
    0
}

/// Spawn a command with its output logged under `label`, with `tx`
/// signaled when the output ends.
fn spawn_logged(mut command: Command, label: &'static str, tx: &Sender<bool>) -> Result<Child> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .inspect_err(|err| error!("Failed to spawn {label} process: {err}"))?;
    crate::process_output_handler(&mut child, label, tx.clone());
    Ok(child)
}

/// Wait for a container to be running, polling until `timeout` has
/// passed.
pub(crate) fn wait_until_running(context: &Context, name: &str, timeout: Duration) -> bool {
    let start = Instant::now();
    loop {
        if context.manager.is_running(name) {
            return true;
        }
        if start.elapsed() > timeout {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Start EveCtl in the foreground.
///
/// Typically not done from the menus but instead the command line.
pub(crate) fn start_foreground(context: &Context) -> Result<()> {
    info!("Starting services in the foreground");
    context.config.validate_start_configuration()?;

    for service in [
        Service::Suricata,
        Service::EveBoxServer,
        Service::EveBoxAgent,
    ] {
        let name = service.container_name(context);
        let _ = context.manager.stop(&name, None);
        context.manager.quiet_rm(&name);
    }
    elastic::stop_elasticsearch(context);

    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    {
        let tx = tx.clone();
        ctrlc::set_handler(move || {
            info!("Received shutdown signal, stopping containers");
            let _ = tx.send(true);
        })?;
    }
    let _housekeeper = housekeeper::ForegroundGuard(context);
    housekeeper::reconcile(context)?;

    let mut children = vec![];

    if context.config.elasticsearch_enabled() {
        let engine = context.config.elasticsearch.engine.name();
        if let Err(err) = elastic::create_data_dir(context) {
            error!("Failed to create data directory for {}: {}", engine, err);
            return Err(err);
        }
        let command = elastic::build_docker_command(context, false);
        debug!("Starting {}: {:?}", engine, &command);
        children.push((engine, spawn_logged(command, engine, &tx)?));
    }

    // Sleep for a moment to give the search engine container a chance
    // to be created.
    std::thread::sleep(Duration::from_secs(1));

    if context.config.evebox_server.enabled {
        let command = evebox::server::build_command(context, false)?;
        children.push((
            "evebox-server",
            spawn_logged(command, "evebox-server", &tx)?,
        ));
    } else {
        info!("EveBox-Server not enabled");
    }

    if context.config.evebox_agent.enabled {
        let command = evebox::agent::build_command(context, false)?;
        children.push(("evebox-agent", spawn_logged(command, "evebox-agent", &tx)?));
    } else {
        info!("EveBox-Agent not enabled");
    }

    if context.config.suricata.enabled {
        suricata::mkdirs(context)?;
        suricata::remove_engine_log(context);
        let command = match suricata::build_command(context, false) {
            Ok(command) => command,
            Err(err) => {
                error!("Invalid Suricata configuration: {}", err);
                return Err(err);
            }
        };
        info!("Starting Suricata: {:?}", &command);
        children.push(("suricata", spawn_logged(command, "suricata", &tx)?));
    } else {
        info!("Suricata not enabled");
    }

    if context.config.suricata.enabled
        && let Some(script) = suricata::eve_prune_script_for(context)
    {
        if wait_until_running(
            context,
            &suricata::container_name(context),
            Duration::from_secs(3),
        ) {
            if let Err(err) = suricata::start_eve_prune(context, &script) {
                error!("Failed to start EVE spool pruning: {err}");
            }
        } else {
            error!(
                "Timed out waiting for the Suricata container to start running, not starting EVE spool pruning"
            );
        }
    }

    if housekeeper::enabled(context)
        && !verify_containers_running(
            context,
            &[("Housekeeper", housekeeper::container_name(context))],
        )
    {
        stop_all(context);
        bail!("Housekeeper failed during foreground startup");
    }

    if children.is_empty() {
        info!("No processes started. Exiting");
        return Ok(());
    }

    let _ = rx.recv();
    // Stop housekeeping before waiting on foreground children, including
    // agent-only sessions. Waiting first could leave cleanup running forever.
    let stopped = stop_all(context);

    for (process, mut child) in children {
        match child.wait() {
            Ok(status) => {
                if !status.success() {
                    error!("Process {process} exited with error code {:?}", status);
                }
            }
            Err(err) => {
                error!(
                    "Failed to get exist status for process {process}: {:?}",
                    err
                );
            }
        }
    }

    if !stopped {
        bail!("Failed to stop foreground services");
    }
    Ok(())
}

pub(crate) fn stop_container(context: &Context, name: &str, signal: Option<&str>) -> bool {
    let mut ok = true;
    if context.manager.is_active(name)
        && let Err(err) = context.manager.stop(name, signal)
    {
        error!("Failed to stop container {name}: {err}");
        ok = false;
    }
    context.manager.quiet_rm(name);

    ok
}

pub(crate) fn stop_all(context: &Context) -> bool {
    let mut ok = true;
    for service in Service::STOP_ORDER {
        if !service.stop(context) {
            ok = false;
        }
    }
    ok
}

pub(crate) fn restart(context: &Context) {
    stop_all(context);
    if !start(context) {
        crate::prompt::enter();
    }
}

/// Returns true if everything started successfully, otherwise false
/// is return.
pub(crate) fn start(context: &Context) -> bool {
    if let Err(err) = context.config.validate_start_configuration() {
        error!("Invalid configuration: {err}");
        return false;
    }

    let mut ok = true;

    for service in Service::ALL {
        if service == Service::Housekeeper {
            // Reconcile even if Suricata was already running or cleanup
            // was disabled.
            if let Err(err) = service.start_detached(context) {
                error!("Failed to reconcile housekeeper: {err:#}");
                ok = false;
            }
        } else if service.enabled(&context.config) {
            let label = service.label(&context.config);
            info!("Starting {label}");
            if let Err(err) = service.start_detached(context) {
                error!("Failed to start {label}: {err}");
                ok = false;
            }
        }
    }

    let containers = enabled_containers(context);
    if !containers.is_empty() {
        std::thread::sleep(Duration::from_secs(2));
        if !verify_containers_running(context, &containers) {
            ok = false;
        }
    }

    ok
}

/// The labels and container names of the enabled services.
pub(crate) fn enabled_containers(context: &Context) -> Vec<(&'static str, String)> {
    Service::ALL
        .into_iter()
        .filter(|service| service.enabled(&context.config))
        .map(|service| {
            (
                service.label(&context.config),
                service.container_name(context),
            )
        })
        .collect()
}

pub(crate) fn verify_containers_running(context: &Context, containers: &[(&str, String)]) -> bool {
    let mut ok = true;
    for (label, name) in containers {
        match context.manager.state(name) {
            Ok(state) if state.running && !state.restarting => {
                debug!("{label} container {name} remained running after startup");
            }
            Ok(state) => {
                let detail = if state.error.is_empty() {
                    String::new()
                } else {
                    format!("; error: {}", state.error)
                };
                error!(
                    "{label} container {name} is {}; exit code {}{detail}",
                    state.status, state.exit_code
                );
                ok = false;
            }
            Err(err) => {
                error!("Failed to inspect {label} container {name}: {err}");
                ok = false;
            }
        }
    }
    ok
}

/// Main menu backed by the container runtime. The runtime snapshot's
/// configuration is synchronized from the menu's before each action.
struct MainMenuBackend<'a> {
    runtime: Context,
    update_continuation_args: &'a UpdateContinuationArgs,
}

impl MainMenuBackend<'_> {
    fn context(&mut self, config: &Config) -> &Context {
        if self.runtime.config != *config {
            self.runtime.config = config.clone();
        }
        &self.runtime
    }
}

impl menu::main::Backend for MainMenuBackend<'_> {
    fn status(&mut self, config: &Config) -> menu::main::Status {
        let context = self.context(config);
        crate::log_status(context);
        let running = enabled_containers(context)
            .iter()
            .any(|(_, name)| context.manager.is_running(name));
        menu::main::Status {
            running,
            ready_to_start: true,
            restart_recommended: false,
        }
    }

    fn start(&mut self, config: &Config) -> Result<()> {
        if start(self.context(config)) {
            Ok(())
        } else {
            bail!("One or more services failed to start")
        }
    }

    fn stop(&mut self, config: &Config) -> Result<()> {
        if stop_all(self.context(config)) {
            Ok(())
        } else {
            bail!("One or more services failed to stop")
        }
    }

    fn restart(&mut self, config: &Config) -> Result<()> {
        let context = self.context(config);
        stop_all(context);
        if start(context) {
            Ok(())
        } else {
            bail!("One or more services failed to start")
        }
    }

    fn install(&mut self, _config: &mut Config) -> Result<()> {
        bail!("Containers are installed on start")
    }

    fn update_rules(&mut self, config: &Config) -> Result<()> {
        rules::update_rules(self.context(config), &[])
    }

    fn rules(&mut self, config: &Config) -> Box<dyn rules::Backend + '_> {
        Box::new(rules::ContainerBackend(self.context(config)))
    }

    fn update(&mut self, config: &Config) -> Result<menu::main::UpdateOutcome> {
        // A self-update replaces the process and never returns.
        let args = self.update_continuation_args;
        crate::update(self.context(config), args, false, true);
        Ok(menu::main::UpdateOutcome::Completed)
    }

    fn configure(&mut self, config: &mut Config) -> Result<()> {
        self.runtime.config = config.clone();
        let result = menu::configure::main(&mut self.runtime);
        *config = self.runtime.config.clone();
        result
    }

    fn other(&mut self, config: &mut Config) -> Result<()> {
        menu::other::menu(self.context(config));
        Ok(())
    }
}

pub(crate) fn menu_main(
    mut context: Context,
    update_continuation_args: &UpdateContinuationArgs,
) -> Result<()> {
    let mut backend = MainMenuBackend {
        runtime: context.clone(),
        update_continuation_args,
    };
    menu::main::menu(&mut context.config, &mut backend)
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use crate::container::{RESTART_POLICY_ARG, command_args};
    use crate::context::testing::docker_context;

    #[test]
    fn service_orders_cover_every_service_once() {
        for order in [Service::ALL, Service::STOP_ORDER] {
            for service in Service::ALL {
                assert_eq!(order.iter().filter(|s| **s == service).count(), 1);
            }
        }
    }

    #[test]
    fn container_names_include_retired_and_alternate_names() {
        let (_root, context) = docker_context(Config::default());
        let names: Vec<String> = Service::STOP_ORDER
            .iter()
            .flat_map(|service| service.container_names(&context))
            .collect();
        assert_eq!(names.len(), 7);
        assert_eq!(names[0], housekeeper::legacy_container_name(&context));
        assert_eq!(names[1], housekeeper::container_name(&context));
        assert!(names[5].ends_with("-elastic"));
        assert!(names[6].ends_with("-opensearch"));
    }

    #[test]
    fn detached_service_commands_use_restart_policies() {
        let mut server_config = Config::default();
        server_config.evebox_server.enabled = true;
        let (_server_root, server_context) = docker_context(server_config);
        let detached = command_args(&evebox::server::build_command(&server_context, true).unwrap());
        assert!(detached.contains(&RESTART_POLICY_ARG.to_string()));
        let foreground =
            command_args(&evebox::server::build_command(&server_context, false).unwrap());
        assert!(!foreground.contains(&RESTART_POLICY_ARG.to_string()));

        let mut agent_config = Config::default();
        agent_config.evebox_agent.enabled = true;
        agent_config.evebox_agent.server = "https://evebox.example".to_string();
        let (_agent_root, agent_context) = docker_context(agent_config);
        let agent = command_args(&evebox::agent::build_command(&agent_context, true).unwrap());
        assert!(agent.contains(&RESTART_POLICY_ARG.to_string()));

        let mut elastic_config = Config::default();
        elastic_config.evebox_server.enabled = true;
        elastic_config.elasticsearch.enabled = true;
        let (_elastic_root, elastic_context) = docker_context(elastic_config);
        let detached = command_args(&elastic::build_docker_command(&elastic_context, true));
        assert!(detached.contains(&RESTART_POLICY_ARG.to_string()));
        assert!(!detached.contains(&"--rm".to_string()));
        let foreground = command_args(&elastic::build_docker_command(&elastic_context, false));
        assert!(!foreground.contains(&RESTART_POLICY_ARG.to_string()));
        assert!(foreground.contains(&"--rm".to_string()));
    }

    #[test]
    fn enabled_containers_matches_configuration() {
        let mut config = Config::default();
        config.suricata.enabled = true;
        config.evebox_server.enabled = true;
        config.elasticsearch.enabled = true;
        let (_root, context) = docker_context(config);

        let containers = enabled_containers(&context);
        assert_eq!(containers.len(), 3);
        assert!(containers.iter().any(|(label, _)| *label == "Suricata"));
        assert!(
            containers
                .iter()
                .any(|(label, _)| *label == "EveBox-Server")
        );
        assert!(
            containers
                .iter()
                .any(|(label, _)| *label == "Elasticsearch")
        );
    }

    #[test]
    fn enabled_containers_includes_housekeeper_only_when_required() {
        let (_root, mut context) = docker_context(Config::default());
        for suricata in [false, true] {
            for extraction in [false, true] {
                for retention in [0, 7, 19] {
                    context.config.suricata.enabled = suricata;
                    context.config.suricata.file_extraction.enabled = extraction;
                    context.config.suricata.file_extraction.max_age_days = Some(retention);
                    let names = enabled_containers(&context);
                    assert_eq!(
                        names.iter().any(|(label, name)| *label == "Housekeeper"
                            && *name == housekeeper::container_name(&context)),
                        suricata && extraction && retention > 0
                    );
                }
            }
        }
    }
}
