// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Shared rules menus and the `rules` command; the backend owns the
//! updater and service reloads.

use colored::Colorize;

use crate::prelude::*;
use crate::prompt::Selections;
use crate::rules::{Backend, OverrideFile, Ruleset};
use crate::{prompt, term};

/// The `rules` command: the rules menu's operations, shared by all
/// platforms. Values not given on the command line are prompted for.
#[derive(clap::Subcommand, Debug, Clone, Eq, PartialEq)]
pub(crate) enum Command {
    /// Update the Suricata rules
    Update,

    /// Refresh the ruleset index
    UpdateSources,

    /// Enable a ruleset from the index, choosing one if --name is omitted
    EnableRuleset {
        /// Ruleset to enable, for example: et/open
        #[arg(long)]
        name: Option<String>,
    },

    /// Disable a ruleset, choosing one if --name is omitted
    DisableRuleset {
        /// Ruleset to disable
        #[arg(long)]
        name: Option<String>,
    },

    /// Add and enable a ruleset from a URL, prompting for missing values
    AddRuleset {
        /// Name for the ruleset, for example: local/my-rules
        #[arg(long)]
        name: Option<String>,

        /// URL of a .rules file or tar.gz archive; %(__version__)s is
        /// replaced with the Suricata version
        #[arg(long)]
        url: Option<String>,
    },

    /// List the enabled rulesets
    ListEnabledRulesets,
}

/// Run a `rules` command. Changes made with every value given on the
/// command line don't prompt, so they can be scripted; run `rules update`
/// to apply them.
pub(crate) fn run_command(backend: &dyn Backend, command: Command) -> Result<()> {
    match command {
        Command::Update => backend.update_rules(),
        Command::UpdateSources => backend.update_sources(),
        Command::EnableRuleset { name: Some(name) } => backend.enable_ruleset(&name),
        Command::EnableRuleset { name: None } => select_ruleset(backend, true).map(|_| ()),
        Command::DisableRuleset { name: Some(name) } => backend.disable_ruleset(&name),
        Command::DisableRuleset { name: None } => select_ruleset(backend, false).map(|_| ()),
        Command::AddRuleset { name, url } => add_custom_ruleset(backend, name, url).map(|_| ()),
        Command::ListEnabledRulesets => list_enabled_rulesets(backend),
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Options {
    Enable,
    Disable,
    AddCustom,
    Update,
    UpdateSources,
    ListEnabled,
    Edit(OverrideFile),
    Return,
}

fn menu_options(backend: &dyn Backend) -> Selections<Options> {
    let mut selections = Selections::with_index();
    selections.push(Options::Enable, "Enable a Ruleset");
    selections.push(Options::Disable, "Disable a Ruleset");
    if backend.supports_custom_rulesets() {
        selections.push(Options::AddCustom, "Add a Custom Ruleset (URL)");
    }
    selections.push(Options::Update, "Update Rules");
    selections.push(Options::UpdateSources, "Update Rule Sources");
    selections.push(Options::ListEnabled, "List Enabled Rulesets");
    for file in OverrideFile::ALL {
        if backend.override_path(file).is_some() {
            selections.push(Options::Edit(file), format!("Edit {}", file.filename()));
        }
    }
    selections.push(Options::Return, "Return");
    selections
}

pub(crate) fn menu(backend: &dyn Backend) -> Result<()> {
    loop {
        term::title("EveCtl: Manage Rules");
        let selections = menu_options(backend);
        let action = match selections.prompt("Select menu option")? {
            None | Some(Options::Return) => break,
            Some(action) => action,
        };
        match run_action(backend, action) {
            Ok(true) => prompt::enter(),
            result => prompt::report("Rules operation failed", result.map(|_| ())),
        }
    }
    Ok(())
}

/// Return whether the caller should pause to let the user read output.
fn run_action(backend: &dyn Backend, action: Options) -> Result<bool> {
    match action {
        Options::Enable => select_ruleset(backend, true),
        Options::Disable => select_ruleset(backend, false),
        Options::AddCustom => add_custom_ruleset(backend, None, None),
        Options::Update => backend.update_rules().map(|()| true),
        Options::UpdateSources => backend.update_sources().map(|()| true),
        Options::ListEnabled => list_enabled_rulesets(backend).map(|()| true),
        Options::Edit(file) => edit_override(backend, file).map(|()| false),
        Options::Return => Ok(false),
    }
}

fn ruleset_choices(backend: &dyn Backend, enable: bool) -> Result<Vec<Ruleset>> {
    let enabled = backend.enabled_rulesets()?;
    let mut choices = if enable {
        backend
            .available_rulesets()?
            .into_iter()
            .filter(|source| {
                source.can_enable && !enabled.iter().any(|other| other.id == source.id)
            })
            .collect()
    } else {
        enabled
    };
    choices.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(choices)
}

fn ruleset_label(ruleset: &Ruleset) -> String {
    match &ruleset.summary {
        Some(summary) => format!("{}: {}", ruleset.id, summary.green().italic()),
        None => ruleset.id.clone(),
    }
}

fn select_ruleset(backend: &dyn Backend, enable: bool) -> Result<bool> {
    let choices = ruleset_choices(backend, enable)?;
    if choices.is_empty() {
        println!(
            "{}",
            if enable {
                "No additional rulesets available to enable"
            } else {
                "No rulesets enabled"
            }
        );
        return Ok(true);
    }
    let mut selections = Selections::new();
    for source in choices {
        let label = ruleset_label(&source);
        selections.push(source.id, label);
    }
    let question = if enable {
        "Choose a ruleset to enable or ESC to exit"
    } else {
        "Choose a ruleset to DISABLE or ESC to exit"
    };
    let Some(id) = selections.prompt(question)? else {
        return Ok(false);
    };
    change_ruleset(backend, &id, enable, || {
        prompt::confirm_with_help(
            "Would you like to update your rules now?",
            if enable {
                "A rule update is required to make the new ruleset active"
            } else {
                "A rule update is required to complete disabling this ruleset"
            },
        )
    })?;
    Ok(true)
}

fn change_ruleset(
    backend: &dyn Backend,
    id: &str,
    enable: bool,
    confirm_update: impl FnOnce() -> bool,
) -> Result<()> {
    if enable {
        backend.enable_ruleset(id)?;
    } else {
        backend.disable_ruleset(id)?;
    }
    if confirm_update() {
        backend.update_rules()?;
    }
    Ok(())
}

/// Reject names suricata-update already knows: an enabled source, or an
/// index source whose configuration the custom URL would take over.
fn check_new_ruleset_name(
    name: &str,
    indexed: &[String],
    enabled: &[String],
) -> std::result::Result<(), String> {
    crate::rules::check_custom_ruleset_name(name)?;
    if enabled.iter().any(|id| id == name) {
        return Err(format!("A ruleset named {name} is already enabled"));
    }
    if indexed.iter().any(|id| id == name) {
        return Err(format!(
            "{name} is in the ruleset index; use Enable a Ruleset instead"
        ));
    }
    Ok(())
}

/// Add a custom ruleset, prompting for the name and URL when not given.
/// A rule update is only offered when something was prompted for.
fn add_custom_ruleset(
    backend: &dyn Backend,
    name: Option<String>,
    url: Option<String>,
) -> Result<bool> {
    let interactive = name.is_none() || url.is_none();
    // Reject bad values given on the command line before any backend work.
    if let Some(name) = &name {
        crate::rules::check_custom_ruleset_name(name.trim()).map_err(|err| anyhow!(err))?;
    }
    if let Some(url) = &url {
        crate::rules::check_custom_ruleset_url(url.trim()).map_err(|err| anyhow!(err))?;
    }
    let ids = |rulesets: Vec<Ruleset>| rulesets.into_iter().map(|r| r.id).collect::<Vec<_>>();
    // The index is only used to catch name clashes; it may not be
    // downloaded yet.
    let indexed = backend.available_rulesets().map(ids).unwrap_or_default();
    let enabled = ids(backend.enabled_rulesets()?);
    let name = match name {
        Some(name) => {
            let name = name.trim().to_string();
            check_new_ruleset_name(&name, &indexed, &enabled).map_err(|err| anyhow!(err))?;
            name
        }
        None => match prompt::skippable(
            inquire::Text::new("Ruleset name:")
                .with_help_message("A short name for the ruleset, for example: local/my-rules")
                .with_validator(prompt::validator(move |name| {
                    check_new_ruleset_name(name.trim(), &indexed, &enabled)
                }))
                .prompt(),
        )? {
            Some(name) => name.trim().to_string(),
            None => return Ok(false),
        },
    };
    let url = match url {
        Some(url) => url.trim().to_string(),
        None => match prompt::skippable(
            inquire::Text::new("Ruleset URL:")
                .with_help_message(
                    "A .rules file or tar.gz archive; %(__version__)s is replaced \
                     with the Suricata version",
                )
                .with_validator(prompt::validator(|url| {
                    crate::rules::check_custom_ruleset_url(url.trim())
                }))
                .prompt(),
        )? {
            Some(url) => url.trim().to_string(),
            None => return Ok(false),
        },
    };
    add_custom(backend, &name, &url, || {
        interactive
            && prompt::confirm_with_help(
                "Would you like to update your rules now?",
                "A rule update is required to make the new ruleset active",
            )
    })?;
    Ok(true)
}

fn add_custom(
    backend: &dyn Backend,
    name: &str,
    url: &str,
    confirm_update: impl FnOnce() -> bool,
) -> Result<()> {
    backend.add_custom_ruleset(name, url)?;
    println!("Added ruleset {name}");
    if confirm_update() {
        backend.update_rules()?;
    }
    Ok(())
}

fn list_enabled_rulesets(backend: &dyn Backend) -> Result<()> {
    let rulesets = ruleset_choices(backend, false)?;
    if rulesets.is_empty() {
        println!("No Suricata rulesets enabled");
    } else {
        println!("Enabled Suricata rulesets:");
        for ruleset in rulesets {
            println!("- {}", ruleset.id);
        }
    }
    Ok(())
}

fn edit_override(backend: &dyn Backend, file: OverrideFile) -> Result<()> {
    let path = backend
        .override_path(file)
        .ok_or_else(|| anyhow!("Rule override files are not supported by this backend"))?;
    if !path.exists()
        && prompt::confirm(&format!(
            "Would you like to start with a {} template",
            file.filename()
        ))
    {
        backend.write_override_template(file)?;
    }
    let mut editors = Vec::new();
    if let Ok(editor) = std::env::var("EDITOR") {
        editors.push(editor);
    }
    editors.extend(["nano", "vim", "vi"].map(String::from));
    for editor in editors {
        match std::process::Command::new(&editor).arg(&path).status() {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => warn!("Editor {editor} exited with {status}"),
            Err(err) => debug!("Could not launch editor {editor}: {err}"),
        }
    }
    bail!(
        "Could not edit {}; set the EDITOR environment variable",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::menu::test_support::FakePlatform;

    fn source(id: &str, can_enable: bool) -> Ruleset {
        Ruleset {
            id: id.into(),
            summary: None,
            can_enable,
        }
    }

    #[test]
    fn menu_shares_operations_and_gates_override_files() {
        for overrides in [false, true] {
            let backend = FakePlatform {
                overrides,
                ..Default::default()
            };
            let options = menu_options(&backend).tags();
            let mut expected = vec![
                Options::Enable,
                Options::Disable,
                Options::Update,
                Options::UpdateSources,
                Options::ListEnabled,
            ];
            if overrides {
                expected.extend(OverrideFile::ALL.map(Options::Edit));
            }
            expected.push(Options::Return);
            assert_eq!(options, expected);
            assert!(backend.calls().is_empty());
        }
    }

    #[derive(clap::Parser, Debug)]
    struct Cli {
        #[command(subcommand)]
        command: Command,
    }

    fn parse(args: &[&str]) -> std::result::Result<Command, clap::Error> {
        use clap::Parser;
        Cli::try_parse_from(std::iter::once("rules").chain(args.iter().copied()))
            .map(|cli| cli.command)
    }

    #[test]
    fn rules_command_parses_options() {
        assert_eq!(parse(&["update"]).unwrap(), Command::Update);
        assert_eq!(parse(&["update-sources"]).unwrap(), Command::UpdateSources);
        assert_eq!(
            parse(&["list-enabled-rulesets"]).unwrap(),
            Command::ListEnabledRulesets
        );
        assert_eq!(
            parse(&["enable-ruleset", "--name", "et/open"]).unwrap(),
            Command::EnableRuleset {
                name: Some("et/open".into())
            }
        );
        assert_eq!(
            parse(&["disable-ruleset"]).unwrap(),
            Command::DisableRuleset { name: None }
        );
        assert_eq!(
            parse(&["add-ruleset", "--name", "local/r", "--url", "https://x/r"]).unwrap(),
            Command::AddRuleset {
                name: Some("local/r".into()),
                url: Some("https://x/r".into())
            }
        );
        assert_eq!(
            parse(&["add-ruleset", "--url", "https://x/r"]).unwrap(),
            Command::AddRuleset {
                name: None,
                url: Some("https://x/r".into())
            }
        );
        // Names are options, not positionals.
        assert!(parse(&["enable-ruleset", "et/open"]).is_err());
        assert!(parse(&["reload"]).is_err());
    }

    #[test]
    fn rules_commands_with_all_values_do_not_prompt() {
        for (command, expected) in [
            (Command::Update, "update:"),
            (Command::UpdateSources, "sources:"),
            (
                Command::EnableRuleset {
                    name: Some("et/open".into()),
                },
                "enable:et/open",
            ),
            (
                Command::DisableRuleset {
                    name: Some("et/open".into()),
                },
                "disable:et/open",
            ),
            (Command::ListEnabledRulesets, "enabled:"),
        ] {
            let backend = FakePlatform::default();
            run_command(&backend, command).unwrap();
            assert_eq!(backend.calls(), [expected]);
        }

        // Adding checks for clashes, then adds without offering an update.
        let backend = FakePlatform::default();
        let command = Command::AddRuleset {
            name: Some(" local/r ".into()),
            url: Some("https://x/r.rules".into()),
        };
        run_command(&backend, command).unwrap();
        assert_eq!(
            backend.calls(),
            ["available:", "enabled:", "add:local/r=https://x/r.rules"]
        );
    }

    #[test]
    fn add_ruleset_rejects_bad_values_without_adding() {
        // Syntax errors are caught without calling the backend.
        for (name, url) in [("-x", "https://x/r.rules"), ("local/r", "ftp://x/r.rules")] {
            let backend = FakePlatform::default();
            let command = Command::AddRuleset {
                name: Some(name.into()),
                url: Some(url.into()),
            };
            assert!(run_command(&backend, command).is_err(), "{name} {url}");
            assert!(backend.calls().is_empty());
        }
        for (name, url) in [
            ("-x", "https://x/r.rules"),
            ("et/open", "https://x/r.rules"),
            ("local/mine", "https://x/r.rules"),
            ("local/r", "ftp://x/r.rules"),
        ] {
            let backend = FakePlatform {
                available: vec![source("et/open", true)],
                enabled: vec![source("local/mine", false)],
                ..Default::default()
            };
            let command = Command::AddRuleset {
                name: Some(name.into()),
                url: Some(url.into()),
            };
            assert!(run_command(&backend, command).is_err(), "{name} {url}");
            assert!(!backend.calls().iter().any(|call| call.starts_with("add:")));
        }
    }

    #[test]
    fn custom_ruleset_option_is_gated_by_backend_support() {
        for custom_rulesets in [false, true] {
            let backend = FakePlatform {
                custom_rulesets,
                ..Default::default()
            };
            let options = menu_options(&backend).tags();
            assert_eq!(options.contains(&Options::AddCustom), custom_rulesets);
            if custom_rulesets {
                assert_eq!(options[2], Options::AddCustom);
            }
        }
    }

    #[test]
    fn new_ruleset_names_must_not_clash() {
        let indexed = vec!["et/open".to_string()];
        let enabled = vec!["local/mine".to_string()];
        assert!(check_new_ruleset_name("local/new", &indexed, &enabled).is_ok());
        assert!(check_new_ruleset_name("et/open", &indexed, &enabled).is_err());
        assert!(check_new_ruleset_name("local/mine", &indexed, &enabled).is_err());
        assert!(check_new_ruleset_name("-x", &indexed, &enabled).is_err());
    }

    #[test]
    fn adding_a_custom_ruleset_offers_an_update() {
        for update in [true, false] {
            let backend = FakePlatform::default();
            add_custom(&backend, "local/r", "https://x/r.rules", || update).unwrap();
            let mut expected = vec!["add:local/r=https://x/r.rules".to_string()];
            if update {
                expected.push("update:".into());
            }
            assert_eq!(backend.calls(), expected);
        }
        let backend = FakePlatform {
            fail: Some("add"),
            ..Default::default()
        };
        assert!(add_custom(&backend, "local/r", "https://x/r.rules", || panic!()).is_err());
        assert_eq!(backend.calls(), ["add:local/r=https://x/r.rules"]);
    }

    #[test]
    fn enable_choices_are_sorted_and_exclude_enabled_and_unsupported_sources() {
        let backend = FakePlatform {
            available: vec![
                source("z", true),
                source("obsolete", false),
                source("parameters", false),
                source("enabled", true),
                source("a", true),
            ],
            enabled: vec![source("enabled", false)],
            ..Default::default()
        };
        assert_eq!(
            ruleset_choices(&backend, true).unwrap(),
            vec![source("a", true), source("z", true)]
        );
    }

    #[test]
    fn disable_includes_unknown_sources_without_fetching_available_index() {
        let backend = FakePlatform {
            enabled: vec![source("z-unknown", false), source("a", false)],
            fail: Some("available"),
            ..Default::default()
        };
        let choices = ruleset_choices(&backend, false).unwrap();
        assert_eq!(
            choices,
            vec![source("a", false), source("z-unknown", false)]
        );
        assert_eq!(ruleset_label(&choices[1]), "z-unknown");
        assert_eq!(backend.calls(), ["enabled:"]);
    }

    #[test]
    fn empty_lists_and_backend_errors_are_handled_without_panicking() {
        let mut backend = FakePlatform::default();
        assert!(ruleset_choices(&backend, true).unwrap().is_empty());
        assert!(ruleset_choices(&backend, false).unwrap().is_empty());
        for failure in ["available", "enabled"] {
            backend.fail = Some(failure);
            assert!(ruleset_choices(&backend, true).is_err());
        }
    }

    #[test]
    fn successful_changes_offer_optional_update_in_order() {
        for enable in [true, false] {
            for update in [true, false] {
                let backend = FakePlatform::default();
                change_ruleset(&backend, "test/source", enable, || update).unwrap();
                let operation = if enable { "enable" } else { "disable" };
                let mut expected = vec![format!("{operation}:test/source")];
                if update {
                    expected.push("update:".into());
                }
                assert_eq!(backend.calls(), expected);
            }
        }
    }

    #[test]
    fn failed_changes_do_not_offer_or_run_updates() {
        for enable in [true, false] {
            let operation = if enable { "enable" } else { "disable" };
            let backend = FakePlatform {
                fail: Some(operation),
                ..Default::default()
            };
            assert!(change_ruleset(&backend, "test/source", enable, || panic!()).is_err());
            assert_eq!(backend.calls(), [format!("{operation}:test/source")]);
        }
    }

    #[test]
    fn update_errors_propagate_after_a_successful_change() {
        let backend = FakePlatform {
            fail: Some("update"),
            ..Default::default()
        };
        assert!(change_ruleset(&backend, "test/source", true, || true).is_err());
        assert_eq!(backend.calls(), ["enable:test/source", "update:"]);
    }

    #[test]
    fn actions_dispatch_to_backend_and_propagate_errors() {
        for (action, operation) in [
            (Options::Update, "update"),
            (Options::UpdateSources, "sources"),
            (Options::ListEnabled, "enabled"),
        ] {
            let mut backend = FakePlatform::default();
            assert!(run_action(&backend, action).unwrap());
            assert_eq!(backend.calls(), [format!("{operation}:")]);
            backend.fail = Some(operation);
            assert!(run_action(&backend, action).is_err());
        }
    }

    #[test]
    fn unsupported_override_actions_are_rejected_without_prompting() {
        let backend = FakePlatform::default();
        for file in OverrideFile::ALL {
            assert!(run_action(&backend, Options::Edit(file)).is_err());
            assert!(backend.write_override_template(file).is_err());
        }
    }
}
