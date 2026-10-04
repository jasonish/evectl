// SPDX-FileCopyrightText: (C) 2023 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;
use crate::prompt::Selections;
use crate::{container::Container, context::Context};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Options {
    Suricata,
    EveBox,
    Return,
}

/// Hidden CLI entry point; the configuration is saved on exit as no
/// caller persists it.
pub(crate) fn menu(context: &mut Context) {
    let original = context.config.clone();
    edit(context);
    if context.config != original
        && let Err(err) = context.config.save()
    {
        error!("Failed to save configuration: {err:#}");
        crate::prompt::enter();
    }
}

/// Edit the container images; the caller persists the configuration.
pub(crate) fn edit(context: &mut Context) {
    loop {
        crate::term::clear();

        let suricata_image = context.image_name(Container::Suricata);
        let evebox_image = context.image_name(Container::EveBox);

        let mut selections = Selections::new();
        selections.push(
            Options::Suricata,
            format!("Suricata Image: {suricata_image}"),
        );
        selections.push(Options::EveBox, format!("EveBox Image: {evebox_image}"));
        selections.push(Options::Return, "Return");

        match selections.prompt("Select container to configure") {
            Ok(Some(Options::Suricata)) => set_image(
                &mut context.config.suricata.image,
                "Enter Suricata image name",
                &suricata_image,
            ),
            Ok(Some(Options::EveBox)) => set_image(
                &mut context.config.evebox_server.image,
                "Enter EveBox image name",
                &evebox_image,
            ),
            Ok(Some(Options::Return)) | Ok(None) | Err(_) => return,
        }
    }
}

/// Enter keeps the current image; ESC resets to the built-in default.
fn set_image(image: &mut Option<String>, prompt: &str, current: &str) {
    *image = inquire::Text::new(prompt)
        .with_default(current)
        .with_help_message("Enter to keep current, ESC to reset to default")
        .prompt()
        .ok();
}
