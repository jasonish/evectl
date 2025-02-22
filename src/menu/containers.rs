// SPDX-FileCopyrightText: (C) 2023 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::{container::Container, context::Context};

pub(crate) fn menu(context: &mut Context) {
    loop {
        crate::term::clear();

        let suricata_image_name = context.image_name(Container::Suricata);
        let evebox_image_name = context.image_name(Container::EveBox);

        let selections = crate::prompt::Selections::new()
            .push(
                "suricata",
                format!("Suricata Image: {}", suricata_image_name),
            )
            .push("evebox", format!("EveBox Image: {}", evebox_image_name))
            .push("return", "Return")
            .to_vec();

        match inquire::Select::new("Select container to configure", selections).prompt() {
            Ok(selection) => match selection.tag {
                "suricata" => {
                    set_suricata_image(context, &suricata_image_name);
                }
                "evebox" => {
                    set_evebox_image(context, &evebox_image_name);
                }
                "return" => return,
                _ => unimplemented!(),
            },
            Err(_) => return,
        }
    }
}

fn set_suricata_image(context: &mut Context, default: &str) {
    match inquire::Text::new("Enter Suricata image name")
        .with_default(default)
        .with_help_message("Enter to keep current, ESC to reset to default")
        .prompt()
    {
        Ok(image) => {
            context.config.suricata.image = Some(image);
        }
        Err(_) => {
            context.config.suricata.image = None;
        }
    }
    context.config.save().unwrap();
}

fn set_evebox_image(context: &mut Context, default: &str) {
    match inquire::Text::new("Enter EveBox image name")
        .with_default(default)
        .with_help_message("Enter to keep current, ESC to reset to default")
        .prompt()
    {
        Ok(image) => {
            context.config.evebox_server.image = Some(image);
        }
        Err(_) => {
            context.config.evebox_server.image = None;
        }
    }
    context.config.save().unwrap();
}
