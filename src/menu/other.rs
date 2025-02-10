// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::{actions, context::Context, prompt, term};

pub(crate) fn menu(context: &Context) {
    loop {
        term::title("EveCtl: Other Menu Items");

        let selections = crate::prompt::Selections::with_index()
            .push("rotate", "Force Log Rotation")
            .push("suricata-shell", "Suricata Shell")
            .push("evebox-shell", "EveBox Shell")
            .push("return", "Return")
            .to_vec();

        match inquire::Select::new("Select menu option", selections).prompt() {
            Err(_) => return,
            Ok(selection) => match selection.tag {
                "return" => return,
                "rotate" => {
                    actions::force_suricata_logrotate(context);
                    prompt::enter();
                }
                "suricata-shell" => {
                    let _ = context
                        .manager
                        .command()
                        .args([
                            "exec",
                            "-it",
                            "-e",
                            "PS1=[\\u@suricata \\W]\\$ ",
                            &crate::suricata::container_name(context),
                            "bash",
                        ])
                        .status();
                }
                "evebox-shell" => {
                    let _ = context
                        .manager
                        .command()
                        .args([
                            "exec",
                            "-it",
                            "-e",
                            "PS1=[\\u@evebox \\W]\\$ ",
                            &crate::evebox::server::container_name(context),
                            "/bin/sh",
                        ])
                        .status();
                }
                _ => {}
            },
        }
    }
}
