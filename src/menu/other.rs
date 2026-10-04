// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prompt::Selections;
use crate::{context::Context, term};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Options {
    SuricataShell,
    EveBoxShell,
    Return,
}

pub(crate) fn menu(context: &Context) {
    loop {
        term::title("EveCtl: Other Menu Items");

        let mut selections = Selections::with_index();
        selections.push(Options::SuricataShell, "Suricata Shell");
        selections.push(Options::EveBoxShell, "EveBox Shell");
        selections.push(Options::Return, "Return");

        match selections.prompt("Select menu option") {
            Ok(Some(Options::SuricataShell)) => shell(
                context,
                &crate::suricata::container_name(context),
                "suricata",
                "bash",
            ),
            Ok(Some(Options::EveBoxShell)) => shell(
                context,
                &crate::evebox::server::container_name(context),
                "evebox",
                "/bin/sh",
            ),
            Ok(Some(Options::Return)) | Ok(None) | Err(_) => return,
        }
    }
}

/// Open an interactive shell in a running container.
fn shell(context: &Context, container: &str, host: &str, shell: &str) {
    let _ = context
        .manager
        .command()
        .args([
            "exec",
            "-it",
            "-e",
            &format!("PS1=[\\u@{host} \\W]\\$ "),
            container,
            shell,
        ])
        .status();
}
