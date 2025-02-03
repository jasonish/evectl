// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use anyhow::Result;

use crate::{context::Context, term};

#[derive(Clone)]
enum Options {
    ContainerImages,
    Return,
}

/// Main configure menu.
pub(crate) fn main(context: &mut Context) -> Result<()> {
    loop {
        term::clear();

        let mut selections = crate::prompt::Selections::with_index();
        selections.push(Options::ContainerImages, "Containers Images");
        selections.push(Options::Return, "Return");

        match inquire::Select::new("EveCtl: Configure", selections.to_vec()).prompt() {
            Ok(selection) => match selection.tag {
                Options::ContainerImages => crate::menu::containers::menu(context),
                Options::Return => return Ok(()),
            },
            Err(_) => break,
        }
    }

    Ok(())
}
