// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use crate::{context::Context, term};

#[derive(Clone)]
enum Options {
    Memory,
    Return,
}

pub(crate) fn menu(context: &mut Context) -> Result<()> {
    loop {
        term::clear();

        let mut selections = crate::prompt::Selections::with_index();

        selections.push(
            Options::Memory,
            format!("Memory Limit [{}GB]", crate::elastic::memory_gb(context)),
        );
        selections.push(Options::Return, "Return");

        match inquire::Select::new("EveCtl: Configure Elasticsearch", selections.to_vec()).prompt()
        {
            Ok(selection) => match selection.tag {
                Options::Memory => set_memory(context)?,
                Options::Return => break,
            },
            Err(_) => break,
        }
    }

    Ok(())
}

fn set_memory(context: &mut Context) -> Result<()> {
    let memory = inquire::CustomType::<u32>::new("Memory limit in gigabytes:")
        .with_default(crate::elastic::memory_gb(context))
        .with_help_message("Elasticsearch will use half of this for its heap. ESC to cancel.")
        .prompt_skippable()?;
    match memory {
        None => {}
        Some(0) => {
            error!("Memory limit must be at least 1GB");
            crate::prompt::enter();
        }
        Some(memory) => {
            context.config.elasticsearch.memory = if memory == crate::elastic::DEFAULT_MEMORY_GB {
                None
            } else {
                Some(memory)
            };
        }
    }
    Ok(())
}
