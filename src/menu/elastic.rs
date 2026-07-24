// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use crate::{config::SearchEngine, context::Context, term};

#[derive(Clone)]
enum Options {
    Engine,
    Memory,
    Return,
}

pub(crate) fn menu(context: &mut Context) -> Result<()> {
    loop {
        term::clear();

        let engine = context.config.elasticsearch.engine;
        let mut selections = crate::prompt::Selections::with_index();

        selections.push(
            Options::Engine,
            format!("Search Engine [{}]", engine.name()),
        );
        selections.push(
            Options::Memory,
            format!("Memory Limit [{}GB]", crate::elastic::memory_gb(context)),
        );
        selections.push(Options::Return, "Return");

        match inquire::Select::new(
            &format!("EveCtl: Configure {}", engine.name()),
            selections.to_vec(),
        )
        .prompt()
        {
            Ok(selection) => match selection.tag {
                Options::Engine => set_engine(context)?,
                Options::Memory => set_memory(context)?,
                Options::Return => break,
            },
            Err(_) => break,
        }
    }

    Ok(())
}

/// Prompt for a search engine, returning None if the prompt was
/// cancelled.
pub(crate) fn select_engine() -> Result<Option<SearchEngine>> {
    let mut selections = crate::prompt::Selections::new();
    selections.push(SearchEngine::OpenSearch, "OpenSearch (recommended)");
    selections.push(SearchEngine::Elasticsearch, "Elasticsearch");
    let selection =
        inquire::Select::new("Which search engine?", selections.to_vec()).prompt_skippable()?;
    Ok(selection.map(|selection| selection.tag))
}

fn set_engine(context: &mut Context) -> Result<()> {
    if let Some(engine) = select_engine()?
        && engine != context.config.elasticsearch.engine
    {
        context.config.elasticsearch.engine = engine;
        warn!("Existing events will not be migrated between search engines.");
        crate::prompt::enter();
    }
    Ok(())
}

fn set_memory(context: &mut Context) -> Result<()> {
    let memory = inquire::CustomType::<u32>::new("Memory limit in gigabytes:")
        .with_default(crate::elastic::memory_gb(context))
        .with_help_message("The search engine will use half of this for its heap. ESC to cancel.")
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
