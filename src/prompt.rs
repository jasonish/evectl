// SPDX-FileCopyrightText: (C) 2023 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Prompt helpers shared by the menus. Backing out of a prompt (ESC or
//! Ctrl-C) is never an error here; it is reported as `None` or `false`,
//! except for the `ask*` questions used inside multi-step flows.

use inquire::InquireError;

use crate::prelude::*;

pub fn enter() {
    let _ = inquire::Text::new("Press ENTER to continue:").prompt();
}

pub fn enter_with_prefix(prefix: &str) {
    let _ = inquire::Text::new(&format!("{}. Press ENTER to continue:", prefix)).prompt();
}

/// True when a prompt error is the user backing out (ESC or Ctrl-C)
/// rather than a real failure.
pub(crate) fn cancelled(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<InquireError>(),
        Some(InquireError::OperationCanceled | InquireError::OperationInterrupted)
    )
}

/// Map a prompt result to its answer, with ESC or Ctrl-C as `None`.
pub(crate) fn skippable<T>(result: inquire::error::InquireResult<T>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// Report a failed menu action and wait so the error is seen before the
/// screen is cleared. Backing out of a prompt is not reported.
pub(crate) fn report(what: &str, result: Result<()>) {
    if let Err(err) = result
        && !cancelled(&err)
    {
        error!("{what}: {err:#}");
        enter();
    }
}

/// Like `report`, but also waits after success so output can be read.
pub(crate) fn report_and_pause(what: &str, result: Result<()>) {
    if let Err(err) = &result
        && cancelled(err)
    {
        return;
    }
    if let Err(err) = result {
        error!("{what}: {err:#}");
    }
    enter();
}

/// Confirm a destructive action, defaulting to no. Failure to prompt
/// (e.g. no terminal) is treated as a no.
pub fn confirm_destructive(prompt: &str) -> bool {
    matches!(
        inquire::Confirm::new(prompt).with_default(false).prompt(),
        Ok(true)
    )
}

/// A yes/no question defaulting to yes; backing out is a no.
pub(crate) fn confirm(prompt: &str) -> bool {
    matches!(
        inquire::Confirm::new(prompt).with_default(true).prompt(),
        Ok(true)
    )
}

pub(crate) fn confirm_with_help(prompt: &str, help: &str) -> bool {
    matches!(
        inquire::Confirm::new(prompt)
            .with_default(true)
            .with_help_message(help)
            .prompt(),
        Ok(true)
    )
}

/// A yes/no question in a multi-step flow, where backing out is
/// returned as an error so the flow can abort.
pub(crate) fn ask(prompt: &str, default: bool) -> Result<bool> {
    Ok(inquire::Confirm::new(prompt)
        .with_default(default)
        .prompt()?)
}

pub(crate) fn ask_with_help(prompt: &str, default: bool, help: &str) -> Result<bool> {
    Ok(inquire::Confirm::new(prompt)
        .with_default(default)
        .with_help_message(help)
        .prompt()?)
}

/// Edit an optional text setting. Blank input clears the current value
/// after confirmation. Returns `None` if the value is unchanged.
pub(crate) fn edit_optional(
    prompt: &str,
    current: Option<&str>,
    clear_prompt: &str,
) -> Option<Option<String>> {
    edit_optional_with(current, clear_prompt, || {
        inquire::Text::new(prompt).prompt().ok()
    })
}

/// Like `edit_optional`, with the text collected by `input` (for a
/// prompt with a default, help, or masking).
pub(crate) fn edit_optional_with(
    current: Option<&str>,
    clear_prompt: &str,
    input: impl FnOnce() -> Option<String>,
) -> Option<Option<String>> {
    let input = input()?;
    let input = input.trim();
    if !input.is_empty() {
        Some(Some(input.to_string()))
    } else if current.is_some() && confirm(clear_prompt) {
        Some(None)
    } else {
        None
    }
}

/// Adapt a plain check into an inquire validator, with the error text
/// shown as the validation message.
pub(crate) fn validator(
    check: impl Fn(&str) -> std::result::Result<(), String> + Clone + 'static,
) -> impl Fn(&str) -> std::result::Result<inquire::validator::Validation, inquire::CustomUserError>
+ Clone
+ 'static {
    move |input: &str| {
        Ok(match check(input) {
            Ok(()) => inquire::validator::Validation::Valid,
            Err(message) => inquire::validator::Validation::Invalid(message.into()),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct SelectItem<T>
where
    T: Clone,
{
    pub tag: T,
    pub value: String,
    /// Shown before the value when the selections are numbered.
    index: Option<usize>,
}

impl<T> std::fmt::Display for SelectItem<T>
where
    T: Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.index {
            Some(index) => write!(f, "{index:2}. {}", self.value),
            None => write!(f, "{}", self.value),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Selections<T>
where
    T: Clone,
{
    items: Vec<SelectItem<T>>,
    index: bool,
}

impl<T> Selections<T>
where
    T: Clone,
{
    pub fn new() -> Self {
        Self {
            items: vec![],
            index: false,
        }
    }

    pub fn with_index() -> Self {
        Self {
            items: vec![],
            index: true,
        }
    }

    pub fn push(&mut self, key: T, value: impl Into<String>) -> &mut Self {
        let index = self.index.then_some(self.items.len() + 1);
        self.items.push(SelectItem {
            tag: key,
            value: value.into(),
            index,
        });
        self
    }

    pub fn to_vec(&self) -> Vec<SelectItem<T>> {
        self.items.clone()
    }

    #[cfg(test)]
    pub(crate) fn tags(&self) -> Vec<T> {
        self.items.iter().map(|item| item.tag.clone()).collect()
    }

    #[cfg(test)]
    pub(crate) fn labels(&self) -> Vec<String> {
        self.items.iter().map(|item| item.value.clone()).collect()
    }

    /// A page size showing every item, limited to what fits in the
    /// terminal (leaving room for the prompt and help lines).
    pub fn page_size(&self) -> usize {
        let len = self.items.len().max(1);
        match crossterm::terminal::size() {
            Ok((_, rows)) => len.min(usize::from(rows).saturating_sub(3).max(1)),
            Err(_) => len,
        }
    }

    /// A select prompt over these items, sized to show them all.
    pub(crate) fn select<'a>(&self, title: &'a str) -> inquire::Select<'a, SelectItem<T>> {
        inquire::Select::new(title, self.to_vec()).with_page_size(self.page_size())
    }

    /// Prompt for one of the items, with ESC or Ctrl-C as `None`.
    pub(crate) fn prompt(&self, title: &str) -> Result<Option<T>> {
        self.prompt_with(title, |select| select)
    }

    /// Like `prompt`, with the select prompt adjusted first (e.g. a
    /// starting cursor or help message).
    pub(crate) fn prompt_with<'a>(
        &self,
        title: &'a str,
        configure: impl FnOnce(inquire::Select<'a, SelectItem<T>>) -> inquire::Select<'a, SelectItem<T>>,
    ) -> Result<Option<T>>
    where
        T: 'a,
    {
        Ok(skippable(configure(self.select(title)).prompt())?.map(|item| item.tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbering_is_rendered_but_not_stored() {
        let mut selections = Selections::with_index();
        selections.push(1, "One");
        selections.push(2, "Two");
        assert_eq!(selections.tags(), [1, 2]);
        assert_eq!(selections.labels(), ["One", "Two"]);
        let items = selections.to_vec();
        assert_eq!(items[0].to_string(), " 1. One");
        assert_eq!(items[1].to_string(), " 2. Two");

        let mut plain = Selections::new();
        plain.push((), "Plain");
        assert_eq!(plain.to_vec()[0].to_string(), "Plain");
    }

    #[test]
    fn cancellations_are_recognized_and_skipped() {
        for error in [
            InquireError::OperationCanceled,
            InquireError::OperationInterrupted,
        ] {
            assert!(cancelled(&anyhow::Error::from(error)));
        }
        assert!(!cancelled(&anyhow!("Discovery failed")));
        assert_eq!(skippable(Ok(1)).unwrap(), Some(1));
        assert_eq!(
            skippable::<u8>(Err(InquireError::OperationCanceled)).unwrap(),
            None
        );
        assert!(skippable::<u8>(Err(InquireError::NotTTY)).is_err());
    }

    #[test]
    fn validator_adapts_check_results() {
        let check = validator(|input: &str| {
            if input.is_empty() {
                Err("Required".to_string())
            } else {
                Ok(())
            }
        });
        assert!(matches!(
            check("x").unwrap(),
            inquire::validator::Validation::Valid
        ));
        assert!(matches!(
            check("").unwrap(),
            inquire::validator::Validation::Invalid(_)
        ));
    }
}
