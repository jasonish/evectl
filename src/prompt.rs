// SPDX-FileCopyrightText: (C) 2023 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

pub fn enter() {
    let _ = inquire::Text::new("Press ENTER to continue:").prompt();
}

pub fn enter_with_prefix(prefix: &str) {
    let _ = inquire::Text::new(&format!("{}. Press ENTER to continue:", prefix)).prompt();
}

/// Confirm a destructive action, defaulting to no. Failure to prompt
/// (e.g. no terminal) is treated as a no.
pub fn confirm_destructive(prompt: &str) -> bool {
    matches!(
        inquire::Confirm::new(prompt).with_default(false).prompt(),
        Ok(true)
    )
}

pub fn confirm(prompt: &str, help: Option<&str>) -> bool {
    let prompt = inquire::Confirm::new(prompt).with_default(true);
    let prompt = if let Some(help) = help {
        prompt.with_help_message(help)
    } else {
        prompt
    };
    matches!(prompt.prompt(), Ok(true))
}

#[derive(Debug, Default, Clone)]
pub struct SelectItem<T>
where
    T: Clone,
{
    pub tag: T,
    pub value: String,
}

impl<T> std::fmt::Display for SelectItem<T>
where
    T: Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
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
        let value = if self.index {
            let i = self.items.len() + 1;
            format!("{:2}. {}", i, value.into())
        } else {
            value.into()
        };
        self.items.push(SelectItem { tag: key, value });
        self
    }

    pub fn to_vec(&self) -> Vec<SelectItem<T>> {
        self.items.clone()
    }
}
