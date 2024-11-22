// SPDX-FileCopyrightText: (C) 2024 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

pub(crate) mod advanced;
pub(crate) mod configure;
pub(crate) mod evebox;
pub(crate) mod suricata;
pub(crate) mod suricata_update;

#[derive(Debug, Default, Clone)]
pub(crate) struct SelectItem {
    pub(crate) tag: String,
    pub(crate) value: String,
}

impl std::fmt::Display for SelectItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct Selections {
    items: Vec<SelectItem>,
    index: bool,
}

impl Selections {
    pub(crate) fn with_index() -> Self {
        Self {
            index: true,
            ..Default::default()
        }
    }

    pub(crate) fn push(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let value = if self.index {
            let i = self.items.len() + 1;
            format!("{:2}. {}", i, value.into())
        } else {
            value.into()
        };
        self.items.push(SelectItem {
            tag: key.into(),
            value,
        });
    }

    pub(crate) fn to_vec(&self) -> Vec<SelectItem> {
        self.clone().items
    }
}
