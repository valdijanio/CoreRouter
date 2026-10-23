//! English explanations, sorted by key. Labels need no English catalog:
//! the English text is their key.

pub(super) const HELP: &[(&str, &str)] = &[
    (
        "settings.help_lang",
        "## What it does\n\
         The language of the explanations: the windows of the round “i” button and the help \
         text of each parameter.\n\n\
         An explanation that is not written in this language yet shows in the \
         language of the labels, and then in English.",
    ),
    (
        "settings.labels_lang",
        "## What it does\n\
         The language of the labels: menus, window titles, columns and buttons.\n\n\
         Most labels are only in English for now (the RouterOS names, which the \
         manuals and the terminal use too); a label with no translation shows \
         in English.\n\n\
         ## Where it is kept\n\
         On this computer (or in this browser), not on the router: each \
         operator picks their own.",
    ),
];
