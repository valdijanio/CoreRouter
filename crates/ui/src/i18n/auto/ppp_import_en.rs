//! English explanations of PPP › Secrets › Import from MikroTik (G4.3n),
//! scope `ppp_import`, sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    ("ppp_import.file", "## File\n\nThe RouterOS export's path on this computer (`~/` is your home). Make it on the MikroTik with `/ppp secret export show-sensitive file=secrets` (or `/export show-sensitive`): **without `show-sensitive` RouterOS leaves the passwords out silently**, and the preview counts the secrets without one. Dropping the `.rsc` on this window works too.\n\nThe file holds every subscriber's password in clear: delete it (and its copies) after the import."),
    ("ppp_import.map", "## Profile mapping\n\nEach profile the file's secrets use and where they go here. A profile with the same name here is used as is; one the file defines (`/ppp profile add`) and we lack is created from it; any other (red) must be mapped to one of ours, or nothing is imported.\n\nProfile fields with no counterpart here (on-up scripts, use-encryption, queues) are listed under \"Not imported\"."),
    ("ppp_import.on_conflict", "## Name already here\n\nWhat to do with a secret of the file whose name exists here: **skip** (ours stays), **replace** (the file's takes its place and keeps the id) or **import renamed** (`name-2`, `name-3`… — the subscriber only logs in with the new name)."),
    ("ppp_import.paste", "## Paste\n\nPaste the export's text here (what `/ppp secret export show-sensitive` prints on the MikroTik's terminal). It is never shown: it goes straight to the import and is forgotten on Import or when the window closes."),
];
