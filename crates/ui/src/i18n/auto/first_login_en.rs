//! English explanations of the first-login warning (G0.3b, G0.3d), sorted
//! by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[(
    "first_login.no_password",
    "## Account without a password

This account of group **full** has no password. As on a RouterOS CHR, the router then takes the **empty password from any network** (always over TLS): whoever reaches it first logs in and controls it.

Keeping it so is your choice; nothing is forced or limited. The warning stays in the top bar, the health checks and every client until the account has a password.

Set it with **Set password**, `/user set admin password=…` in the terminal, or `user.set`. `--reset-admin-password` on the daemon brings back the empty password.",
)];
