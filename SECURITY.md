# Security

Version 0.1 is an early release. Use findings as investigation leads and validate the configuration against your own data. Keep the process unprivileged with read-only access to necessary logs.

Report a vulnerability through the repository's private reporting option when available. Otherwise open an issue requesting a private contact without exploit details, credentials, or real log records. Use synthetic reproductions with documentation IP ranges.

The application does not open network sockets, execute input as commands, collect packet payloads, or change access policy. Local databases and exports contain sensitive operational metadata and are not encrypted. Retention and filesystem protection belong to the operator.
