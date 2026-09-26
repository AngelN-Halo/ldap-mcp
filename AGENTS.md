# Contributor guidance

- Keep directory operations read-only, bounded, and correctly escaped.
- Never commit `.env`, certificates, keys, logs, exports, or real identity records.
- Keep site-specific hosts, naming contexts, access policies, and network topology outside this example.
- The source's legacy custom LDAP attributes and tool names are compatibility-sensitive. Review them separately before public release; do not mass-rename schema identifiers.
- Test with synthetic records and verified TLS. Enforce authenticated and authorized client access at deployment.
