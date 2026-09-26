# Read-only LDAP/IDM MCP example

This project provides LDAP identity lookups and guarded reports. It performs no directory writes. **It is not a production deployment recipe.**

## Configuration

Copy `.env.example` to ignored `.env` and supply your own LDAPS endpoint, bind account, naming context, and trusted CA. Keep TLS verification enabled and authenticate callers through a deployment-specific gateway. The Compose example uses a project-local network and publishes no host port. Configure any shared gateway network privately, not in this public example.

Use only a least-privilege read account. Review export limits, access controls, logging, and retention before using real identities. Never include actual names, staff records, email addresses, site/job codes, host inventories, or entitlements in documentation or tests.

## Illustrative schema (not production-compatible)

ISD is a fictional district label. The sample uses fictional, literal LDAP extended attributes: `isdPreferredGivenName`, `isdPreferredSurname`, `isdWorkforceId`, `isdManagerWorkforceId`, `isdEmploymentStatus`, `isdSiteCode`, `isdPreviousSiteCode`, `isdJobCategory`, `isdPositionCode`, `isdAssignmentClass`, and `isdBadgeId`. For instance, a test site might be `SITE-A` and a job category `CATEGORY-1`. These names are deliberately fictional; LDAP filters and projected attributes in `server.py` refer to them literally, so they will **not work against an ordinary directory** unless its schema defines them. Adapt the code to your own privately documented schema and test all filters before connecting to any real directory. Standard attributes such as `uid`, `mail`, `employeeNumber`, `employeeType`, and vendor-defined `DirXML-*` and `nrf*` attributes retain their conventional spelling.

Public tool names use neutral ISD labels, for example `idm_search_isd_users`, `idm_get_isd_user_profile`, etc. This intentionally breaks callers of old tool names; no compatibility aliases disclose them.

## Validation

After configuring a local `.env`, run `docker compose config`, build, and test read-only queries with synthetic or approved test records. Verify TLS, scoped search, caller authorization, export safeguards and error logging. Do not expose the MCP endpoint to the public internet.
