# Service inventory

This file is synthetic demo data. The service names, teams, environments, and package versions are made up. Nothing here is a real company system.

Grok Bot teammates can read `services.json` when a package name comes up. Each service has an owner team, an environment, and npm dependencies pinned to exact versions. There are no version ranges in this file.

A teammate looks up the package name and the installed version. That lookup answers whether we run the package, and which version each service has. It does not decide whether a version sits inside a range.

For the demo package `@acme-demo/yaml-lite`:

- `billing-api` runs `2.3.1`.
- `ledger-worker` runs `1.9.2`.
- `portal-web` runs `2.4.3`.
- `notify-relay` does not depend on it.
- `directory-sync` does not depend on it either.

The other `@acme-demo/*` packages are filler so a service is not a single dependency.
