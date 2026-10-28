# Service inventory

This file is synthetic demo data. The service names, teams, environments, and package versions are made up. Nothing here is a real company system.

Grok Bot teammates read `services.json` when an advisory names a package. Each service has an owner team, an environment, and npm dependencies pinned to exact versions. There are no version ranges in this file.

A teammate looks up the package name and the installed version. That lookup answers whether we run the package, and which version each service has. It does not decide whether a version sits inside an advisory range. The advisory reader, when it is built, supplies the affected range and the fixed version. Those facts are compared with this inventory. This repo does not do that comparison yet.

For the demo package `@acme-demo/yaml-lite`:

- `billing-api` runs `2.3.1` (affected).
- `ledger-worker` runs `1.9.2` (affected, old line, no fix).
- `portal-web` runs `2.4.3` (fixed).
- `notify-relay` does not depend on it.
- `directory-sync` does not depend on it either.

The other `@acme-demo/*` packages are filler so a service is not a single dependency.
