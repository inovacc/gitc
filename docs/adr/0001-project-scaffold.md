# ADR-0001: Project Scaffold and Tooling Choices

## Status
Accepted

## Context
A new Go project needs a standard structure, tooling, and runtime foundation.

## Decision
- **Runtime:** github.com/inovacc/mantle (bootstrap/logger/obsv)
- **Type:** cli; **Layout:** single
- **CLI Framework:** Cobra (supplied to mantle bootstrap)
- **Task Runner:** Taskfile
- **Linting:** golangci-lint v2
- **Releases:** GoReleaser
- **Module Path:** github.com/dyammarcano/gitc

## Consequences
Consistent structure, cross-platform builds, automated releases, mantle-managed
lifecycle/config/logging from day one.
