# ProjectBrain

A local-first developer context generator.

ProjectBrain detects the project's environment and stack, then generates context files for AI coding agents.

## Current MVP

Detects:

- DDEV settings from `.ddev/config.yaml`, including custom web commands
- Docker / Docker Compose
- Drupal and its installed version from `composer.lock`
- Laravel
- PHP, Composer dependencies, scripts, and version constraints
- Node.js, TypeScript, package scripts, frameworks, and package managers
- Drush versions and common commands
- PHP_CodeSniffer, PHPStan, and PHPUnit versions and configuration files
- Git

Prompts for the AI tool and generates its native, automatically loaded instructions:

- Devin: `AGENTS.md`
- Claude Code: `CLAUDE.md`
- Cursor: `.cursor/rules/projectbrain.mdc`

Shared analysis remains in:

- `.ai/project-context.md`
- `.ai/commands.md`
- `.ai/security-report.md`
- `.ai/projectbrain.json` drift metadata

Every generated context file includes autonomy rules that tell agents to work without asking
questions, resolve uncertainty by reading the project, and run the required build, test, and
environment commands themselves.

Every generated context file includes explicit security requirements for agent-written code, and
each run scans the project source for common security issues (hardcoded secrets, SQL string
interpolation, unsafe deserialization, shell and eval sinks, XSS sinks, weak hashes, disabled TLS
verification, request-derived file paths).

## Requirements

- Node.js 20+

No third-party npm packages are required.

## Run

```bash
npm run build
node dist/index.js init
```

Or:

```bash
npm run start -- init
```

ProjectBrain asks whether to generate instructions for Devin, Claude Code, Cursor, or all three.
For non-interactive use, pass `--tool=devin`, `--tool=claude`, `--tool=cursor`, or `--tool=all`:

```bash
projectbrain --init --tool=devin
```

Check whether project configuration or generated context has drifted:

```bash
projectbrain check
```

The command exits with status 1 when regeneration is required, making it suitable for CI.

Security scan only:

```bash
projectbrain security
```

## Example

Inside a Drupal + DDEV project:

```bash
node /path/to/projectbrain/dist/index.js init
```

This prompts for an AI tool, creates its native instruction file, and writes shared analysis to `.ai`.

## Context drift

Each generation records hashes of relevant project configuration and every generated file in
`.ai/projectbrain.json`. Run `projectbrain check` after dependency or environment changes to verify
that the agent instructions are still current. Regenerate stale context with `projectbrain update`.
