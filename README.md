# ProjectBrain

A local-first developer context generator.

ProjectBrain detects the project's environment and stack, then generates context files for AI coding agents.

## Current MVP

Detects:

- DDEV
- Docker / Docker Compose
- Drupal
- Laravel
- PHP / Composer
- Node.js / TypeScript
- Git
- package managers

Prompts for the AI tool and generates its native, automatically loaded instructions:

- Devin: `AGENTS.md`
- Claude Code: `CLAUDE.md`
- Cursor: `.cursor/rules/projectbrain.mdc`

Shared analysis remains in:

- `.ai/project-context.md`
- `.ai/commands.md`
- `.ai/security-report.md`

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

Security scan only:

```bash
node dist/index.js security
```

## Example

Inside a Drupal + DDEV project:

```bash
node /path/to/projectbrain/dist/index.js init
```

This prompts for an AI tool, creates its native instruction file, and writes shared analysis to `.ai`.

## Important

This is an MVP foundation. The next major features should be:

1. Parse `.ddev/config.yaml`
2. Parse `composer.json` and `package.json`
3. Detect Drupal version accurately
4. Detect PHP_CodeSniffer / PHPStan / PHPUnit configuration
5. Detect Drush commands
6. Generate real agent-specific output formats
7. Add context drift detection
8. Add `projectbrain check`
