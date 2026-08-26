#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";

type Profile = {
  root: string;
  languages: string[];
  frameworks: string[];
  environments: string[];
  tools: string[];
  packageManagers: string[];
  commands: string[];
  rules: string[];
  protectedPaths: string[];
  securityRules: string[];
  autonomyRules: string[];
  versions: string[];
  configurations: string[];
};

type JsonObject = Record<string, unknown>;

type GenerationManifest = {
  version: 1;
  tools: AiTool[];
  inputHash: string;
  outputs: Record<string, string>;
};

type Finding = {
  file: string;
  line: number;
  severity: "high" | "medium" | "low";
  rule: string;
  excerpt: string;
};

type SecurityRule = {
  id: string;
  severity: "high" | "medium" | "low";
  pattern: RegExp;
  extensions?: string[];
  message: string;
};

type AiTool = "devin" | "claude" | "cursor";

const root = process.cwd();

function exists(relative: string): boolean {
  return fs.existsSync(path.join(root, relative));
}

function read(relative: string): string {
  try {
    return fs.readFileSync(path.join(root, relative), "utf8");
  } catch {
    return "";
  }
}

function readJson(relative: string): JsonObject {
  try {
    const value: unknown = JSON.parse(read(relative));
    return value && typeof value === "object" && !Array.isArray(value) ? (value as JsonObject) : {};
  } catch {
    return {};
  }
}

function objectValue(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as JsonObject) : {};
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function yamlScalars(contents: string): Record<string, string> {
  const values: Record<string, string> = {};
  for (const line of contents.split("\n")) {
    const match = line.match(/^([A-Za-z][\w-]*):\s*(.*?)\s*(?:#.*)?$/);
    if (!match || !match[2]) continue;
    values[match[1]] = match[2].replace(/^['"]|['"]$/g, "");
  }
  return values;
}

function dependencyVersion(source: JsonObject, packageName: string): string | undefined {
  const packages = Array.isArray(source.packages) ? source.packages : [];
  const development = Array.isArray(source["packages-dev"]) ? source["packages-dev"] : [];
  for (const entry of [...packages, ...development]) {
    const dependency = objectValue(entry);
    if (dependency.name === packageName) return stringValue(dependency.version)?.replace(/^v/, "");
  }
  return undefined;
}

function addUnique(list: string[], value: string): void {
  if (!list.includes(value)) list.push(value);
}

function detect(): Profile {
  const profile: Profile = {
    root,
    languages: [],
    frameworks: [],
    environments: [],
    tools: [],
    packageManagers: [],
    commands: [],
    rules: [
      "Inspect existing code patterns before making changes.",
      "Prefer existing project conventions over introducing new patterns.",
      "Do not modify generated, vendor, dependency, or framework core files unless explicitly requested.",
      "Run relevant validation or tests after making changes."
    ],
    protectedPaths: ["vendor/", "node_modules/"],
    securityRules: [
      "Write secure code by default; treat all external input as untrusted.",
      "Never hardcode secrets, API keys, tokens, or passwords. Use environment variables or the project's secret storage.",
      "Validate and sanitize all input; escape all output for its rendering context.",
      "Use parameterized queries or the project's query builder. Never concatenate input into SQL.",
      "Never pass unvalidated input to shell commands, file paths, deserialization, or dynamic code evaluation.",
      "Enforce authentication and authorization checks on every entry point that changes or exposes data.",
      "Use vetted cryptographic libraries; never invent crypto and never use MD5 or SHA1 for passwords.",
      "Do not log secrets, credentials, or personal data, and do not expose stack traces to end users.",
      "Keep dependencies current and avoid introducing packages with known vulnerabilities."
    ],
    autonomyRules: [
      "Work autonomously. Do not ask questions unless the task is genuinely blocked.",
      "Resolve uncertainty by reading the codebase, configuration, and documentation before asking the user.",
      "When several reasonable approaches exist, pick the one that matches existing project conventions and continue.",
      "Do not ask for permission to read files, search the codebase, or inspect configuration.",
      "Run the necessary build, test, lint, and environment commands yourself instead of asking the user to run them.",
      "After making changes, verify them by running the relevant checks and fix what fails.",
      "Only stop and ask when a decision is irreversible, destructive, requires credentials, or depends on information that exists nowhere in the project.",
      "When you must ask, state your assumption, proceed on it if safe, and report it instead of waiting.",
      "Report what you did, what you ran, and the result. Do not ask the user to confirm each intermediate step."
    ],
    versions: [],
    configurations: []
  };

  const composer = read("composer.json");
  const composerJson = readJson("composer.json");
  const composerLock = readJson("composer.lock");
  const packageJsonContents = read("package.json");
  const packageJson = readJson("package.json");
  const composerDependencies = {
    ...objectValue(composerJson.require),
    ...objectValue(composerJson["require-dev"])
  };
  const nodeDependencies = {
    ...objectValue(packageJson.dependencies),
    ...objectValue(packageJson.devDependencies)
  };

  if (composer) {
    addUnique(profile.languages, "PHP");
    addUnique(profile.tools, "Composer");
    addUnique(profile.packageManagers, "Composer");
    const phpVersion = stringValue(composerDependencies.php);
    if (phpVersion) addUnique(profile.versions, `PHP ${phpVersion}`);
    for (const [name, script] of Object.entries(objectValue(composerJson.scripts))) {
      const values = Array.isArray(script) ? script : [script];
      if (values.some(value => typeof value === "string" && value.includes("drush"))) {
        addUnique(profile.commands, `composer ${name}`);
      }
    }
  }

  if (packageJsonContents) {
    addUnique(profile.languages, "JavaScript");
    addUnique(profile.tools, "Node.js");
    const packageManager = stringValue(packageJson.packageManager)?.split("@")[0];
    addUnique(profile.packageManagers, packageManager || "npm");
    const engines = objectValue(packageJson.engines);
    const nodeVersion = stringValue(engines.node);
    if (nodeVersion) addUnique(profile.versions, `Node.js ${nodeVersion}`);
    for (const name of Object.keys(objectValue(packageJson.scripts))) {
      addUnique(profile.commands, `${packageManager || "npm"} run ${name}`);
    }
  }

  if (exists("tsconfig.json")) addUnique(profile.languages, "TypeScript");
  if (exists(".git")) addUnique(profile.tools, "Git");

  // Environment detection.
  const ddevContents = read(".ddev/config.yaml");
  if (ddevContents || exists(".ddev")) {
    addUnique(profile.environments, "DDEV");
    addUnique(profile.commands, "ddev start");
    addUnique(profile.commands, "ddev describe");
    addUnique(profile.commands, "ddev ssh");
    if (ddevContents) {
      addUnique(profile.configurations, ".ddev/config.yaml");
      const ddev = yamlScalars(ddevContents);
      for (const key of ["name", "type", "docroot", "php_version", "webserver_type", "database"]) {
        if (ddev[key]) addUnique(profile.versions, `DDEV ${key}: ${ddev[key]}`);
      }
    }
    try {
      for (const name of fs.readdirSync(path.join(root, ".ddev", "commands", "web"))) {
        if (!name.startsWith(".")) addUnique(profile.commands, `ddev ${name}`);
      }
    } catch {}
  }

  if (
    exists("docker-compose.yml") ||
    exists("docker-compose.yaml") ||
    exists("compose.yml") ||
    exists("compose.yaml") ||
    exists("Dockerfile")
  ) {
    addUnique(profile.environments, "Docker");
    addUnique(profile.commands, "docker compose up -d");
    addUnique(profile.commands, "docker compose ps");
  }

  // Drupal detection.
  const drupalPackage = composerDependencies["drupal/core-recommended"]
    ? "drupal/core-recommended"
    : composerDependencies["drupal/core"]
      ? "drupal/core"
      : undefined;
  const isDrupal = Boolean(drupalPackage || exists("core/lib/Drupal.php") || exists("web/core/lib/Drupal.php"));
  const drupalVersion =
    dependencyVersion(composerLock, "drupal/core") ||
    dependencyVersion(composerLock, "drupal/core-recommended") ||
    (drupalPackage ? stringValue(composerDependencies[drupalPackage]) : undefined);

  if (isDrupal) {
    addUnique(profile.frameworks, drupalVersion ? `Drupal ${drupalVersion}` : "Drupal");
    if (drupalVersion) addUnique(profile.versions, `Drupal ${drupalVersion}`);
    profile.securityRules.push(
      "Use Drupal's database API with placeholders instead of raw SQL strings.",
      "Render user data through the render system or Twig auto-escaping; avoid #markup with raw input.",
      "Check permissions and access via route requirements or access handlers, not ad hoc logic.",
      "Validate and sanitize form input in form validation handlers."
    );
    profile.rules.push(
      "Follow Drupal coding standards.",
      "Prefer dependency injection over static service access.",
      "Do not modify Drupal core.",
      "Use Drupal APIs and services instead of bypassing framework conventions.",
      "Respect cacheability metadata where applicable.",
      "Use configuration management for deployable configuration."
    );
    profile.protectedPaths.push("core/", "web/core/");
  }

  const drushConstraint = stringValue(composerDependencies["drush/drush"]);
  const drushVersion = dependencyVersion(composerLock, "drush/drush") || drushConstraint;
  if (drushVersion || exists("vendor/bin/drush")) {
    addUnique(profile.tools, drushVersion ? `Drush ${drushVersion}` : "Drush");
    if (drushVersion) addUnique(profile.versions, `Drush ${drushVersion}`);
    const prefix = profile.environments.includes("DDEV") ? "ddev drush" : "vendor/bin/drush";
    addUnique(profile.commands, `${prefix} status`);
    addUnique(profile.commands, `${prefix} cr`);
    addUnique(profile.commands, `${prefix} updatedb`);
    addUnique(profile.commands, `${prefix} config:export`);
    addUnique(profile.commands, `${prefix} config:import`);
  }
  if (isDrupal && profile.environments.includes("DDEV")) addUnique(profile.commands, "ddev composer install");

  // Laravel detection.
  if (exists("artisan") || composerDependencies["laravel/framework"]) {
    addUnique(profile.frameworks, "Laravel");
    profile.rules.push(
      "Follow existing Laravel conventions.",
      "Keep controllers focused and use existing service/action patterns.",
      "Use migrations for database schema changes."
    );
    profile.protectedPaths.push("vendor/");
    addUnique(profile.commands, "php artisan test");
  }

  // PHP quality tooling.
  const qualityTools = [
    { name: "PHPStan", package: "phpstan/phpstan", files: ["phpstan.neon", "phpstan.neon.dist"], command: "vendor/bin/phpstan analyse" },
    { name: "PHP_CodeSniffer", package: "squizlabs/php_codesniffer", files: ["phpcs.xml", "phpcs.xml.dist", ".phpcs.xml", ".phpcs.xml.dist"], command: "vendor/bin/phpcs" },
    { name: "PHPUnit", package: "phpunit/phpunit", files: ["phpunit.xml", "phpunit.xml.dist"], command: "vendor/bin/phpunit" }
  ];
  for (const tool of qualityTools) {
    const configuration = tool.files.find(file => exists(file));
    const version = dependencyVersion(composerLock, tool.package) || stringValue(composerDependencies[tool.package]);
    if (!configuration && !version) continue;
    addUnique(profile.tools, version ? `${tool.name} ${version}` : tool.name);
    if (version) addUnique(profile.versions, `${tool.name} ${version}`);
    if (configuration) addUnique(profile.configurations, configuration);
    addUnique(profile.commands, tool.command);
  }

  // Node ecosystem.
  if (exists("package-lock.json")) addUnique(profile.packageManagers, "npm");
  if (exists("pnpm-lock.yaml")) addUnique(profile.packageManagers, "pnpm");
  if (exists("yarn.lock")) addUnique(profile.packageManagers, "Yarn");
  if (nodeDependencies.next) addUnique(profile.frameworks, `Next.js ${String(nodeDependencies.next)}`);
  if (nodeDependencies.vite) addUnique(profile.tools, `Vite ${String(nodeDependencies.vite)}`);

  return profile;
}

function list(values: string[]): string {
  return values.length ? values.map(value => `- ${value}`).join("\n") : "- None detected";
}

function rules(profile: Profile): string {
  return profile.rules.map(rule => `- ${rule}`).join("\n");
}

function securityRules(profile: Profile): string {
  return profile.securityRules.map(rule => `- ${rule}`).join("\n");
}

function autonomyRules(profile: Profile): string {
  return profile.autonomyRules.map(rule => `- ${rule}`).join("\n");
}

function commands(profile: Profile): string {
  return profile.commands.length
    ? profile.commands.map(command => `- \`${command}\``).join("\n")
    : "- Inspect project documentation and package scripts.";
}

function projectContext(profile: Profile): string {
  return `# ProjectBrain Context

## Project Root

\`${profile.root}\`

## Detected Languages

${list(profile.languages)}

## Detected Frameworks

${list(profile.frameworks)}

## Detected Development Environments

${list(profile.environments)}

## Detected Tools

${list(profile.tools)}

## Package Managers

${list(profile.packageManagers)}

## Detected Versions

${list(profile.versions)}

## Detected Configuration

${list(profile.configurations)}

## General Coding Rules

${rules(profile)}

## Autonomy Rules

${autonomyRules(profile)}

## Protected Paths

${list(profile.protectedPaths)}

## Security Requirements

All generated or modified code must satisfy these requirements.

${securityRules(profile)}

## Suggested Commands

${commands(profile)}
`;
}

function devinContext(profile: Profile): string {
  return `${projectContext(profile)}

# Devin Operating Instructions

## Before Making Changes

1. Inspect the relevant existing implementation.
2. Search for similar code before creating a new pattern.
3. Understand the detected environment before running commands.
4. Avoid modifying protected paths.
5. Make the smallest reasonable change.

## Autonomy

${autonomyRules(profile)}

## Security Requirements

${securityRules(profile)}

After writing code, review your own diff for injection, access control, secret handling, and
input validation problems before reporting the task as complete. See \`.ai/security-report.md\`
for issues already detected in this project.

## Environment Rules

${
  profile.environments.includes("DDEV")
    ? "- This project uses DDEV. Prefer running PHP, Composer, Drush, and project commands through DDEV when appropriate.\n- Do not assume host PHP matches the project's configured PHP version."
    : "- No DDEV environment was detected. Inspect project documentation before assuming runtime commands."
}

${
  profile.frameworks.includes("Drupal")
    ? `
## Drupal Rules

- Follow Drupal coding standards.
- Do not modify Drupal core.
- Prefer dependency injection.
- Reuse existing services, plugins, and architectural patterns.
- Consider configuration and cacheability when changing Drupal behavior.
`
    : ""
}
`;
}

function claudeContext(profile: Profile): string {
  return `${projectContext(profile)}

# Agent Instructions

Treat this document as generated project context.

Before implementing a task:
- Read the relevant code.
- Identify existing conventions.
- Reuse project patterns.
- Run relevant checks after changes.

# Autonomy

${autonomyRules(profile)}

# Security Requirements

${securityRules(profile)}

After implementing a change, re-read the diff and confirm none of the requirements above are
violated. Detected issues in the existing codebase are listed in \`.ai/security-report.md\`.
`;
}

function cursorContext(profile: Profile): string {
  return `---
description: ProjectBrain detected project rules
alwaysApply: true
---

# Project Rules

${rules(profile)}

## Security Rules

${securityRules(profile)}

## Autonomy Rules

${autonomyRules(profile)}

## Environment

${list(profile.environments)}

## Frameworks

${list(profile.frameworks)}

## Protected Paths

${list(profile.protectedPaths)}
`;
}

const SKIP_DIRECTORIES = new Set([
  ".git",
  ".ai",
  "node_modules",
  "vendor",
  "dist",
  "build",
  "coverage",
  ".cache",
  ".ddev"
]);

const SCAN_EXTENSIONS = new Set([
  ".php",
  ".module",
  ".inc",
  ".install",
  ".theme",
  ".js",
  ".mjs",
  ".cjs",
  ".jsx",
  ".ts",
  ".tsx",
  ".py",
  ".rb",
  ".go",
  ".java",
  ".twig",
  ".yml",
  ".yaml",
  ".env",
  ".sh"
]);

const MAX_FILE_BYTES = 512 * 1024;
const MAX_FINDINGS = 500;

const SECURITY_RULES: SecurityRule[] = [
  {
    id: "hardcoded-secret",
    severity: "high",
    pattern:
      /(?:api[_-]?key|secret|password|passwd|passphrase|access[_-]?token|auth[_-]?token|private[_-]?key)\s*(?:=|:|=>)\s*["'][^"'\s]{8,}["']/i,
    message: "Possible hardcoded credential. Move it to an environment variable or secret store."
  },
  {
    id: "private-key-material",
    severity: "high",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/,
    message: "Private key material committed to the repository."
  },
  {
    id: "aws-access-key",
    severity: "high",
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    message: "AWS access key ID found in source."
  },
  {
    id: "sql-string-interpolation",
    severity: "high",
    pattern:
      /(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b[^;\n]*(?:\$\{|\$_(?:GET|POST|REQUEST|COOKIE)|"\s*\+\s*|'\s*\.\s*\$)/i,
    message: "SQL built by string concatenation or interpolation. Use parameterized queries."
  },
  {
    id: "dynamic-code-evaluation",
    severity: "high",
    pattern: /(?:^|[^\w$>])(?:eval|assert)\s*\(|new\s+Function\s*\(/,
    extensions: [".php", ".module", ".inc", ".install", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"],
    message: "Dynamic code evaluation. Replace with explicit logic."
  },
  {
    id: "shell-execution",
    severity: "high",
    pattern:
      /(?:shell_exec|passthru|popen|proc_open|system)\s*\(|\bexec\s*\(\s*[`"'][^`"']*(?:\$\{|\$_)|child_process[\s\S]{0,40}\bexec\s*\(/,
    message: "Shell execution reached with interpolated input. Use argument arrays and validate input."
  },
  {
    id: "unsafe-deserialization",
    severity: "high",
    pattern: /\bunserialize\s*\(|yaml\.load\s*\(|pickle\.loads?\s*\(/,
    message: "Unsafe deserialization of untrusted data."
  },
  {
    id: "superglobal-used-directly",
    severity: "medium",
    pattern: /\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*(?:\)|;|\.|,)/,
    extensions: [".php", ".module", ".inc", ".install", ".theme"],
    message: "Request input used without validation or sanitization."
  },
  {
    id: "xss-sink",
    severity: "medium",
    pattern: /\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|\becho\s+\$_(?:GET|POST|REQUEST)/,
    message: "Untrusted data may reach an HTML sink. Escape output for its context."
  },
  {
    id: "weak-hash",
    severity: "medium",
    pattern: /\b(?:md5|sha1)\s*\(/i,
    message: "Weak hash function. Use a password hashing function or SHA-256+ for integrity."
  },
  {
    id: "tls-verification-disabled",
    severity: "high",
    pattern:
      /rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*(?:,|=>)\s*(?:false|0)|verify\s*=\s*False/,
    message: "TLS certificate verification disabled."
  },
  {
    id: "path-traversal",
    severity: "medium",
    pattern:
      /(?:file_get_contents|fopen|readFile(?:Sync)?|include|require)\s*\(?\s*[^;\n]{0,40}(?:\$_(?:GET|POST|REQUEST)|req\.(?:query|params|body))/,
    message: "File path derived from request input. Validate against an allowlist."
  },
  {
    id: "twig-raw-filter",
    severity: "medium",
    pattern: /\|\s*raw\b/,
    extensions: [".twig"],
    message: "Twig `raw` filter disables escaping. Confirm the value is trusted."
  }
];

function collectFiles(directory: string, collected: string[]): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(directory, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const absolute = path.join(directory, entry.name);

    if (entry.isSymbolicLink()) continue;

    if (entry.isDirectory()) {
      if (SKIP_DIRECTORIES.has(entry.name)) continue;
      collectFiles(absolute, collected);
      continue;
    }

    if (!entry.isFile()) continue;

    const extension = path.extname(entry.name);
    const isEnvFile = entry.name.startsWith(".env");

    if (!isEnvFile && !SCAN_EXTENSIONS.has(extension)) continue;

    try {
      if (fs.statSync(absolute).size > MAX_FILE_BYTES) continue;
    } catch {
      continue;
    }

    collected.push(absolute);
  }
}

function scanSecurity(): Finding[] {
  const files: string[] = [];
  collectFiles(root, files);

  const findings: Finding[] = [];

  for (const file of files) {
    if (findings.length >= MAX_FINDINGS) break;

    let contents: string;
    try {
      contents = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }

    const extension = path.extname(file);
    const relative = path.relative(root, file);
    const lines = contents.split("\n");

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      if (!line || line.length > 1000) continue;

      for (const rule of SECURITY_RULES) {
        if (rule.extensions && !rule.extensions.includes(extension)) continue;
        if (!rule.pattern.test(line)) continue;

        findings.push({
          file: relative,
          line: index + 1,
          severity: rule.severity,
          rule: rule.id,
          excerpt: line.trim().slice(0, 200)
        });

        if (findings.length >= MAX_FINDINGS) break;
      }

      if (findings.length >= MAX_FINDINGS) break;
    }
  }

  return findings;
}

function securityReport(profile: Profile, findings: Finding[]): string {
  const order: Finding["severity"][] = ["high", "medium", "low"];
  const messages = new Map(SECURITY_RULES.map(rule => [rule.id, rule.message]));

  const sections = order
    .map(severity => {
      const group = findings.filter(finding => finding.severity === severity);
      const heading = `## ${severity.toUpperCase()} (${group.length})`;

      if (!group.length) return `${heading}\n\nNone detected.`;

      const rows = group
        .map(
          finding =>
            `- \`${finding.file}:${finding.line}\` **${finding.rule}** — ${
              messages.get(finding.rule) ?? ""
            }\n  \`\`\`\n  ${finding.excerpt}\n  \`\`\``
        )
        .join("\n");

      return `${heading}\n\n${rows}`;
    })
    .join("\n\n");

  return `# Security Report

Generated by ProjectBrain. Pattern-based scan; verify every finding manually.

Total findings: ${findings.length}

## Requirements For New Code

${securityRules(profile)}

${sections}
`;
}

const AI_TOOLS: AiTool[] = ["devin", "claude", "cursor"];

function parseTool(value: string | undefined): AiTool[] | undefined {
  if (!value) return undefined;
  if (value === "all") return AI_TOOLS;
  return AI_TOOLS.includes(value as AiTool) ? [value as AiTool] : undefined;
}

async function selectTools(): Promise<AiTool[]> {
  const toolArgument = process.argv.find(argument => argument.startsWith("--tool="))?.split("=", 2)[1];
  const selectedFromArgument = parseTool(toolArgument);
  if (selectedFromArgument) return selectedFromArgument;

  if (toolArgument || !stdin.isTTY) {
    throw new Error("Choose an AI tool with --tool=devin, --tool=claude, --tool=cursor, or --tool=all.");
  }

  const prompt = createInterface({ input: stdin, output: stdout });
  try {
    console.log("Which AI tool should ProjectBrain generate files for?");
    console.log("  1. Devin");
    console.log("  2. Claude Code");
    console.log("  3. Cursor");
    console.log("  4. All tools");
    const answer = (await prompt.question("Select [1-4]: ")).trim().toLowerCase();
    const selections: Record<string, AiTool[]> = {
      "1": ["devin"],
      devin: ["devin"],
      "2": ["claude"],
      claude: ["claude"],
      "claude code": ["claude"],
      "3": ["cursor"],
      cursor: ["cursor"],
      "4": AI_TOOLS,
      all: AI_TOOLS
    };
    const selected = selections[answer];
    if (!selected) throw new Error("Invalid selection. Choose 1, 2, 3, or 4.");
    return selected;
  } finally {
    prompt.close();
  }
}

const CONTEXT_INPUTS = [
  ".ddev/config.yaml",
  "composer.json",
  "composer.lock",
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "tsconfig.json",
  "phpstan.neon",
  "phpstan.neon.dist",
  "phpcs.xml",
  "phpcs.xml.dist",
  ".phpcs.xml",
  ".phpcs.xml.dist",
  "phpunit.xml",
  "phpunit.xml.dist"
];

function hash(value: string | Buffer): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function inputHash(): string {
  const inputs = CONTEXT_INPUTS.filter(exists)
    .map(file => `${file}\0${read(file)}`)
    .join("\0");
  return hash(`${inputs}\0${JSON.stringify(detect())}`);
}

function outputHashes(files: string[]): Record<string, string> {
  return Object.fromEntries(
    files.map(file => [path.relative(root, file), hash(fs.readFileSync(file))])
  );
}

function readManifest(): GenerationManifest | undefined {
  try {
    return JSON.parse(read(".ai/projectbrain.json")) as GenerationManifest;
  } catch {
    return undefined;
  }
}

function checkContext(): boolean {
  const manifest = readManifest();
  if (!manifest || manifest.version !== 1 || !Array.isArray(manifest.tools)) {
    console.error("ProjectBrain context has not been generated. Run projectbrain init.");
    return false;
  }

  const problems: string[] = [];
  if (manifest.inputHash !== inputHash()) problems.push("Project configuration changed since generation.");
  for (const [relative, expectedHash] of Object.entries(manifest.outputs)) {
    if (!exists(relative)) problems.push(`Generated file is missing: ${relative}`);
    else if (hash(fs.readFileSync(path.join(root, relative))) !== expectedHash) {
      problems.push(`Generated file was modified: ${relative}`);
    }
  }

  if (problems.length) {
    console.error("ProjectBrain context drift detected:");
    for (const problem of problems) console.error(`  - ${problem}`);
    console.error(`Run projectbrain update --tool=${manifest.tools.length === AI_TOOLS.length ? "all" : manifest.tools[0]}.`);
    return false;
  }

  console.log("ProjectBrain context is current.");
  return true;
}

function writeOutput(profile: Profile, selectedTools: AiTool[]): void {
  const outputDir = path.join(root, ".ai");
  fs.mkdirSync(outputDir, { recursive: true });

  fs.writeFileSync(path.join(outputDir, "project-context.md"), projectContext(profile));
  fs.writeFileSync(
    path.join(outputDir, "commands.md"),
    `# Detected Commands\n\n${commands(profile)}\n`
  );

  const generatedFiles = [path.join(outputDir, "project-context.md"), path.join(outputDir, "commands.md")];

  if (selectedTools.includes("devin")) {
    const file = path.join(root, "AGENTS.md");
    fs.writeFileSync(file, devinContext(profile));
    generatedFiles.push(file);
  }

  if (selectedTools.includes("claude")) {
    const file = path.join(root, "CLAUDE.md");
    fs.writeFileSync(file, claudeContext(profile));
    generatedFiles.push(file);
  }

  if (selectedTools.includes("cursor")) {
    const cursorDir = path.join(root, ".cursor", "rules");
    const file = path.join(cursorDir, "projectbrain.mdc");
    fs.mkdirSync(cursorDir, { recursive: true });
    fs.writeFileSync(file, cursorContext(profile));
    generatedFiles.push(file);
  }

  const findings = scanSecurity();
  const reportFile = path.join(outputDir, "security-report.md");
  fs.writeFileSync(reportFile, securityReport(profile, findings));
  generatedFiles.push(reportFile);

  const manifest: GenerationManifest = {
    version: 1,
    tools: selectedTools,
    inputHash: inputHash(),
    outputs: outputHashes(generatedFiles)
  };
  const manifestFile = path.join(outputDir, "projectbrain.json");
  fs.writeFileSync(manifestFile, `${JSON.stringify(manifest, null, 2)}\n`);
  generatedFiles.push(manifestFile);

  console.log("ProjectBrain analysis complete.");
  console.log("Generated:");
  for (const file of generatedFiles) console.log(`  ${path.relative(root, file)}`);
  console.log("");
  console.log("Detected:");
  console.log(`  Languages: ${profile.languages.join(", ") || "none"}`);
  console.log(`  Frameworks: ${profile.frameworks.join(", ") || "none"}`);
  console.log(`  Environments: ${profile.environments.join(", ") || "none"}`);
  console.log("");
  console.log("Security scan:");
  console.log(`  High: ${findings.filter(finding => finding.severity === "high").length}`);
  console.log(`  Medium: ${findings.filter(finding => finding.severity === "medium").length}`);
  console.log(`  Low: ${findings.filter(finding => finding.severity === "low").length}`);
  console.log(`  Report: ${reportFile}`);
}

const commandArgument = process.argv[2];
const command = commandArgument?.startsWith("--") ? commandArgument.slice(2) : commandArgument;

switch (command) {
  case "init":
  case "scan":
  case "update":
    writeOutput(detect(), await selectTools());
    break;
  case "check":
    process.exitCode = checkContext() ? 0 : 1;
    break;
  case "security": {
    const findings = scanSecurity();
    const outputDir = path.join(root, ".ai");
    fs.mkdirSync(outputDir, { recursive: true });
    fs.writeFileSync(
      path.join(outputDir, "security-report.md"),
      securityReport(detect(), findings)
    );
    console.log(`Security findings: ${findings.length}`);
    console.log(`Report: ${path.join(outputDir, "security-report.md")}`);
    break;
  }
  default:
    console.log("ProjectBrain");
    console.log("");
    console.log("Usage:");
    console.log("  npm run build");
    console.log("  node dist/index.js init [--tool=devin|claude|cursor|all]");
    console.log("");
    console.log("Generating commands prompt for an AI tool when --tool is omitted.");
    console.log("");
    console.log("Commands:");
    console.log("  init   Analyze project and generate context");
    console.log("  scan   Analyze project and generate context");
    console.log("  update Regenerate context");
    console.log("  check  Check generated context for drift");
    console.log("  security Scan source for security issues only");

    process.exit(command ? 1 : 0);
}
