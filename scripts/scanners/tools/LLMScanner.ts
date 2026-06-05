import * as fs from "fs";
import * as path from "path";
import { BaseScanner } from "./BaseScanner";

// ─── Package JSON Shapes ─────────────────────────────────────────────
// These mirror the parts of package.json / package-lock.json we inspect.
// Defined narrowly to avoid `any`.

interface PackageJsonShape {
  name?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

/** A single entry under `packages` (lockfile v2/v3). */
interface LockfileV2Entry {
  version?: string;
  resolved?: string;
  hasInstallScript?: boolean;
  link?: boolean;
}

/** A single entry under `dependencies` (lockfile v1 – recursive). */
interface LockfileV1Entry {
  version?: string;
  resolved?: string;
  dependencies?: Record<string, LockfileV1Entry>;
}

interface PackageLockShape {
  lockfileVersion?: number;
  packages?: Record<string, LockfileV2Entry>;
  dependencies?: Record<string, LockfileV1Entry>;
}

/** Internal struct for flagged dependencies. */
interface DependencyFlag {
  name: string;
  version?: string;
  resolved?: string;
  reason: string;
}

// ─── Constants ───────────────────────────────────────────────────────

/**
 * Directories inside the plugin root to scrape source code from.
 *
 * NOTE: The `api/` directory is deliberately excluded. It contains
 * framework-provided .d.ts type declarations (copied from generator-joplin),
 * not user-written code.  Scanning it wastes ~30K tokens and causes
 * false positives because the declarations reference security-sensitive
 * API names like `joplin.require()` in their type signatures.
 */
const SOURCE_DIRS = ["src"] as const;

/** File extensions considered source code. */
const SOURCE_EXTENSIONS: ReadonlySet<string> = new Set([
  ".ts",
  ".js",
  ".tsx",
  ".jsx",
]);

// All packages from this scope are trusted and excluded from the SCA summary
const TRUSTED_SCOPE = "@joplin/";

/** Standard npm registry prefix – anything NOT starting with this is flagged. */
const NPM_REGISTRY_PREFIX = "https://registry.npmjs.org/";

export abstract class LLMScanner extends BaseScanner {

  // Build the full text payload that will be sent to the LLM
  protected scrapeDataForScan(targetDir: string): string {
    const codeSection = this.harvestSourceFiles(targetDir);
    const depsSection = this.reducePackageLock(targetDir);

    return `CODE:\n${codeSection}\n\nDEPENDENCIES:\n${depsSection}`;
  }

  // Read all files from the `src/` dir and return them as a single string with file-path separators
  private harvestSourceFiles(targetDir: string): string {
    const collectedChunks: string[] = [];

    for (const dir of SOURCE_DIRS) {
      const fullPath = path.join(targetDir, dir);
      if (!fs.existsSync(fullPath)) continue;

      const stat = fs.statSync(fullPath);
      if (!stat.isDirectory()) continue;

      this.collectFilesRecursively(fullPath, targetDir, collectedChunks);
    }

    if (collectedChunks.length === 0) {
      return "[No source files found in src/ directory]";
    }

    return collectedChunks.join("\n");
  }

  // Traverse `dirPath` recursively, adding formatted code blocks for every file whose extension is in `SOURCE_EXTENSIONS`
  private collectFilesRecursively(
    dirPath: string,
    rootDir: string,
    output: string[],
  ): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dirPath, { withFileTypes: true });
    } catch {
      // skip silently.
      return;
    }

    for (const entry of entries) {
      // Skip symlinks entirely as they could point outside the checked-out directory.
      if (entry.isSymbolicLink()) continue;

      const fullPath = path.join(dirPath, entry.name);

      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === ".git") continue;
        this.collectFilesRecursively(fullPath, rootDir, output);
        continue;
      }

      if (!entry.isFile()) continue;
      if (!SOURCE_EXTENSIONS.has(path.extname(entry.name))) continue;

      try {
        const content = fs.readFileSync(fullPath, "utf-8");
        const relativePath = path.relative(rootDir, fullPath);
        
        const normalized = relativePath.split(path.sep).join("/");
        output.push(`\n--- FILE: ${normalized} ---\n${content}`);
      } catch {
        // Unreadable file – note it but keep going.
        const relativePath = path.relative(rootDir, fullPath);
        output.push(`\n--- FILE: ${relativePath} --- [READ ERROR]\n`);
      }
    }
  }

  // Build a lightweight text summary of the plugin's dependency tree
  private reducePackageLock(targetDir: string): string {
    const sections: string[] = [];

    // Direct dependencies from package.json 
    const pkgJsonPath = path.join(targetDir, "package.json");
    if (fs.existsSync(pkgJsonPath)) {
      const pkgJson = this.readJsonSafe<PackageJsonShape>(pkgJsonPath);
      if (pkgJson) {
        sections.push(
          this.formatDirectDeps("dependencies", pkgJson.dependencies),
        );
        sections.push(
          this.formatDirectDeps("devDependencies", pkgJson.devDependencies),
        );
        sections.push(this.formatPluginScripts(pkgJson.scripts));
      } else {
        sections.push("## package.json\n[Failed to parse]");
      }
    } else {
      sections.push("## package.json\n[Not found]");
    }

    // simplifying lockfile
    const lockPath = path.join(targetDir, "package-lock.json");
    if (!fs.existsSync(lockPath)) {
      sections.push("\n## Lockfile Analysis\n[No package-lock.json found]");
      return sections.join("\n");
    }

    const lockfile = this.readJsonSafe<PackageLockShape>(lockPath);
    if (!lockfile) {
      sections.push(
        "\n## Lockfile Analysis\n[Failed to parse package-lock.json]",
      );
      return sections.join("\n");
    }

    const flags: DependencyFlag[] = [];

    if (lockfile.packages) {
      this.analyzeLockfileV2(lockfile.packages, flags);
    } else if (lockfile.dependencies) {
      this.analyzeLockfileV1(lockfile.dependencies, flags);
    }

    // Split flags into two groups for the report.
    const installScriptFlags = flags.filter(
      (f) => f.reason === "hasInstallScript",
    );
    const nonRegistryFlags = flags.filter(
      (f) => f.reason === "nonRegistrySource",
    );

    sections.push(
      "\n## Packages with Install Scripts (postinstall / preinstall)",
    );
    if (installScriptFlags.length > 0) {
      for (const f of installScriptFlags) {
        sections.push(`- ${f.name}@${f.version ?? "unknown"}(Source: ${f.resolved ?? "registry"})`);
      }
    } else {
      sections.push("(none detected)");
    }

    sections.push("\n## Packages Resolved from Non-NPM Sources");
    if (nonRegistryFlags.length > 0) {
      for (const f of nonRegistryFlags) {
        sections.push(`- ${f.name} → ${f.resolved ?? "unknown source"}`);
      }
    } else {
      sections.push("(all packages resolve to registry.npmjs.org)");
    }

    return sections.join("\n");
  }

  // ── Lockfile Version Handlers ─────────────────────────────────────

  /**
   * Analyse the `packages` object from a v2/v3 lockfile.
   *
   * Keys look like `node_modules/express` or
   * `node_modules/foo/node_modules/@scope/bar`.
   */
  private analyzeLockfileV2(
    packages: Record<string, LockfileV2Entry>,
    flags: DependencyFlag[],
  ): void {
    for (const [pkgPath, entry] of Object.entries(packages)) {
      // Skip the root entry (empty string key).
      if (pkgPath === "") continue;

      // Skip workspace links – they're local packages, not third-party.
      if (entry.link === true) continue;

      const pkgName = this.extractPackageNameFromPath(pkgPath);
      if (pkgName.startsWith(TRUSTED_SCOPE)) continue;

      if (entry.hasInstallScript === true) {
        flags.push({
          name: pkgName,
          version: entry.version,
          reason: "hasInstallScript",
        });
      }

      if (entry.resolved && !entry.resolved.startsWith(NPM_REGISTRY_PREFIX)) {
        flags.push({
          name: pkgName,
          resolved: entry.resolved,
          reason: "nonRegistrySource",
        });
      }
    }
  }

  /**
   * Analyse the nested `dependencies` tree from a v1 lockfile.
   *
   * v1 doesn't have `hasInstallScript` so we can only flag
   * non-registry resolved URLs here.
   */
  private analyzeLockfileV1(
    deps: Record<string, LockfileV1Entry>,
    flags: DependencyFlag[],
  ): void {
    for (const [name, entry] of Object.entries(deps)) {
      if (name.startsWith(TRUSTED_SCOPE)) continue;

      if (entry.resolved && !entry.resolved.startsWith(NPM_REGISTRY_PREFIX)) {
        flags.push({
          name,
          version: entry.version,
          resolved: entry.resolved,
          reason: "nonRegistrySource",
        });
      }

      // v1 has nested dependencies – recurse.
      if (entry.dependencies) {
        this.analyzeLockfileV1(entry.dependencies, flags);
      }
    }
  }

  // ── Helpers ───────────────────────────────────────────────────────

  /**
   * Extract the npm package name from a v2/v3 lockfile key.
   *
   * Examples:
   *  - `"node_modules/express"`                        → `"express"`
   *  - `"node_modules/foo/node_modules/@scope/bar"`    → `"@scope/bar"`
   */
  private extractPackageNameFromPath(lockfilePath: string): string {
    const marker = "node_modules/";
    const lastIndex = lockfilePath.lastIndexOf(marker);
    if (lastIndex === -1) return lockfilePath;
    return lockfilePath.substring(lastIndex + marker.length);
  }

  /**
   * Format one section of direct deps from package.json.
   * Filters out `@joplin/*` packages.
   */
  private formatDirectDeps(
    label: string,
    deps: Record<string, string> | undefined,
  ): string {
    const header = `## Direct ${label} (package.json)`;
    if (!deps || Object.keys(deps).length === 0) {
      return `${header}\n(none)`;
    }

    const filtered = Object.entries(deps).filter(
      ([name]) => !name.startsWith(TRUSTED_SCOPE),
    );

    if (filtered.length === 0) {
      return `${header}\n(all entries are @joplin/* — filtered out)`;
    }

    const lines = filtered.map(([name, version]) => `- ${name}: ${version}`);
    return `${header}\n${lines.join("\n")}`;
  }

  /**
   * Surface the plugin's own npm scripts in the dependency summary.
   *
   * Lifecycle hooks like `postinstall`, `preinstall`, and `install`
   * are high-priority threat signals because they execute automatically
   * during `npm ci` in the CI build job.
   */
  private formatPluginScripts(
    scripts: Record<string, string> | undefined,
  ): string {
    const header = "## Plugin npm Scripts (package.json)";
    if (!scripts || Object.keys(scripts).length === 0) {
      return `${header}\n(none)`;
    }

    const dangerousHooks = ["postinstall", "preinstall", "install"] as const;
    const lines: string[] = [];

    for (const [name, command] of Object.entries(scripts)) {
      const isDangerous = dangerousHooks.some((hook) => name === hook);
      const prefix = isDangerous ? "⚠️ " : "";
      lines.push(`- ${prefix}${name}: \`${command}\``);
    }

    return `${header}\n${lines.join("\n")}`;
  }

  /**
   * Safely parse a JSON file.  Returns `null` on any error
   * (missing file, invalid JSON, encoding issues).
   */
  private readJsonSafe<T>(filePath: string): T | null {
    try {
      const raw = fs.readFileSync(filePath, "utf-8");
      return JSON.parse(raw) as T;
    } catch {
      return null;
    }
  }
}
