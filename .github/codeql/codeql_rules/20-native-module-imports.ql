/**
 * @name Native Module Imports
 * @description Bypassing joplin.require to gain host access.
 * @kind problem
 * @problem.severity error
 * @id joplin/native-module-imports
 */
import javascript

predicate isProductionFile(File f) {
  not f.getBaseName().regexpMatch(".*\\.(test|spec|mock)\\.(js|ts|jsx|tsx)") and
  not f.getBaseName().regexpMatch(".*config\\.(js|ts|mjs|cjs)") and
  not f.getRelativePath().regexpMatch(".*(?:^|/)(?:tests?|scripts?|tools?|build|mocks?)(?:/|$).*")
}

from DataFlow::SourceNode importNode, string moduleName, string baseName
where
  importNode = DataFlow::moduleImport(moduleName) and
  isProductionFile(importNode.getFile()) and
  baseName = moduleName.regexpReplaceAll("^node:", "") and
  baseName in ["child_process", "net", "os", "dgram", "fs", "fs-extra", "tls", "http", "https", "sqlite3", "better-sqlite3"]
select importNode, "Sandbox Bypass (Native Import): The plugin is directly requiring a core Node.js native module (like `fs`, `net`, or `child_process`) without using `joplin.require`. \\n**Reviewer Action:** Direct native imports evade Joplin's permission and wrapper systems. Instruct the developer to switch to `joplin.require('module-name')` to ensure standard security policies and hooks apply."
