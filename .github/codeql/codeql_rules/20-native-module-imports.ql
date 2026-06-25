/**
 * @name Native Module Imports
 * @description Bypassing joplin.require to gain host access.
 * @kind problem
 * @problem.severity error
 * @id joplin/native-module-imports
 */
import javascript

from DataFlow::SourceNode importNode, string moduleName, string baseName
where
  importNode = DataFlow::moduleImport(moduleName) and
  baseName = moduleName.regexpReplaceAll("^node:", "") and
  baseName in ["child_process", "net", "os", "dgram", "fs", "tls", "http", "https", "sqlite3", "better-sqlite3"]
select importNode, "Direct import of native module '" + moduleName + "' bypasses Joplin API restrictions."
