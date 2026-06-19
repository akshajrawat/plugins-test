/**
 * ## **3. RULE 3 :**
 * **The Sources :** It flags filesystem entry points, path-resolving variables, and environment utilities that allow a plugin to determine its location or escape its sandbox: `__dirname`, `__filename`, `process.cwd()`, `app.getPath()`, `os.homedir()`, `path.resolve()`, `path.join()`, `joplin.plugins.dataDir`, and module imports for `fs` or `fs-extra`.
 * 
 * **The Sinks :** It watches file write, manipulation, and permission methods that could be used to overwrite legitimate application files, modify the plugin's own source code, or delete data: `writeFile`, `writeFileSync`, `appendFile`, `appendFileSync`, `rename`, `renameSync`, `copyFile`, `copyFileSync`, `unlink`, `unlinkSync`, `chmod`, `chmodSync`, `mkdir`, `mkdirSync`, `createWriteStream`, `rm`, `rmSync`, `rmdir`, `rmdirSync`, `truncate`, `truncateSync`, `symlink`, `symlinkSync`, `link`, `linkSync`, `remove`, `removeSync`, `move`, `moveSync`, `copy`, `copySync`, `emptyDir`, `emptyDirSync`, `outputFile`, `outputFileSync`, `write`, `writeSync`, `ftruncate`, `ftruncateSync`.
 * 
 * @name Unauthorized FS Access / Self-Modification
 * @description Detects unauthorized file system access or self-modification.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin unauthorized-fs-access
 * @id js/joplin/unauthorized-fs-access
 */
import javascript
import DataFlow::PathGraph
import JoplinSources

class FsAccessConfig extends TaintTracking::Configuration {
  FsAccessConfig() { this = "FsAccessConfig" }

  override predicate isSource(DataFlow::Node source) {
    source = DataFlow::globalVarRef("__dirname") or
    source = DataFlow::globalVarRef("__filename") or
    source = DataFlow::globalVarRef("process").getAMethodCall("cwd") or
    source = DataFlow::globalVarRef("app").getAMethodCall("getPath") or
    source = DataFlow::moduleMember("os", "homedir").getACall() or
    source = DataFlow::moduleMember("path", "resolve").getACall() or
    source = DataFlow::moduleMember("path", "join").getACall() or
    source = Joplin::joplin().getAPropertyRead("plugins").getAPropertyRead("dataDir") or
    source = Joplin::require("fs-extra") or
    source = DataFlow::moduleImport("fs") or
    source = DataFlow::moduleImport("fs-extra") or
    (source = DataFlow::globalVarRef("require").getACall() and source.(DataFlow::CallNode).getArgument(0).getStringValue() = "fs")
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call | 
      call.getCalleeName() in [
        "writeFile", "writeFileSync", "appendFile", "appendFileSync",
        "rename", "renameSync", "copyFile", "copyFileSync",
        "unlink", "unlinkSync",
        "chmod", "chmodSync",
        "mkdir", "mkdirSync",
        "createWriteStream",
        "rm", "rmSync", "rmdir", "rmdirSync",
        "truncate", "truncateSync",
        "symlink", "symlinkSync", "link", "linkSync",
        "remove", "removeSync",
        "move", "moveSync",
        "copy", "copySync",
        "emptyDir", "emptyDirSync",
        "outputFile", "outputFileSync",
        "write", "writeSync", "ftruncate", "ftruncateSync"
      ]
    |
      sink = call.getArgument(0)
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, FsAccessConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Unauthorized FS Access or Self-Modification."
