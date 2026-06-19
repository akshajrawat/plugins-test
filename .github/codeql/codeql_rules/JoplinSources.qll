/**
 * Shared definitions for Joplin Plugin CodeQL rules.
 */
import javascript
import JoplinLinks

module Joplin {
  /** Gets a reference to the global `joplin` object or api module import. */
  DataFlow::SourceNode joplin() {
    result = DataFlow::globalVarRef("joplin") or
    result = DataFlow::moduleImport("api")
  }

  /** Gets a reference to `joplin.settings`. */
  DataFlow::SourceNode settings() {
    result = joplin().getAPropertyRead("settings")
  }

  /** Gets a reference to `joplin.data`. */
  DataFlow::SourceNode data() {
    result = joplin().getAPropertyRead("data")
  }

  /** Gets a reference to `joplin.clipboard`. */
  DataFlow::SourceNode clipboard() {
    result = joplin().getAPropertyRead("clipboard")
  }

  /** Gets a reference to `joplin.workspace`. */
  DataFlow::SourceNode workspace() {
    result = joplin().getAPropertyRead("workspace")
  }

  /** Gets a reference to `joplin.views.panels`. */
  DataFlow::SourceNode panels() {
    result = joplin().getAPropertyRead("views").getAPropertyRead("panels")
  }

  /** Gets a reference to `joplin.interop`. */
  DataFlow::SourceNode interop() {
    result = joplin().getAPropertyRead("interop")
  }

  /** Gets a call to `joplin.require`. */
  DataFlow::CallNode require(string moduleName) {
    result.getCalleeName() = "require" and
    result.getReceiver().getALocalSource() = joplin() and
    result.getArgument(0).getStringValue() = moduleName
  }

  /** Gets a call to `joplin.settings.globalValue` or `globalValues`. */
  DataFlow::CallNode settingsGlobalValue() {
    result.getReceiver().getALocalSource() = settings() and
    (result.getCalleeName() = "globalValue" or result.getCalleeName() = "globalValues")
  }
}
