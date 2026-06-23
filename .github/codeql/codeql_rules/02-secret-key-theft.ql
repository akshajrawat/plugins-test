/**
 * @name Secret and Key Theft
 * @description Detects sensitive settings flowing out to network, fs, child_process, or webview.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin secret-key-theft
 * @id js/joplin/secret-key-theft
 */
import javascript
import DataFlow::PathGraph
import JoplinSources
import JoplinSinks


class SecretTheftConfig extends TaintTracking::Configuration {
  SecretTheftConfig() { this = "SecretTheftConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call, Expr argExpr, string settingName |
      
      (call.getCalleeName() = "globalValue" or call.getCalleeName() = "globalValues") and
      argExpr = call.getArgument(0).asExpr() and
      (
        settingName = argExpr.getStringValue() 
        or 
        settingName = argExpr.(ArrayExpr).getAnElement().getStringValue()
      ) and
      Joplin::isSensitiveSetting(settingName) |
      source = call
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    JoplinSinks::isNetworkExfiltrationSink(sink) or
    JoplinSinks::isFileSystemPathSink(sink) or
    JoplinSinks::isFileSystemDataSink(sink) or
    JoplinSinks::isCommandExecutionSink(sink) or
    JoplinSinks::isJoplinSpecificSink(sink)
  }

}

from DataFlow::PathNode source, DataFlow::PathNode sink, SecretTheftConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Sensitive data flowing to critical sink."
