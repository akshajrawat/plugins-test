/**
 * @name Secret and Key Theft
 * @description Detects sensitive settings flowing out to network, fs, child_process, or webview.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin secret-key-theft
 * @id js/joplin/secret-key-theft
 */
import javascript

import JoplinSources
import JoplinSinks


module SecretTheftConfig implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
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

  predicate isSink(DataFlow::Node sink) {
    JoplinSinks::isNetworkExfiltrationSink(sink) or
    JoplinSinks::isFileSystemPathSink(sink) or
    JoplinSinks::isFileSystemDataSink(sink) or
    JoplinSinks::isCommandExecutionSink(sink) or
    JoplinSinks::isJoplinSpecificSink(sink)
  }

}

module SecretTheftFlow = TaintTracking::Global<SecretTheftConfig>;
import SecretTheftFlow::PathGraph

from SecretTheftFlow::PathNode source, SecretTheftFlow::PathNode sink
where SecretTheftFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Sensitive data flowing to critical sink."
