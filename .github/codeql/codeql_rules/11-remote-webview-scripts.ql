/**
 * @name Remote Webview Scripts
 * @description Detects creating a webview with an external remote script or URL.
 * @kind path-problem
 * @problem.severity warning
 * @tags security joplin-plugin remote-webview
 * @id js/joplin/remote-webview
 */
import javascript
import DataFlow::PathGraph
import JoplinSources

class RemoteWebviewConfig extends TaintTracking::Configuration {
  RemoteWebviewConfig() { this = "RemoteWebviewConfig" }

  override predicate isSource(DataFlow::Node source) {
    // any string/template whose resolved value contains an external URL
    source.getStringValue().regexpMatch("(?s).*https?://(?!localhost|127\\.0\\.0\\.1).*")
    or
    // any string literal that IS an external URL (bare URL assigned to a variable)
    source.asExpr() instanceof StringLiteral and
    source.getStringValue().regexpMatch("(?i)^https?://(?!localhost|127\\.0\\.0\\.1).*")
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode call |
      (call.getMethodName() = "setHtml" and call.getReceiver().getALocalSource() = Joplin::panels()) or
      (call.getMethodName() = "setHtml" and call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs"))
    |
      sink = call.getArgument(1)
    )
  }

}

from DataFlow::PathNode source, DataFlow::PathNode sink, RemoteWebviewConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Remote external URL loaded into Webview. Requires human review."
