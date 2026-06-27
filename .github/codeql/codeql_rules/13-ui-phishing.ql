/**
 * @name Social Engineering & UI Phishing
 * @description Spoofing internal authentication interfaces to harvest credentials.
 * @kind path-problem
 * @problem.severity error
 * @id joplin/ui-phishing
 */
import javascript
import JoplinSources
import JoplinSinks
import JoplinLinks

predicate isPhishingHtml(DataFlow::Node htmlArg) {
  exists(string s | s = htmlArg.getStringValue() |
    s.regexpMatch("(?is).*type=[\"']password[\"'].*") or
    s.regexpMatch("(?is).*(login|password|credentials|authenticate|sign in).*")
  ) or
  exists(StringLiteral str |
    htmlArg.asExpr().getAChildExpr*() = str and
    (
      str.getStringValue().regexpMatch("(?is).*type=[\"']password[\"'].*") or 
      str.getStringValue().regexpMatch("(?is).*(login|password|credentials|authenticate|sign in).*")
    )
  )
}

module UiPhishingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Dialogs path
    exists(DataFlow::CallNode openCall, DataFlow::CallNode setHtmlCall |
      openCall = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs").getAMethodCall("open") and
      setHtmlCall = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs").getAMethodCall("setHtml") and
      (
        setHtmlCall.getArgument(0).getALocalSource() = openCall.getArgument(0).getALocalSource() or
        setHtmlCall.getArgument(0).getStringValue() = openCall.getArgument(0).getStringValue()
      ) and
      isPhishingHtml(setHtmlCall.getArgument(1)) and
      source = openCall
    )
    or
    // Panels / Webview path
    exists(DataFlow::CallNode setHtmlCall |
      setHtmlCall.getCalleeName() = "setHtml" and
      (setHtmlCall.getReceiver().getALocalSource() = Joplin::panels() or setHtmlCall.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs")) and
      isPhishingHtml(setHtmlCall.getArgument(1))
    |
      exists(DataFlow::MethodCallNode onMessage |
        onMessage.getMethodName() = "onMessage" and
        onMessage.getReceiver().getALocalSource() = Joplin::panels() and
        onMessage.getArgument(0).getALocalSource() = setHtmlCall.getArgument(0).getALocalSource() and
        source = onMessage.getArgument(1).getALocalSource().(DataFlow::FunctionNode).getParameter(0)
      )
    )
  }

  predicate isSink(DataFlow::Node sink) {
    JoplinSinks::isNetworkExfiltrationSink(sink) or
    JoplinSinks::isCommandExecutionSink(sink) or
    JoplinSinks::isFileSystemDataSink(sink)
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(DataFlow::PropRead read |
      read.getBase() = node1 and
      read.getPropertyName() = "formData" and
      node2 = read
    )
  }
}

module UiPhishing = TaintTracking::Global<UiPhishingConfig>;
import UiPhishing::PathGraph

from UiPhishing::PathNode source, UiPhishing::PathNode sink
where UiPhishing::flowPath(source, sink)
select sink.getNode(), source, sink, "UI Phishing Indicator: Data submitted through a custom Joplin dialog or prompt is being transmitted to an external network. \\n**Reviewer Action:** Review the HTML of the dialog. Ensure it is not mimicking an official Joplin authentication screen or asking for external service credentials (like GitHub or Dropbox) over an untrusted connection."
