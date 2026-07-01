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

predicate isPhishingHtml(DataFlow::Node htmlArg) {
  exists(string s | s = htmlArg.getStringValue() |
    s.regexpMatch("(?is).*type=[\"']password[\"'].*") or
    s.regexpMatch("(?is).*(password|token|credential|login|sign in|authenticate|dropbox|github|onedrive|webdav|sync|api key|secret).*")
  ) or
  exists(StringLiteral str |
    htmlArg.asExpr().getAChildExpr*() = str and
    (
      str.getStringValue().regexpMatch("(?is).*type=[\"']password[\"'].*") or 
      str.getStringValue().regexpMatch("(?is).*(password|token|credential|login|sign in|authenticate|dropbox|github|onedrive|webdav|sync|api key|secret).*")
    )
  )
}

predicate sameHandle(DataFlow::Node h1, DataFlow::Node h2) {
  h1.getStringValue() = h2.getStringValue() or
  h1.getALocalSource() = h2.getALocalSource() or
  h1 = h2
}

module UiPhishingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Dialogs path
    exists(DataFlow::CallNode openCall, DataFlow::CallNode setHtmlCall |
      openCall = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs").getAMethodCall("open") and
      setHtmlCall = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs").getAMethodCall("setHtml") and
      sameHandle(setHtmlCall.getArgument(0), openCall.getArgument(0)) and
      isPhishingHtml(setHtmlCall.getArgument(1)) and
      source = openCall
    )
    or
    // Panels path
    exists(DataFlow::CallNode setHtmlCall |
      setHtmlCall = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("panels").getAMethodCall("setHtml") and
      isPhishingHtml(setHtmlCall.getArgument(1))
    |
      exists(DataFlow::MethodCallNode onMessage, DataFlow::FunctionNode cb |
        onMessage = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("panels").getAMethodCall("onMessage") and
        sameHandle(onMessage.getArgument(0), setHtmlCall.getArgument(0)) and
        cb = onMessage.getArgument(1).getAFunctionValue() and
        source = cb.getParameter(0)
      )
    )
  }

  predicate isSink(DataFlow::Node sink) {
    isNetworkExfiltrationSink(sink)
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Await
    exists(AwaitExpr await |
      await.getOperand() = node1.asExpr() and
      node2.asExpr() = await
    ) or
    // .formData property
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
