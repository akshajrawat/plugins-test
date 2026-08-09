/**
 * @name Data Exfiltration
 * @description Detects reading notes, folders, or resources and piping the data to network requests.
 * @kind path-problem
 * @problem.severity warning
 * @tags security joplin-plugin data-exfiltration
 * @id js/joplin/data-exfiltration
 */
import javascript
import JoplinSources
import JoplinSinks

predicate isSensitiveDataPath(DataFlow::ArrayCreationNode path) {
  path.getElement(0).mayHaveStringValue(["notes", "folders", "resources", "search"])
  or
  path.getElement(0).mayHaveStringValue("tags") and
  path.getElement(2).mayHaveStringValue("notes")
}

predicate isLoopbackRequest(ClientRequest request) {
  exists(string host |
    request.getHost().mayHaveStringValue(host) and
    host.regexpMatch("(?i)^(localhost|127\\.0\\.0\\.1|::1|\\[::1\\])$")
  )
  or
  exists(string url |
    request.getUrl().mayHaveStringValue(url) and
    url.regexpMatch("(?i)^https?://(localhost|127\\.0\\.0\\.1|\\[::1\\])(:[0-9]+)?([/?#].*)?$")
  )
}

module DataExfilConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode getCall, DataFlow::ArrayCreationNode path |
      getCall = Joplin::data().getAMethodCall("get") and
      path = getCall.getArgument(0).getALocalSource() and
      isSensitiveDataPath(path) and
      source = getCall
    )
    or
    exists(DataFlow::MethodCallNode selectedNoteCall |
      selectedNoteCall.getMethodName() = "selectedNote" and
      selectedNoteCall.getReceiver().getALocalSource() = Joplin::workspace() and
      source = selectedNoteCall
    )
  }

  predicate isSink(DataFlow::Node sink) {
    isNetworkExfiltrationSink(sink) and
    not exists(ClientRequest cr |
      (sink = cr.getADataNode() or sink = cr.getUrl()) and
      isLoopbackRequest(cr)
    )
  }
}

module DataExfil = TaintTracking::Global<DataExfilConfig>;
import DataExfil::PathGraph

from DataExfil::PathNode source, DataExfil::PathNode sink
where DataExfil::flowPath(source, sink)
select sink.getNode(), source, sink, "Data Exfiltration Warning: The plugin is reading notes, folders, or resources and sending that data to an external network endpoint. Check if the plugin is a legitimate sync/export tool. If not, this is a massive privacy breach. Verify exactly what data is being sent in the payload."
