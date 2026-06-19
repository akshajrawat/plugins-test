/**
 * @name Sync Smuggling (Intra-API Exfiltration)
 * @description Exfiltrating sensitive user data by abusing built-in sync.
 * @kind path-problem
 * @problem.severity error
 * @id joplin/sync-smuggling
 */
import javascript
import JoplinSources
import DataFlow::PathGraph

class SyncSmugglingConfig extends TaintTracking::Configuration {
  SyncSmugglingConfig() { this = "SyncSmugglingConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode getCall |
      getCall = Joplin::data().getAMethodCall("get") and
      (
        getCall.getArgument(0).getALocalSource().(DataFlow::ArrayCreationNode).getElement(0).getStringValue() = "notes" or
        getCall.getArgument(0).getALocalSource().(DataFlow::ArrayCreationNode).getElement(0).getStringValue() = "folders"
      ) and
      source = getCall
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode userDataSetCall |
      userDataSetCall = Joplin::data().getAMethodCall("userDataSet") and
      sink = userDataSetCall.getAnArgument()
    )
  }
}

from SyncSmugglingConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential Sync Smuggling: Data from notes/folders flows into userDataSet."
