/**
 * @name Sync Smuggling (Intra-API Exfiltration)
 * @description Exfiltrating sensitive user data by abusing built-in sync.
 * @kind path-problem
 * @problem.severity error
 * @id joplin/sync-smuggling
 */
import javascript
import JoplinSources
import JoplinSinks

predicate isTargetType(string type) {
  type in ["notes", "folders", "resources", "master_keys"]
}

module SyncSmugglingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode getCall, DataFlow::Node pathArg, string typeVal |
      getCall = Joplin::data().getAMethodCall("get") and
      pathArg = getCall.getArgument(0) and
      isTargetType(typeVal) and
      typeVal = pathArg.getALocalSource().(DataFlow::ArrayCreationNode).getElement(0).getStringValue() and
      source = getCall
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode userDataSetCall |
      userDataSetCall = Joplin::data().getAMethodCall("userDataSet") and
      sink = userDataSetCall.getAnArgument()
    )
  }
}

module SyncSmuggling = TaintTracking::Global<SyncSmugglingConfig>;
import SyncSmuggling::PathGraph

module IdCorrelationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode getCall | 
      getCall = Joplin::data().getAMethodCall("get") and 
      source = getCall.getArgument(0).getALocalSource().(DataFlow::ArrayCreationNode).getElement(1)
    )
  }
  predicate isSink(DataFlow::Node sink) {
    sink = Joplin::data().getAMethodCall("userDataSet").getAnArgument()
  }
}
module IdCorrelation = TaintTracking::Global<IdCorrelationConfig>;

predicate isSameItemCorrelated(DataFlow::CallNode getCall, DataFlow::CallNode userDataSetCall) {
  exists(DataFlow::Node idSource, DataFlow::Node idSink |
    idSource = getCall.getArgument(0).getALocalSource().(DataFlow::ArrayCreationNode).getElement(1) and
    idSink = userDataSetCall.getAnArgument() and
    IdCorrelation::flow(idSource, idSink)
  )
}

from SyncSmuggling::PathNode source, SyncSmuggling::PathNode sink, DataFlow::CallNode getCall, DataFlow::CallNode userDataSetCall
where 
  SyncSmuggling::flowPath(source, sink) and
  source.getNode() = getCall and
  sink.getNode() = userDataSetCall.getAnArgument() and
  userDataSetCall = Joplin::data().getAMethodCall("userDataSet") and
  not isSameItemCorrelated(getCall, userDataSetCall)
select sink.getNode(), source, sink, "Potential Sync Smuggling: Data from notes/folders/resources/keys flows into userDataSet. \n" +
  "Reviewer: verify (1) itemId differs from the item read, (2) target item isn't benign plugin cache, (3) target item isn't shared/published externally."
