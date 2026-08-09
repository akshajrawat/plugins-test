/**
 * @name Sync Smuggling (Intra-API Exfiltration)
 * @description Detects suspicious cross-item storage or execution through synchronized Joplin user data.
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
      sink = userDataSetCall.getArgument(3)
    )
  }
}


module UserDataExecConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode getCall |
      getCall = Joplin::data().getAMethodCall("userDataGet") and
      source = getCall
    )
  }
  predicate isSink(DataFlow::Node sink) {
    isCommandExecutionSink(sink) or
    exists(DataFlow::CallNode call | call = DataFlow::globalVarRef("eval").getACall() and sink = call.getArgument(0)) or
    exists(DataFlow::InvokeNode inv |
      (inv = DataFlow::globalVarRef("Function").getAnInstantiation() or
       inv = DataFlow::globalVarRef("Function").getACall()) and
      sink = inv.getLastArgument()
    ) or
    exists(DataFlow::CallNode call | (call = DataFlow::globalVarRef("setTimeout").getACall() or call = DataFlow::globalVarRef("setInterval").getACall()) and sink = call.getArgument(0))
  }
}

module CombinedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    SyncSmugglingConfig::isSource(source) or UserDataExecConfig::isSource(source)
  }
  predicate isSink(DataFlow::Node sink) {
    SyncSmugglingConfig::isSink(sink) or UserDataExecConfig::isSink(sink)
  }
}
module CombinedFlow = TaintTracking::Global<CombinedConfig>;
import CombinedFlow::PathGraph


module IdCorrelationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode getCall | 
      getCall = Joplin::data().getAMethodCall("get") and 
      source = getCall.getArgument(0).getALocalSource().(DataFlow::ArrayCreationNode).getElement(1)
    )
  }
  predicate isSink(DataFlow::Node sink) {
    sink = Joplin::data().getAMethodCall("userDataSet").getArgument(1)
  }
}
module IdCorrelation = TaintTracking::Global<IdCorrelationConfig>;

predicate modelTypeMatches(string sourceType, DataFlow::Node targetType) {
  exists(DataFlow::PropRead modelTypeRead |
    modelTypeRead = targetType.getALocalSource() and
    (
      sourceType = "notes" and modelTypeRead.getPropertyName() = "Note" or
      sourceType = "folders" and modelTypeRead.getPropertyName() = "Folder" or
      sourceType = "resources" and modelTypeRead.getPropertyName() = "Resource" or
      sourceType = "master_keys" and modelTypeRead.getPropertyName() = "MasterKey"
    )
  )
}

predicate isSameItemCorrelated(DataFlow::CallNode getCall, DataFlow::CallNode userDataSetCall) {
  exists(DataFlow::Node pathArg, DataFlow::Node idSource, string sourceType |
    pathArg = getCall.getArgument(0) and
    sourceType = pathArg.getALocalSource().(DataFlow::ArrayCreationNode).getElement(0).getStringValue() and
    idSource = getCall.getArgument(0).getALocalSource().(DataFlow::ArrayCreationNode).getElement(1) and
    modelTypeMatches(sourceType, userDataSetCall.getArgument(0)) and
    IdCorrelation::flow(idSource, userDataSetCall.getArgument(1))
  )
}

from CombinedFlow::PathNode source, CombinedFlow::PathNode sink, DataFlow::Node sourceNode, DataFlow::Node sinkNode, string msg
where 
  CombinedFlow::flowPath(source, sink) and
  sourceNode = source.getNode() and
  sinkNode = sink.getNode() and
  (
    exists(DataFlow::CallNode getCall, DataFlow::CallNode userDataSetCall |
      SyncSmugglingConfig::isSource(sourceNode) and
      sourceNode = getCall and
      sinkNode = userDataSetCall.getArgument(3) and
      userDataSetCall = Joplin::data().getAMethodCall("userDataSet") and
      not isSameItemCorrelated(getCall, userDataSetCall) and
      msg = "Cross-item Sync Smuggling Indicator: Sensitive Joplin item data is being copied into another item's synchronized `userDataSet` metadata. Verify that this cross-item hidden storage is intentional and appropriate."
    )
    or
    (
      UserDataExecConfig::isSource(sourceNode) and
      UserDataExecConfig::isSink(sinkNode) and
      msg = "Sync Smuggling Execution: Hidden `userDataSet` content is being read out of the database and flowing directly into an execution sink. It indicates the plugin is reading payloads that were smuggled into the sync engine and executing them, serving as a stealthy Remote Code Execution (RCE)."
    )
  )
select sinkNode, source, sink, msg
