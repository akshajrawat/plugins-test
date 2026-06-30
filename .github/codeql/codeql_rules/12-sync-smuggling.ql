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
    exists(DataFlow::InvokeNode inv | inv = DataFlow::globalVarRef("Function").getAnInstantiation() and sink = inv.getAnArgument()) or
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

from CombinedFlow::PathNode source, CombinedFlow::PathNode sink, DataFlow::Node sourceNode, DataFlow::Node sinkNode, string msg
where 
  CombinedFlow::flowPath(source, sink) and
  sourceNode = source.getNode() and
  sinkNode = sink.getNode() and
  (
    exists(DataFlow::CallNode getCall, DataFlow::CallNode userDataSetCall |
      SyncSmugglingConfig::isSource(sourceNode) and
      sourceNode = getCall and
      sinkNode = userDataSetCall.getAnArgument() and
      userDataSetCall = Joplin::data().getAMethodCall("userDataSet") and
      not isSameItemCorrelated(getCall, userDataSetCall) and
      msg = "Sync Smuggling Attempt: Sensitive note, folder, or key data is being copied and hidden inside a note's invisible `userDataSet` property. \\n**Reviewer Action:** This is a stealth exfiltration technique. Verify why the plugin needs to duplicate sensitive content into hidden metadata fields that the user cannot easily inspect."
    )
    or
    (
      UserDataExecConfig::isSource(sourceNode) and
      UserDataExecConfig::isSink(sinkNode) and
      msg = "Sync Smuggling Execution: Hidden `userDataSet` content is being read out of the database and flowing directly into an execution or network sink. \\n**Reviewer Action:** This is highly dangerous. It indicates the plugin is reading payloads that were smuggled into the sync engine and executing them, serving as a stealthy Remote Code Execution (RCE) or exfiltration trigger."
    )
  )
select sinkNode, source, sink, msg
