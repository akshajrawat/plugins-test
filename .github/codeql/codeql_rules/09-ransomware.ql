/**
 * @name Mass Encryption / Ransomware
 * @description Detects a pattern combining reading notes, encrypting them, and overwriting the originals.
 * @kind problem
 * @problem.severity warning
 * @tags security joplin-plugin ransomware
 * @id js/joplin/ransomware
 */
import javascript
import JoplinSources

/** Checks if a call is inside any loop construct. */
predicate inAnyLoop(DataFlow::CallNode call) {
  exists(LoopStmt loop | call.asExpr().getEnclosingStmt().getParentStmt*() = loop) or
  exists(DataFlow::CallNode timer, DataFlow::FunctionNode callback |
    timer = DataFlow::globalVarRef("setInterval").getACall() and
    callback = timer.getArgument(0).getAFunctionValue() and
    call.getContainer().getEnclosingContainer*() = callback.getFunction()
  ) or
  exists(DataFlow::MethodCallNode arrayCall |
    arrayCall.getMethodName() in ["forEach", "map"] and
    call.getContainer().getEnclosingContainer*() = arrayCall.getArgument(0).getAFunctionValue().getFunction()
  )
}

/** Holds if `source` reads Joplin note data. */
predicate readsJoplinData(DataFlow::Node source) {
  exists(DataFlow::MethodCallNode call |
    call = source and
    call.getMethodName() = "get" and call.getReceiver().getALocalSource() = Joplin::data() and
    call.getArgument(0).getALocalSource().(DataFlow::ArrayCreationNode).getElement(0).getStringValue() = "notes"
  ) or
  exists(DataFlow::MethodCallNode call |
    call = source and
    call.getMethodName() = "selectedNote" and call.getReceiver().getALocalSource() = Joplin::workspace()
  )
}

/** Extracts the ID being read, if single-note read. */
predicate getReadNoteId(DataFlow::Node source, DataFlow::Node idNode) {
  exists(DataFlow::MethodCallNode call | call = source |
    call.getMethodName() = "get" and call.getReceiver().getALocalSource() = Joplin::data() and
    idNode = call.getArgument(0).getALocalSource().(DataFlow::ArrayCreationNode).getElement(1)
  ) or
  exists(DataFlow::MethodCallNode call | call = source |
    call.getMethodName() = "selectedNote" and call.getReceiver().getALocalSource() = Joplin::workspace() and
    idNode = call.getAPropertyRead("id")
  )
}

/** Holds if `call` writes Joplin note data and extracts the write ID. */
predicate writesJoplinNote(DataFlow::MethodCallNode writeCall, DataFlow::Node idNode) {
  writeCall.getMethodName() = "put" and writeCall.getReceiver().getALocalSource() = Joplin::data() and
  writeCall.getArgument(0).getALocalSource().(DataFlow::ArrayCreationNode).getElement(0).getStringValue() = "notes" and
  idNode = writeCall.getArgument(0).getALocalSource().(DataFlow::ArrayCreationNode).getElement(1)
}

predicate isCryptoEncryptionCall(DataFlow::CallNode call) {
  exists(DataFlow::MethodCallNode mc | mc = call |
    mc.getMethodName() = "update" or
    mc.getMethodName() = "final" or
    mc.getMethodName() = "encrypt"
  ) or
  call.getCalleeName() = "encrypt" or
  exists(DataFlow::MethodCallNode mc, DataFlow::CallNode cipherCreation |
    mc = call and
    mc.getMethodName() in ["update", "final"] and
    mc.getReceiver().getALocalSource() = cipherCreation and
    cipherCreation.getCalleeName() in ["createCipher", "createCipheriv"]
  )
}

module RansomwareStage1Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { readsJoplinData(source) }
  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode cryptoCall | isCryptoEncryptionCall(cryptoCall) and sink = cryptoCall.getAnArgument())
  }
}
module RansomwareStage1 = TaintTracking::Global<RansomwareStage1Config>;

module RansomwareStage2Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode cryptoCall | isCryptoEncryptionCall(cryptoCall) and source = cryptoCall)
  }
  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode writeCall | writesJoplinNote(writeCall, _) and sink = writeCall.getArgument(2))
  }
}
module RansomwareStage2 = TaintTracking::Global<RansomwareStage2Config>;

module IdCorrelationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { getReadNoteId(_, source) or readsJoplinData(source) }
  predicate isSink(DataFlow::Node sink) { writesJoplinNote(_, sink) }
}
module IdCorrelation = TaintTracking::Global<IdCorrelationConfig>;

predicate isSameNoteCorrelated(DataFlow::Node source, DataFlow::MethodCallNode writeCall) {
  exists(DataFlow::Node readId, DataFlow::Node writeId |
    getReadNoteId(source, readId) and writesJoplinNote(writeCall, writeId) and
    (readId.getStringValue() = writeId.getStringValue() or readId.getALocalSource() = writeId.getALocalSource() or IdCorrelation::flow(readId, writeId))
  ) or
  // Bulk reads where ID tracking is implicit
  source.(DataFlow::MethodCallNode).getArgument(0).getALocalSource().(DataFlow::ArrayCreationNode).getSize() = 1 or
  IdCorrelation::flow(source, _)
}

from DataFlow::Node source, DataFlow::Node cryptoArg, DataFlow::CallNode cryptoCall, DataFlow::Node sink, DataFlow::MethodCallNode writeCall, string severityMsg
where
  RansomwareStage1::flow(source, cryptoArg) and
  isCryptoEncryptionCall(cryptoCall) and
  cryptoArg = cryptoCall.getAnArgument() and
  RansomwareStage2::flow(cryptoCall, sink) and
  writesJoplinNote(writeCall, _) and
  sink = writeCall.getArgument(2) and
  isSameNoteCorrelated(source, writeCall) and
  (
    if inAnyLoop(writeCall) then
      severityMsg = " [BULK LOOP DETECTED]"
    else
      severityMsg = ""
  )
select writeCall, "Ransomware Pattern Detected" + severityMsg + ": The plugin is reading Joplin notes, passing them through an encryption cipher, and overwriting the original notes. \\n**Reviewer Action:** Unless this plugin is explicitly designed as an end-to-end encryption tool, this behavior mimics ransomware. Verify that the user holds the decryption keys locally and that this action is strictly opt-in."
