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

/**
 * Holds if `source` reads Joplin note data via joplin.data.get() or selectedNote.
 */
predicate readsJoplinData(DataFlow::Node source) {
  exists(DataFlow::MethodCallNode call |
    call.getMethodName() = "get" and
    call.getReceiver().getALocalSource() = Joplin::data()
  |
    source = call
  ) or
  exists(DataFlow::MethodCallNode call |
    call.getMethodName() = "selectedNote" and
    call.getReceiver().getALocalSource() = Joplin::workspace()
  |
    source = call
  )
}

/**
 * Holds if `call` writes Joplin note data via joplin.data.put().
 */
predicate writesJoplinData(DataFlow::MethodCallNode call) {
  call.getMethodName() = "put" and
  call.getReceiver().getALocalSource() = Joplin::data()
}

/**
 * Identifies a call that encrypts data (e.g. cipher.update, CryptoJS.AES.encrypt).
 */
predicate isCryptoEncryptionCall(DataFlow::CallNode call) {
  exists(string methodName | methodName = call.(DataFlow::MethodCallNode).getMethodName() |
    methodName in ["update", "final", "encrypt", "createCipheriv", "createCipher"]
  ) or
  call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("crypto", "createCipheriv") or
  call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("crypto", "createCipher")
}

module RansomwareStage1Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    readsJoplinData(source)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode cryptoCall |
      isCryptoEncryptionCall(cryptoCall) and
      sink = cryptoCall.getAnArgument()
    )
  }
}

module RansomwareStage1 = TaintTracking::Global<RansomwareStage1Config>;

module RansomwareStage2Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode cryptoCall |
      isCryptoEncryptionCall(cryptoCall) and
      source = cryptoCall
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode writeCall |
      writesJoplinData(writeCall) and
      sink = writeCall.getAnArgument()
    )
  }
}

module RansomwareStage2 = TaintTracking::Global<RansomwareStage2Config>;

DataFlow::Node getJoplinDataId(DataFlow::MethodCallNode call) {
  exists(DataFlow::ArrayCreationNode arr |
    arr = call.getArgument(0).getALocalSource() and
    result = arr.getElement(1)
  )
}

module IdCorrelationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    readsJoplinData(source)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode mc | sink = getJoplinDataId(mc))
  }
}

module IdCorrelation = TaintTracking::Global<IdCorrelationConfig>;

predicate isSameNoteCorrelated(DataFlow::Node source, DataFlow::MethodCallNode writeCall) {
  // Case 1: The ID used in the write call is derived from the data we just read (e.g. `note.id`)
  IdCorrelation::flow(source, getJoplinDataId(writeCall))
  or
  // Case 2: The read call and the write call use the exact same ID (e.g. a local variable or identical literal)
  exists(DataFlow::MethodCallNode getCall, DataFlow::Node readId, DataFlow::Node writeId |
    source = getCall and
    getCall.getMethodName() = "get" and
    readId = getJoplinDataId(getCall) and
    writeId = getJoplinDataId(writeCall) and
    (
      readId.getStringValue() = writeId.getStringValue() or
      readId.getALocalSource() = writeId.getALocalSource()
    )
  )
}

from DataFlow::Node source, DataFlow::Node cryptoArg, DataFlow::CallNode cryptoCall, DataFlow::Node sink, DataFlow::MethodCallNode writeCall
where
  RansomwareStage1::flow(source, cryptoArg) and
  isCryptoEncryptionCall(cryptoCall) and
  cryptoArg = cryptoCall.getAnArgument() and
  RansomwareStage2::flow(cryptoCall, sink) and
  writesJoplinData(writeCall) and
  sink = writeCall.getAnArgument() and
  isSameNoteCorrelated(source, writeCall)
select writeCall, "Ransomware Pattern Detected: The plugin is reading Joplin notes, passing them through an encryption cipher, and overwriting the original notes. \\n**Reviewer Action:** Unless this plugin is explicitly designed as an end-to-end encryption tool, this behavior mimics ransomware. Verify that the user holds the decryption keys locally and that this action is strictly opt-in."
