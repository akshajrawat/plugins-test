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
 * Holds if `call` reads Joplin note data via joplin.data.get().
 */
predicate readsJoplinData(DataFlow::MethodCallNode call) {
  call.getMethodName() = "get" and
  call.getReceiver().getALocalSource() = Joplin::data()
}

/**
 * Holds if `call` writes Joplin note data via joplin.data.put().
 */
predicate writesJoplinData(DataFlow::MethodCallNode call) {
  call.getMethodName() = "put" and
  call.getReceiver().getALocalSource() = Joplin::data()
}

/**
 * Holds if `call` performs a cryptographic operation (encrypt/decrypt).
 */
predicate usesCrypto(DataFlow::CallNode call) {
  call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("crypto", "createCipheriv") or
  call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("crypto", "createDecipheriv") or
  call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("crypto", "createCipher") or
  call.getCalleeName() = "createCipheriv" or
  call.getCalleeName() = "createDecipheriv" or
  call.getCalleeName() = "createCipher"
}

from DataFlow::MethodCallNode writeCall, DataFlow::MethodCallNode readCall, DataFlow::CallNode cryptoCall, File f
where
  readsJoplinData(readCall) and
  writesJoplinData(writeCall) and
  usesCrypto(cryptoCall) and
  f = readCall.getFile() and
  f = writeCall.getFile() and
  f = cryptoCall.getFile()
select writeCall, "Ransomware pattern: notes read, encrypted, and overwritten here."
