/**
 * @name Ransomware Key Exfiltration
 * @description Detects encryption key material being sent to a network endpoint.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin ransomware-key-exfil
 * @id js/joplin/ransomware-key-exfil
 */
import javascript
import JoplinSources
import JoplinSinks

predicate isWebCryptoSubtle(DataFlow::Node receiver) {
  receiver.getALocalSource() = DataFlow::globalVarRef("crypto").getAPropertyRead("subtle") or
  receiver.getALocalSource() =
    DataFlow::globalVarRef("globalThis").getAPropertyRead("crypto").getAPropertyRead("subtle") or
  receiver.getALocalSource() =
    DataFlow::globalVarRef("window").getAPropertyRead("crypto").getAPropertyRead("subtle") or
  exists(string moduleName |
    moduleName in ["crypto", "node:crypto"] and
    (
      receiver.getALocalSource() = DataFlow::moduleImport(moduleName).getAPropertyRead("subtle") or
      receiver.getALocalSource() =
        DataFlow::moduleImport(moduleName)
            .getAPropertyRead("webcrypto")
            .getAPropertyRead("subtle")
    )
  )
}

predicate isCryptoJsAlgorithm(DataFlow::Node receiver) {
  exists(string algorithmName |
    receiver.getALocalSource() =
      DataFlow::moduleImport("crypto-js").getAPropertyRead(algorithmName) or
    receiver.getALocalSource() = DataFlow::moduleImport("crypto-js/" + algorithmName)
  )
}

predicate isKeyMaterialUse(DataFlow::Node key) {
  exists(DataFlow::CallNode call |
    call.getCalleeName() in ["createCipher", "createCipheriv"] and
    key = call.getArgument(1)
  ) or
  exists(DataFlow::MethodCallNode call |
    call.getMethodName() = "encrypt" and
    (isWebCryptoSubtle(call.getReceiver()) or isCryptoJsAlgorithm(call.getReceiver())) and
    key = call.getArgument(1)
  ) or
  exists(DataFlow::MethodCallNode call |
    call.getMethodName() = "importKey" and
    isWebCryptoSubtle(call.getReceiver()) and
    key = call.getArgument(1)
  )
}

predicate isExportedKeyMaterial(DataFlow::Node key) {
  exists(DataFlow::MethodCallNode call, DataFlow::Node keyUse |
    call.getMethodName() = "exportKey" and
    isWebCryptoSubtle(call.getReceiver()) and
    isKeyMaterialUse(keyUse) and
    call.getArgument(1).getALocalSource() = keyUse.getALocalSource() and
    key = call
  )
}

predicate isKeyMaterialSource(DataFlow::Node key) {
  exists(DataFlow::Node keyUse |
    isKeyMaterialUse(keyUse) and
    (
      key = keyUse or
      key = keyUse.getALocalSource()
    )
  ) or
  isExportedKeyMaterial(key)
}

module RansomwareKeyExfilConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isKeyMaterialSource(source)
  }
  predicate isSink(DataFlow::Node sink) {
    isNetworkExfiltrationSink(sink)
  }
}
module RansomwareKeyExfil = TaintTracking::Global<RansomwareKeyExfilConfig>;
import RansomwareKeyExfil::PathGraph

from RansomwareKeyExfil::PathNode source, RansomwareKeyExfil::PathNode sink
where RansomwareKeyExfil::flowPath(source, sink)
select sink.getNode(), source, sink, "Critical Ransomware Indicator: Encryption key material is flowing to an external network endpoint."
