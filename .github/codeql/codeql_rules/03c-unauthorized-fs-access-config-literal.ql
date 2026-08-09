/**
 * @name Hardcoded Config Targeting
 * @description Detects hardcoded file operations targeting sensitive paths like Joplin databases or SSH keys.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin unauthorized-fs-access
 * @id js/joplin/unauthorized-fs-access-config-literal
 */
import javascript
import JoplinSinks

predicate isSensitivePathLiteral(DataFlow::Node source) {
  exists(string value |
    value = source.getStringValue() and
    (
      value.regexpMatch("(?i)(.*[/\\\\])?\\.config[/\\\\]joplin-desktop([/\\\\].*)?") or
      value.regexpMatch("(?i)(.*[/\\\\])?\\.ssh([/\\\\].*)?") or
      value.regexpMatch("(?i)(.*[/\\\\])?(id_rsa|authorized_keys)$")
    )
  )
}

predicate isFileReadPath(DataFlow::Node path) {
  exists(DataFlow::CallNode call |
    call.getCalleeName() in [
      "readFile", "readFileSync",
      "readJSON", "readJSONSync",
      "createReadStream",
      "open", "openSync"
    ] and
    path = call.getArgument(0)
  )
}

predicate isSensitiveFileAccessPath(DataFlow::Node path) {
  isFileReadPath(path) or
  (
    isFileSystemPathSink(path) and
    not isArchiveExtractionDestinationSink(path)
  )
}

module SensitivePathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isSensitivePathLiteral(source)
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(DataFlow::CallNode call |
      (
        call = DataFlow::moduleMember("path", "join").getACall() or
        call = DataFlow::moduleMember("path", "resolve").getACall() or
        call = DataFlow::moduleMember("node:path", "join").getACall() or
        call = DataFlow::moduleMember("node:path", "resolve").getACall()
      ) and
      node1 = call.getAnArgument() and
      node2 = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    isSensitiveFileAccessPath(sink)
  }
}

module SensitivePathFlow = TaintTracking::Global<SensitivePathConfig>;
import SensitivePathFlow::PathGraph

from SensitivePathFlow::PathNode source, SensitivePathFlow::PathNode sink
where SensitivePathFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Sensitive Path Targeting: The plugin contains a hardcoded operation targeting a sensitive user configuration or credential path. This is a severe threat indicator for data theft or tampering. Verify this immediately."
