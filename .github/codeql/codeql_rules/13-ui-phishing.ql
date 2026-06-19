/**
 * @name Social Engineering & UI Phishing
 * @description Spoofing internal authentication interfaces to harvest credentials.
 * @kind path-problem
 * @problem.severity error
 * @id joplin/ui-phishing
 */
import javascript
import DataFlow::PathGraph
import JoplinSources

class UiPhishingConfig extends TaintTracking::Configuration {
  UiPhishingConfig() { this = "UiPhishingConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call |
      call = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs").getAMethodCall("open") and
      source = call
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode network |
      network = DataFlow::globalVarRef("fetch").getACall() or
      network = DataFlow::globalVarRef("axios").getACall() or
      network = DataFlow::moduleImport("axios").getACall()
    |
      sink = network.getArgument(0) or sink = network.getArgument(1)
    )
  }
}

from UiPhishingConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "UI Phishing: Phishing dialog data exfiltrated via network."
