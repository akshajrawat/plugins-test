/**
 * @name Unsafe Archive Extraction Destination
 * @description Extracting archives to paths outside the plugin's data directory can overwrite sensitive files.
 * @kind problem
 * @problem.severity warning
 * @id joplin/archive-unsafe-destination
 */
import javascript
import JoplinSources

from DataFlow::CallNode extract, DataFlow::Node dest
where
  extract = Joplin::joplin().getAPropertyRead("fs").getAMethodCall("archiveExtract") and
  dest = extract.getArgument(1) and
  not dest.getALocalSource() = Joplin::joplin().getAPropertyRead("plugins").getAMethodCall("dataDir")
select extract, "Archive extracted to an unsafe destination. Must be restricted to joplin.plugins.dataDir()."
