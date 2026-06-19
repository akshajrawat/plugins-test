/**
 * @name Archive Extraction Attack
 * @description Using maliciously crafted zip files to overwrite sensitive files.
 * @kind problem
 * @problem.severity warning
 * @id joplin/archive-extraction
 */
import javascript
import JoplinSources

from DataFlow::CallNode extract
where
  extract = Joplin::joplin().getAPropertyRead("fs").getAMethodCall("archiveExtract")
select extract, "Archive extraction observed. Ensure sources and destinations are validated."
