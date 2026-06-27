/**
 * @name Third-Party Archive Extraction
 * @description Usage of third-party archive extraction libraries, which may lack necessary path validation.
 * @kind problem
 * @problem.severity warning
 * @id joplin/third-party-archive
 */
import javascript

from DataFlow::Node importArchive, string lib
where
  lib in ["extract-zip", "yauzl", "adm-zip", "tar"] and
  importArchive = DataFlow::moduleImport(lib)
select importArchive, "Third-Party Extractor Warning: The plugin is using an external library (like `extract-zip`, `adm-zip`, or `tar`) to unpack archives. \\n**Reviewer Action:** Third-party extractors often lack native path validation. Manually audit the extraction flow to ensure the developer has implemented robust source validation and directory traversal prevention."
