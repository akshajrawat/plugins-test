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
select importArchive, "Usage of third-party library '" + lib + "' for archive extraction. Validate source and destination paths."
