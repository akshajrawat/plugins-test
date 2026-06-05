import * as fs from 'fs';
import * as path from 'path';

// The three possible security verdicts a scanner can produce.
export type Verdict = 'pass' | 'fail' | 'manual_review';

// The standardised output every scanner must produce.
export interface ScanResult {
	toolName: string;
	verdict: Verdict;
	markdownReport: string;
}

/**
 * Base class for all security scanners.
 * Subclasses must implement `toolName` and `scan()`.
 * `exportToJson` is shared across all scanners.
 */
export abstract class BaseScanner {

	// name of the tool 
	abstract readonly toolName: string;

	// Run the security scan against a plugin checked out at `targetDir`.
	abstract scan(targetDir: string): Promise<ScanResult>;

	// Writes the scan result in `outhputPath` (scan-result.json.. etc) 
	public exportToJson(result: ScanResult, outputPath: string): void {
		const outputDir = path.dirname(outputPath);
		if (!fs.existsSync(outputDir)) {
			fs.mkdirSync(outputDir, { recursive: true });
		}
		fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf-8');
	}
}
