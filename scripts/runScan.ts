import * as path from 'path';
import { GeminiScanner } from './scanners';

/**
 * CLI entry point for the security scanner
 *
 * Requires:
 *   KEY – set as a GitHub Actions secret.
 *   LLM MODEL   – optional override
 *
 * Outputs:
 *   - scan-result.json   in the current working directory.
 */
async function main(): Promise<void> {
	const targetDir = process.argv[2];
	if (!targetDir) {
		console.error('Usage: node runScan.js <path-to-target-plugin>');
		process.exit(1);
	}

	const absoluteTarget = path.resolve(targetDir);
	console.log(`[runScan] Scanning: ${absoluteTarget}`);

	const scanner = new GeminiScanner();
	const result = await scanner.scan(absoluteTarget);

	// Persist the structured result as JSON for CI
	const outputPath = path.join(process.cwd(), 'scan-result.json');
	scanner.exportToJson(result, outputPath);
	console.log(`[runScan] JSON result saved to: ${outputPath}`);
}

main().catch((err: Error) => {
	console.error('[runScan] Fatal error:', err.message);
	process.exit(1);
});
