const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const CODEQL_RULES_DIR = path.resolve(__dirname, '../../.github/codeql/codeql_rules');
const TESTS_DIR = __dirname;
const DB_PATH = path.join(TESTS_DIR, 'test-db');
const RESULTS_PATH = path.join(TESTS_DIR, 'results.sarif');

const EXPECTED_RULES = [
    'js/joplin/dynamic-code-execution',
    'js/joplin/secret-key-theft',
    'js/joplin/unauthorized-fs-access',
    'js/joplin/network-backdoor',
    'js/joplin/clipboard-hijacking',
    'js/joplin/cryptojacking',
    'js/joplin/command-execution',
    'js/joplin/data-exfiltration',
    'js/joplin/ransomware',
    'js/joplin/backup-hijacking',
    'js/joplin/backup-hijacking-structural',
    'js/joplin/remote-webview',
    'js/joplin/remote-webview-structural',
    'joplin/sync-smuggling',
    'joplin/ui-phishing',
    'joplin/tag-flooding',
    'joplin/semantic-sabotage',
    'joplin/resource-exhaustion',
    'joplin/electron-main-takeover',
    'joplin/archive-extraction',
    'joplin/mass-data-destruction',
    'joplin/keylogging',
    'joplin/native-module-imports',
    'joplin/malicious-import',
    'js/joplin/secret-key-access'
];

describe('CodeQL Security Rules Validation', { timeout: 300000 }, () => {
    let foundRules = new Set<string>();

    before(() => {
        try {
            console.log('\n📦 [1/2] Compiling CodeQL Database from mock-test-data.ts...');
            if (fs.existsSync(DB_PATH)) fs.rmSync(DB_PATH, { recursive: true, force: true });
            execSync(`codeql database create "${DB_PATH}" --language=javascript --source-root="${TESTS_DIR}"`, { stdio: 'pipe' });

            console.log('🔍 [2/2] Analyzing database against custom rules (This may take a moment)...');
            execSync(`codeql database analyze "${DB_PATH}" "${CODEQL_RULES_DIR}" --format=sarif-latest --output="${RESULTS_PATH}" --threads=0`, { stdio: 'pipe' });

            console.log('\n📊 Validating results with node:test...\n');
            if (fs.existsSync(RESULTS_PATH)) {
                const sarif = JSON.parse(fs.readFileSync(RESULTS_PATH, 'utf8'));
                sarif.runs.forEach((run: any) => {
                    if (run.results) {
                        run.results.forEach((res: any) => foundRules.add(res.ruleId));
                    }
                });
            }
        } catch (error: any) {
            console.error('\n❌ CodeQL Execution Failed!');
            if (error.stdout) console.error('STDOUT:\n', error.stdout.toString());
            if (error.stderr) console.error('STDERR:\n', error.stderr.toString());
            
            console.log('\n🧹 Cleaning up test-db and results.sarif due to crash...');
            if (fs.existsSync(DB_PATH)) fs.rmSync(DB_PATH, { recursive: true, force: true });
            if (fs.existsSync(RESULTS_PATH)) fs.rmSync(RESULTS_PATH, { force: true });
            
            throw error;
        }
    });

    after(() => {
        console.log('\n🧹 Cleaning up test-db and results.sarif...');
        if (fs.existsSync(DB_PATH)) fs.rmSync(DB_PATH, { recursive: true, force: true });
        if (fs.existsSync(RESULTS_PATH)) fs.rmSync(RESULTS_PATH, { force: true });
    });

    for (const rule of EXPECTED_RULES) {
        it(`should detect malicious payload for ${rule}`, () => {
            assert.ok(foundRules.has(rule), `CodeQL completely missed the vulnerability pattern for ${rule}`);
        });
    }

    it('should not detect any false positives from the safe mock plugins', () => {
        const unexpected = Array.from(foundRules).filter(rule => !EXPECTED_RULES.includes(rule));
        assert.deepStrictEqual(unexpected, [], `Found unexpected rules (false positives): ${unexpected.join(', ')}`);
    });
});
