# skillaudit rule catalog

225 regex rules. Additional built-in analyzers (Unicode smuggling, hidden content, filesystem structure, archives, binaries, SKILL.md manifest, IOCs, correlation) emit the rule ids listed in docs/DESIGN.md.


## AI-agent config / memory tampering (`agent-tampering`)

References: OWASP ASI06, OWASP AST01, ATLAS AML.T0080, ATLAS AML.T0081

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `AGENT-API-REDIRECT` | high | medium | Overrides the model API endpoint (traffic / token interception) |
| `AGENT-CONFIG-WRITE` | high | high | Writes to AI-agent config, rules or memory files |
| `AGENT-MEMORY-INSTRUCTION` | high | medium | Instructs the agent to persist instructions into memory / rules |
| `AGENT-PERMISSION-BYPASS` | high | high | Disables agent permission prompts / sandbox |
| `AGENT-SPAWN-UNSAFE` | high | medium | Spawns an agent CLI with approvals disabled |
| `AGENT-COMMAND-WRITE` | medium | medium | Creates agent slash-commands / sub-agents / skills |
| `AGENT-PERMISSION-BYPASS-DOC` | medium | medium | Mentions disabling agent permission prompts / sandbox |
| `AGENT-SCHEDULE-TASKS` | medium | medium | Schedules agent tasks / wakeups (agent-level persistence) |
| `AGENT-CONFIG-REF` | low | medium | References AI-agent config, rules or memory files |
| `AGENT-MCP-REGISTER` | low | medium | Registers MCP servers |

## Auto-executing files (`autorun`)

References: ATT&CK T1546, OWASP ASI05

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `AGENT-HOOKS-DEFINITION` | medium | high | Defines agent lifecycle hooks (auto-run commands) |

## Concealment from the user (`concealment`)

References: OWASP ASI09, OWASP LLM01

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `EXEC-PS-HIDDEN-WINDOW` | high | medium | PowerShell launched with a hidden window |
| `INJ-CONCEAL-FROM-USER` | high | high | Tells the agent to hide information from the user |
| `INJ-DONT-INSPECT` | high | medium | Discourages reviewing the bundled code |
| `INJ-IMPLEMENTATION-DETAIL` | high | medium | Hides behaviour as an 'implementation detail' / 'would upset the user' |
| `INJ-STEALTH-ACTION` | high | medium | Silent / secret action wording |
| `INJ-BAN-USER-QUESTIONS` | medium | medium | Forbids the agent from asking the user (AskUserQuestion ban) |
| `INJ-DECEPTIVE-OUTPUT` | medium | medium | Instructs the agent to report false results |
| `INJ-NO-CONFIRMATION` | medium | medium | Tells the agent to skip permission / confirmation / safety checks |

## Credential & secret access (`credential-access`)

References: ATT&CK T1552, ATT&CK T1555, OWASP ASI03, ATLAS AML.T0083

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `CRED-AGENT-TOKENS` | critical | high | Access to AI-agent auth tokens |
| `CRED-BROWSER` | critical | high | Access to browser credential / cookie stores |
| `CRED-KEYCHAIN` | critical | high | macOS Keychain dumping / password verification |
| `CRED-MESSAGING-TOKENS` | critical | high | Discord / Telegram / Slack session-token theft paths |
| `CRED-PASSWORD-MANAGERS` | critical | low | Access to password-manager vaults |
| `CRED-WINDOWS` | critical | high | Windows credential store / LSASS / SAM access |
| `CRED-CLOUD` | high | medium | Access to cloud provider credentials |
| `CRED-DEV-TOKENS` | high | medium | Access to developer token files (.npmrc, .pypirc, .netrc, git-credentials) |
| `CRED-GPG` | high | medium | Access to GPG private keys |
| `CRED-PATH-JOIN` | high | high | Builds a path into a credential directory (pathlib / path.join style) |
| `CRED-PROC-ENVIRON` | high | medium | Reads /proc/*/environ (other processes' secrets) |
| `CRED-SHADOW` | high | medium | Access to /etc/shadow or sudoers |
| `CRED-SHELL-HISTORY` | high | medium | Reads shell / REPL history files |
| `CRED-SSH` | high | medium | Access to SSH keys / config |
| `CRED-DOTENV-READ` | medium | medium | Reads .env files |
| `CRED-ENV-HARVEST` | medium | medium | Serialises / prints / ships the whole environment (API keys live here) |
| `CRED-SENSITIVE-GLOB` | medium | medium | Searches for key / certificate / vault file types |
| `CRED-KEYRING` | low | medium | OS keyring access |
| `CRED-API-KEY-ENV` | info | high | Reads AI / cloud API-key environment variables |
| `CRED-ENV-ITERATE` | info | low | Iterates over all environment variables |

## Cryptocurrency theft (`crypto-theft`)

References: ATT&CK T1005, ATT&CK T1115

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `CRED-SEED-EXFIL` | critical | medium | Seed / recovery phrase collection or transmission |
| `CRED-WALLETS` | critical | high | Access to cryptocurrency wallets / wallet extensions |
| `CRYPTO-ADDRESS-SWAP` | critical | high | Clipboard crypto-address replacement (clipper) |
| `CRYPTO-CLIPBOARD-READ` | low | medium | Reads the clipboard |

## Cryptomining (`cryptomining`)

References: ATT&CK T1496

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `MINER-INDICATORS` | critical | high | Cryptominer indicators |

## Defense evasion / anti-forensics (`defense-evasion`)

References: ATT&CK T1562, ATT&CK T1070, ATT&CK T1553.001

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `EVADE-AMSI-ETW` | critical | high | AMSI / ETW tampering |
| `EVADE-HISTORY-WIPE` | high | high | Clears or disables shell history |
| `EVADE-LOG-WIPE` | high | medium | Clears system / event logs |
| `SOC-DISABLE-SECURITY` | high | high | Disables antivirus / firewall / SIP / SELinux |
| `SOC-GATEKEEPER-BYPASS` | high | high | macOS Gatekeeper / quarantine bypass |
| `EXEC-PS-POLICY-BYPASS` | medium | medium | PowerShell execution-policy bypass |
| `EVADE-DETACHED-PROCESS` | low | medium | Launches detached / background processes |
| `EVADE-TIMESTOMP` | low | medium | Modifies file timestamps |
| `PERSIST-LIBRARY-PRELOAD` | low | medium | Library preloading (LD_PRELOAD / DYLD_INSERT_LIBRARIES) |

## Destructive actions (`destructive`)

References: ATT&CK T1485, ATT&CK T1490

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `DESTR-DISK` | critical | high | Disk wipe / filesystem format |
| `DESTR-FORK-BOMB` | critical | high | Fork bomb |
| `DESTR-INHIBIT-RECOVERY` | critical | high | Deletes shadow copies / backups (ransomware behaviour) |
| `DESTR-RM-ROOT` | critical | high | Recursive delete of root / home / everything |
| `DESTR-WINDOWS-WIPE` | critical | high | Recursive delete / format of Windows system or user folders |
| `DESTR-MASS-ENCRYPT` | high | medium | Encrypts files while walking directories (ransomware pattern) |
| `DESTR-GIT-FORCE` | medium | medium | Destructive git history operations |

## Dynamic / shell code execution (`dynamic-exec`)

References: ATT&CK T1059, OWASP ASI05

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `EXEC-LOLBIN-WMIC` | high | medium | wmic process creation |
| `EXEC-MEMORY-INJECTION` | high | medium | Executable-memory / process-injection API |
| `EXEC-PS-IEX` | high | medium | PowerShell Invoke-Expression |
| `EXEC-PS-REFLECTION` | high | medium | Reflective .NET assembly loading |
| `EXEC-PY-PTY` | high | medium | pty.spawn (interactive shell spawning) |
| `EXEC-DESERIALIZE` | medium | medium | Unsafe deserialisation (pickle/dill/joblib/shelve) |
| `EXEC-EVAL` | medium | low | Dynamic code evaluation (eval/exec) |
| `EXEC-JS-FUNCTION` | medium | low | new Function / vm.run* dynamic JavaScript |
| `EXEC-LOLBIN-PROXY` | medium | low | Signed-binary proxy execution tool (LOLBin) |
| `EXEC-PS-DLLIMPORT` | medium | medium | P/Invoke of native Windows APIs from script |
| `EXEC-PY-COMPILE` | medium | medium | Python compile() of code for exec |
| `EXEC-PY-OS-SYSTEM` | medium | medium | os.system / os.popen / os.exec* shell command |
| `EXEC-PY-SUBPROCESS-SHELL` | medium | medium | subprocess call with shell=True |
| `EXEC-PY-YAML-UNSAFE` | medium | medium | yaml.load without SafeLoader |
| `EXEC-WSH-OBJECTS` | medium | medium | Windows Script Host shell / download objects |
| `EXEC-EVAL-DOC` | low | low | eval/exec mentioned in documentation |
| `EXEC-JS-CHILD-PROCESS` | low | medium | Node child_process usage |
| `EXEC-OSASCRIPT` | low | medium | osascript command execution |
| `EXEC-PY-DYNAMIC-IMPORT` | low | medium | Dynamic import of a module name |
| `EXEC-SHELL-EVAL` | low | medium | Shell eval of a variable or substitution |
| `EXEC-PY-SUBPROCESS` | info | high | subprocess usage (runs external commands) |

## Data exfiltration (`exfiltration`)

References: ATT&CK T1041, ATT&CK T1567, OWASP LLM02, ATLAS AML.T0086

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `INJ-EXFIL-INSTRUCTION` | high | medium | Natural-language instruction to send data somewhere |
| `NET-DNS-EXFIL` | high | medium | DNS lookup built from data (DNS exfiltration) |
| `NET-MD-IMAGE-EXFIL` | high | medium | Markdown image URL with templated query (render-time exfiltration) |
| `NET-EMAIL-SEND` | medium | medium | Sends e-mail (possible exfiltration channel) |
| `NET-MAIL-BCC-INJECT` | medium | medium | Hard-coded Bcc/Cc address in mail-sending code |
| `NET-REMOTE-COPY` | medium | medium | scp/rsync/sftp/ftp transfer to a remote host |

## Financial manipulation (`financial`)

References: OWASP ASI09

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `FIN-WALLET-TRANSFER` | medium | medium | Transfers funds / signs crypto transactions |
| `FIN-AFFILIATE-STEERING` | low | medium | Steers the agent to affiliate / referral links |

## Hidden content (`hidden-content`)

References: ATT&CK T1564, OWASP LLM01

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `INJ-NONTEXT-INSTRUCTIONS` | medium | medium | Delegates instructions to an image / document / archive |

## Known malicious indicators (`known-ioc`)

References: OWASP AST01

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `PERSIST-ROGUE-MCP-DIR` | critical | medium | Known rogue MCP-server drop locations |

## Network activity (`network`)

References: ATT&CK T1071

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `NET-CURL-UPLOAD` | medium | medium | curl/wget uploading data or files |
| `NET-NETCAT` | medium | medium | netcat connection |
| `NET-PS-UPLOAD` | medium | medium | PowerShell / .NET upload |
| `NET-HTTP-POST-JS` | low | medium | JavaScript HTTP POST/PUT / sendBeacon |
| `NET-HTTP-POST-PY` | low | medium | Python HTTP POST/PUT (outbound data) |
| `NET-RAW-SOCKET` | low | medium | Raw socket / WebSocket connection |
| `NET-HTTP-CLIENT` | info | high | Outbound HTTP request |

## Obfuscated or encoded payloads (`obfuscation`)

References: ATT&CK T1027, ATT&CK T1140

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `OBF-DECODE-EXEC` | critical | high | Decode-then-execute (base64/atob/FromBase64String into exec) |
| `OBF-DECOMPRESS-EXEC` | critical | high | exec/eval of decompressed data |
| `EXEC-PS-ENCODED` | high | high | PowerShell -EncodedCommand (base64 hidden command) |
| `EXEC-PY-MARSHAL` | high | medium | marshal.loads of code objects |
| `OBF-JS-OBFUSCATOR` | high | medium | javascript-obfuscator style identifiers (_0x...) |
| `OBF-JSFUCK` | high | medium | JSFuck / symbol-only JavaScript |
| `OBF-ROT13` | high | medium | ROT13 decoding of strings |
| `OBF-CHARCODE-JS` | medium | medium | String built from char codes (String.fromCharCode) |
| `OBF-CHARCODE-PS` | medium | medium | String built from [char] casts |
| `OBF-CHARCODE-PY` | medium | medium | String built from chr() chains |
| `OBF-HEX-ESCAPES` | medium | medium | Long run of \x hex escapes |
| `OBF-IFS` | medium | medium | Shell $IFS word-splitting obfuscation |
| `OBF-PS-TICKS` | medium | medium | PowerShell backtick-obfuscated keyword |
| `OBF-SHELLCODE-ARRAY` | medium | medium | Large numeric byte array (possible shellcode) |
| `OBF-STRING-REVERSE` | medium | medium | Reversed string literal (decoded by the scanner) |
| `OBF-UNICODE-ESCAPES` | medium | medium | Long run of \u escapes |
| `OBF-BASE64-DECODE` | low | medium | Base64 decoding at runtime |
| `OBF-STRING-CONCAT` | low | medium | Keyword split into many concatenated fragments |

## Persistence mechanisms (`persistence`)

References: ATT&CK T1547, ATT&CK T1053, ATT&CK T1546.004, ATT&CK T1543

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `PERSIST-SSH-AUTHKEYS` | critical | high | Adds a key to authorized_keys (SSH backdoor) |
| `PERSIST-BROWSER-EXTENSION` | high | medium | Force-installs or side-loads browser extensions |
| `PERSIST-CRON` | high | high | Installs cron jobs |
| `PERSIST-GIT-HOOKS` | high | medium | Installs git hooks / changes core.hooksPath |
| `PERSIST-GIT-TEMPLATE` | high | high | Global git template / hooks hijack |
| `PERSIST-INTERPRETER-HOOK` | high | medium | Interpreter startup hijack (.pth, sitecustomize, NODE_OPTIONS, ld.so.preload) |
| `PERSIST-LAUNCHD` | high | medium | macOS LaunchAgent / LaunchDaemon / login item |
| `PERSIST-SCHTASKS` | high | medium | Windows scheduled task creation |
| `PERSIST-SHELL-RC-WRITE` | high | high | Writes to shell startup files (.bashrc/.zshrc/profile) |
| `PERSIST-SYSTEMD` | high | medium | Creates / enables systemd or init services |
| `PERSIST-WIN-RUNKEY` | high | high | Windows Run keys / Winlogon / startup folder |
| `PERSIST-WIN-SERVICE` | high | medium | Windows service creation |
| `PERSIST-WMI` | high | medium | WMI event subscription persistence |
| `PERSIST-SHELL-RC-REF` | low | medium | References shell startup files |

## Privilege escalation (`privilege-escalation`)

References: ATT&CK T1548, ATT&CK T1611

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `PRIV-SUDOERS` | critical | high | Modifies sudoers / grants NOPASSWD |
| `EXEC-APPLESCRIPT-ADMIN` | high | medium | AppleScript shell command with administrator privileges |
| `PRIV-CONTAINER-ESCAPE` | high | medium | Container escape / host mount primitives |
| `PRIV-SETUID` | high | medium | Sets setuid/setgid bits |
| `PRIV-UAC-BYPASS` | high | high | Windows UAC bypass technique |
| `PRIV-CAPABILITIES` | medium | medium | Grants Linux capabilities |
| `PRIV-ELEVATE` | low | medium | Requests elevation (sudo / RunAs / admin) |
| `PRIV-WORLD-WRITABLE` | low | medium | World-writable permissions (chmod 777) |

## Prompt injection / instruction override (`prompt-injection`)

References: OWASP LLM01, OWASP ASI01, ATLAS AML.T0051, ATLAS AML.T0110

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `INJ-ANTI-REFUSAL` | high | medium | Suppresses refusals / safety warnings / disclaimers |
| `INJ-CHAT-TEMPLATE-TOKENS` | high | medium | Fake chat-template / platform delimiter tokens |
| `INJ-FAKE-AUTHORITY` | high | medium | Claims pre-authorisation by the vendor / admin |
| `INJ-IGNORE-INSTRUCTIONS` | high | high | Instruction-override phrase (ignore previous instructions) |
| `INJ-REMOTE-INSTRUCTIONS` | high | medium | Loads instructions / tasks from a remote URL at runtime |
| `INJ-REVIEWER-MANIPULATION` | high | high | Text aimed at manipulating scanners / reviewers / LLM judges |
| `INJ-ROLE-HIJACK` | high | medium | Jailbreak / unrestricted-mode framing (DAN, god mode, no longer bound) |
| `INJ-TOOL-POISONING` | high | medium | Tool-poisoning pattern (before using this tool, read/pass ...) |
| `INJ-TOOL-SHADOWING` | high | medium | Instruction changes how another tool behaves (tool shadowing) |
| `INJ-COMPLIANCE-FRAMING` | medium | medium | Compliance / audit framing used to force tool use |
| `INJ-NEW-INSTRUCTIONS` | medium | medium | Announces new / hidden / real instructions |
| `INJ-PRIORITY-CLAIM` | medium | medium | Claims to override other instructions / take precedence |
| `INJ-ROLE-TAGS` | medium | medium | System / reasoning / tool-result style tags |
| `INJ-TOOL-WILL-NOT-WORK` | medium | medium | 'Otherwise the tool will not work' coercion |
| `INJ-PSEUDO-TAGS` | low | medium | Instruction-styled pseudo tags (<IMPORTANT>, <instructions>) |
| `INJ-ROLE-REASSIGN` | low | low | Re-assigns the agent's role ('you are now...', 'from now on you...') |
| `INJ-SAFETY-CLAIM` | low | medium | Unprompted claims that the content is safe |

## Reconnaissance / host profiling (`recon`)

References: ATT&CK T1082, ATT&CK T1033, ATT&CK T1016, ATT&CK T1083

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `CRED-FILE-SWEEP` | high | medium | Sweeps the home directory / filesystem for files |
| `RECON-KEYLOGGING` | high | medium | Keystroke capture |
| `NET-IP-LOOKUP` | medium | medium | Public-IP / geolocation lookup service |
| `RECON-AV-CAPTURE` | medium | low | Camera / microphone capture |
| `RECON-NETWORK-ENUM` | medium | medium | Network / directory enumeration |
| `RECON-SCREEN-CAPTURE` | medium | low | Screen capture |
| `RECON-SYSTEM-INFO` | info | high | Host / user profiling commands |

## Remote code download & execution (`remote-exec`)

References: ATT&CK T1105, ATT&CK T1059, OWASP ASI05, OWASP AST01, ATLAS AML.T0050

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `EXEC-JS-REMOTE-EXEC` | critical | high | JavaScript eval/Function of content fetched from the network |
| `EXEC-LOLBIN-MSHTA` | critical | high | mshta executing remote or inline script |
| `EXEC-LOLBIN-REGSVR32` | critical | high | regsvr32 scriptlet execution (Squiblydoo) |
| `EXEC-PIPE-TO-SHELL` | critical | high | Download piped straight into a shell/interpreter |
| `EXEC-PROCESS-SUBST` | critical | high | Shell executes a downloaded script via process substitution |
| `EXEC-PS-DOWNLOAD-IEX` | critical | high | PowerShell downloads and executes code (IEX + DownloadString/IWR) |
| `EXEC-PY-REMOTE-EXEC` | critical | high | Python exec/eval of content fetched from the network |
| `EXEC-SUBSHELL-DOWNLOAD` | critical | high | eval / -c of a command substitution that downloads code |
| `EXEC-DOWNLOAD-CHMOD` | high | high | Downloads a file and makes it executable |
| `EXEC-DOWNLOAD-EXECUTABLE` | high | medium | Downloads an executable / script / archive from a URL |
| `EXEC-LOLBIN-BITSADMIN` | high | medium | bitsadmin file transfer (LOLBin) |
| `EXEC-LOLBIN-CERTUTIL` | high | medium | certutil used to download or decode (LOLBin) |
| `EXEC-LOLBIN-MSIEXEC` | high | medium | msiexec installing a package from a URL |
| `EXEC-LOLBIN-RUNDLL32` | high | medium | rundll32 proxy execution |
| `EXEC-NET-WEBCLIENT` | medium | medium | .NET WebClient / BITS download |

## Reverse shells & remote access (`reverse-shell`)

References: ATT&CK T1219, ATT&CK T1572, ATLAS AML.T0072

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `SHELL-DEV-TCP` | critical | high | Bash /dev/tcp reverse shell |
| `SHELL-MKFIFO` | critical | high | Named-pipe reverse shell (mkfifo + nc/openssl) |
| `SHELL-NETCAT-EXEC` | critical | high | netcat with -e/-c shell |
| `SHELL-OPENSSL-TELNET` | critical | high | openssl/telnet piped to a shell |
| `SHELL-POWERSHELL` | critical | high | PowerShell TCPClient reverse shell |
| `SHELL-PYTHON` | critical | high | Python socket + dup2/pty reverse shell |
| `SHELL-SCRIPTING-LANGS` | critical | high | Perl/Ruby/PHP socket reverse shell |
| `SHELL-SOCAT` | critical | high | socat exec/system reverse shell |
| `SHELL-TUNNEL` | high | medium | Tunnels / port forwarding to the internet |
| `SHELL-REMOTE-ADMIN-TOOL` | medium | low | Remote-administration tool |

## Sandbox / analysis evasion (`sandbox-evasion`)

References: ATT&CK T1497, ATLAS AML.T0094

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `EVADE-LONG-SLEEP` | medium | medium | Long delay before acting (sandbox evasion / delayed trigger) |
| `EVADE-TIME-BOMB` | medium | medium | Date-triggered logic (time bomb) |
| `EVADE-VM-DETECTION` | medium | low | Virtual machine / debugger / analysis-tool detection |
| `EVADE-CI-AWARE` | low | medium | Behaviour depends on CI / sandbox environment variables |

## Hard-coded secrets (`secrets`)

References: ATT&CK T1552.001, OWASP LLM02

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `SECRET-ANTHROPIC` | high | medium | Anthropic API key |
| `SECRET-AWS-KEY-ID` | high | medium | AWS access key id |
| `SECRET-AWS-SECRET` | high | medium | AWS secret access key |
| `SECRET-DISCORD-BOT` | high | medium | Discord bot token |
| `SECRET-GITHUB` | high | medium | GitHub token |
| `SECRET-GITLAB` | high | medium | GitLab token |
| `SECRET-HUGGINGFACE` | high | medium | Hugging Face token |
| `SECRET-NPM` | high | medium | npm token |
| `SECRET-OPENAI` | high | medium | OpenAI API key |
| `SECRET-PRIVATE-KEY` | high | medium | Private key block |
| `SECRET-SENDGRID` | high | medium | SendGrid key |
| `SECRET-SLACK` | high | medium | Slack token |
| `SECRET-STRIPE` | high | medium | Stripe live secret key |
| `SECRET-TELEGRAM-BOT` | high | medium | Telegram bot token (common stealer C2 channel) |
| `SECRET-CONNECTION-STRING` | medium | medium | Credentials embedded in a connection string |
| `SECRET-GOOGLE-API` | medium | medium | Google API key |
| `SECRET-JWT` | medium | medium | JSON Web Token |
| `SECRET-GENERIC-ASSIGNMENT` | low | medium | Hard-coded password / token assignment |

## Social engineering of the user (`social-engineering`)

References: ATT&CK T1204, ATT&CK T1056.002, OWASP ASI09

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `SOC-ARCHIVE-PASSWORD` | critical | high | Password-protected archive delivery (AV evasion) |
| `SOC-FAKE-PASSWORD-DIALOG` | critical | high | Fake system password dialog / password verification |
| `SOC-ASK-FOR-PASSWORD` | high | medium | Asks the user for a password / seed phrase / private key |
| `SOC-FAKE-PREREQUISITE` | high | medium | Install-a-'prerequisite' from a URL lure |
| `SOC-SUDO-PASSWORD-PIPE` | high | medium | Password piped into sudo -S |
| `SOC-CLICKFIX` | medium | medium | Asks the user to paste a command into Run / Terminal (ClickFix) |
| `SOC-URGENCY-BANNER` | medium | medium | Urgent 'required before using this skill' banner |

## Dependency & supply-chain risk (`supply-chain`)

References: ATT&CK T1195, OWASP LLM03, OWASP ASI04, OWASP AST02, ATLAS AML.T0010.005

| ID | Severity | Confidence | Title |
|---|---|---|---|
| `SUPPLY-PIP-INDEX` | high | medium | pip pointed at a non-default package index |
| `SUPPLY-REGISTRY-REDIRECT` | high | medium | Redirects the npm/yarn/pip registry |
| `SUPPLY-NPM-DIRECT-URL` | medium | medium | npm/yarn/pnpm install from a URL / git / tarball |
| `SUPPLY-PIP-DIRECT-URL` | medium | medium | pip install from a URL / git / local wheel |
| `SUPPLY-REQUIREMENTS-DIRECT-URL` | medium | medium | requirements.txt dependency from a URL / git |
| `SUPPLY-BREAK-SYSTEM` | low | medium | pip --break-system-packages / sudo pip |
| `SUPPLY-RUNTIME-PACKAGE-EXEC` | low | medium | Executes a registry package at runtime (npx -y / uvx / pipx run) |
| `SUPPLY-UNPINNED-LATEST` | low | medium | Installs @latest / unpinned remote tool |
| `SUPPLY-PACKAGE-INSTALL` | info | high | Installs packages |

