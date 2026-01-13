# Changelog

All notable changes to **promptmap** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-01-13

### Added
- **Chain Attacks** - Multi-turn conversation attacks (`promptmap chain`)
  - New `chains.py` module with `ChainAttacker` class
  - Based on academic research: [Foot In The Door](http://arxiv.org/abs/2502.19820)
  - 8 built-in attack chains:
    - `gradual_jailbreak` - Build trust over turns, then extract
    - `roleplay_escalation` - Establish roleplay context, exploit it
    - `authority_manipulation` - Impersonate authority figures
    - `hypothetical_framing` - Frame requests as hypothetical
    - `grandma_attack` - Emotional manipulation roleplay
    - `dan_evolution` - Progressive DAN persona injection
    - `context_overflow` - Overload context then inject
    - `translation_attack` - Bypass filters via translation
  - Custom chains via YAML definitions
  - Conversation history support for multi-turn context
  - Success indicator detection per turn
  - Jailbreak detection with turn identification

- **New CLI Command: `promptmap chain`**
  - `--list` - List available chain attacks
  - `--chain <name>` - Run specific chain by name
  - `--chain <file.yaml>` - Run custom chain from YAML file
  - `--all-chains` - Run all built-in chains
  - `-o, --output` - Save results to JSON
  - Full proxy support for Burp Suite

- **Example Chain YAML Files**
  - `chains/foot_in_door.yaml` - FITD technique
  - `chains/research_legitimacy.yaml` - Academic impersonation
  - `chains/developer_debug.yaml` - Developer mode exploitation

### Usage
```bash
# List available chains
promptmap chain --list

# Run all built-in chains
promptmap chain -r request.txt --all-chains

# Run specific chain
promptmap chain -r request.txt --chain gradual_jailbreak

# Run custom chain from YAML
promptmap chain -r request.txt --chain chains/custom.yaml

# With proxy and output
promptmap chain -r request.txt --chain dan_evolution --proxy http://127.0.0.1:8080 -o results.json
```

### Chain YAML Format
```yaml
name: "My Custom Chain"
description: "What this chain does"
technique: "foot_in_the_door"
success_indicators:
  - "system prompt"
  - "my instructions"
turns:
  - message: "First turn message"
    expect: accept
  - message: "Second turn (attack)"
    expect: leak
```

---

## [2.0.0] - 2026-01-13

### Added
- **Custom Payloads Support** (`--payloads` option)
  - Load external payload files: `promptmap scan -r req.txt --payloads custom.txt`
  - One payload per line format
  - Comments with `#`, empty lines ignored
  - Example file at `examples/custom_payloads.txt`

- **Response Analyzer** - Auto-detect leaked sensitive data
  - New `analyzer.py` module with `ResponseAnalyzer` class
  - Detects 25+ sensitive data types:
    - **Cloud Credentials**: AWS keys, Azure keys, GCP keys
    - **API Keys**: OpenAI, Anthropic, GitHub, Slack tokens
    - **Secrets**: Private keys, SSH keys, JWTs, Bearer tokens
    - **PII**: SSN, credit cards, emails, phone numbers
    - **Infrastructure**: Internal IPs, database URLs, file paths
    - **System Prompts**: Detects leaked instructions/context
  - Severity classification: 🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low
  - Risk scoring (0.0 - 1.0)
  - Smart false positive detection
  - Value masking for safe display

- **Enhanced Scan Results**
  - New "Sensitive Data Leaked" summary table
  - Per-finding severity breakdown
  - Masked values shown for each leaked secret
  - Risk score in scan results

- **New CLI Options**
  - `--payloads FILE` - Load custom payload file
  - `--analyze/--no-analyze` - Toggle response analysis (default: enabled)

### Changed
- Updated `ScanResult` dataclass with sensitive data fields
- Updated `ScanReport` with aggregated sensitive data stats
- Display shows leaked secrets with masked values
- Version bumped to 2.0.0

### Usage
```bash
# Scan with custom payloads
promptmap scan -r request.txt --payloads my_payloads.txt

# Disable response analysis (faster, less detail)
promptmap scan -r request.txt --no-analyze

# Full scan with proxy and custom payloads
promptmap scan -r request.txt --proxy http://127.0.0.1:8080 --payloads custom.txt
```

### Example Output
```
📊 Scan Summary
┌──────────────────────┬───────┐
│ Metric               │ Value │
├──────────────────────┼───────┤
│ Total Payloads       │ 142   │
│ Successful Injections│ 15    │
│ Blocked/Failed       │ 127   │
└──────────────────────┴───────┘

🔐 Sensitive Data Leaked
┌──────────────┬───────┐
│ Severity     │ Count │
├──────────────┼───────┤
│ 🔴 CRITICAL  │ 2     │
│ 🟠 HIGH      │ 5     │
│ 🟡 MEDIUM    │ 3     │
└──────────────┴───────┘

⚠️ Successful Injection Payloads:
• [system_prompt] System Prompt Extraction
  Confidence: 85%
  🔑 Leaked Data:
    🔴 openai_key: sk-abc1****
    🟠 email: ad****@company.com
```

---

## [1.3.0] - 2026-01-12

### Added
- **Request File Support** (`-r` option)
  - Parse raw HTTP requests captured from Burp Suite or DevTools
  - Auto-detect injection points in JSON body
  - Support for custom injection markers: `*`, `FUZZ`, `{{prompt}}`, `[INJECT]`
  - New `request_parser.py` module with `RequestParser` class
- **Proxy Support** (`--proxy` option)
  - Route all requests through Burp Suite proxy
  - Example: `promptmap scan -r request.txt --proxy http://127.0.0.1:8080`
- **Limit Option** (`-l` / `--limit`)
  - Control number of payloads: `promptmap scan -r request.txt -l 10`
- **New CLI Commands**:
  - `promptmap sample-request` - Generate template request files
  - `promptmap parse-request` - Preview parsed request without scanning

### Changed
- **Renamed tool from `pis` to `promptmap`**
- Updated banner with new ASCII art
- Author credit: Jai
- Cleaner CLI help (hidden utility commands)
- Version bumped to 1.3.0

### Usage
```bash
# Basic scan
promptmap scan -r request.txt

# Through Burp proxy
promptmap scan -r request.txt --proxy http://127.0.0.1:8080

# Limited payloads with HTML report
promptmap scan -r request.txt -l 10 -o report.html -f html
```

---

## [1.2.0] - 2026-01-12

### Added
- **Detailed HTML Reports** - Every payload now shows full input/output in HTML reports
  - Expandable cards for each payload result
  - 📤 INPUT PAYLOAD section showing exact prompt sent
  - 📥 LLM RESPONSE section showing complete response
  - Color-coded results (red=vulnerable, green=defended)
  - Filter bar: All/Vulnerable/Defended
  - Search functionality to filter payloads
  - Expand All/Collapse All button
  - Copy button for payloads and responses
  - Indicator tags showing detection triggers

### Changed
- HTML report CSS enhanced with new detail card styles
- Report generation now includes full payload_text and response_text

### Fixed
- HTML escaping for special characters in payloads/responses (XSS prevention)

---

## [1.1.0] - 2026-01-11

### Added
- **LLM-as-Judge Detection** - AI-powered vulnerability detection
  - New `judge.py` module with `LLMJudge` class
  - `HybridDetector` combining keyword + LLM-based detection
  - Category-specific judge prompts for 8 attack types
  - Configurable confidence thresholds
- **50+ New Community-Sourced Payloads**
  - 18 new `system_prompt` payloads from SecLists metadata.txt
  - 14 new `jailbreak` payloads from NVIDIA Garak DAN probes, verazuo/jailbreak_llms
  - 18 new `prompt_injection` payloads from PromptInject, HarmBench, Garak
- **Detection Mode Configuration**
  - `keyword` - Fast keyword-based detection (~70% accuracy)
  - `llm_judge` - Slow but accurate AI detection (~95% accuracy)
  - `hybrid` - Best of both: keywords first, LLM for uncertain cases

### Changed
- `scanner.py` integrated with `HybridDetector` for async evaluation
- `config.yaml` now supports detection mode and judge thresholds
- Total payloads increased from 92 to 142

### Sources Integrated
- [SecLists AI/LLM Testing](https://github.com/danielmiessler/SecLists/tree/master/Ai/LLM_Testing)
- [NVIDIA Garak](https://github.com/NVIDIA/garak) - DAN probes, TAP, PromptInject
- [verazuo/jailbreak_llms](https://github.com/verazuo/jailbreak_llms) - DAN dataset
- [jailbreakchat.com](https://www.jailbreakchat.com) - Community jailbreaks

---

## [1.0.0] - 2026-01-10

### Added
- **Initial Release** - Complete prompt injection scanner
- **Core Modules**:
  - `scanner.py` - Main async scanning engine
  - `payloads.py` - PayloadManager with 92 built-in payloads
  - `detector.py` - Keyword-based vulnerability detection
  - `reporter.py` - Multi-format report generation (JSON/HTML/CSV)
  - `cli.py` - Click-based CLI with Rich terminal UI
  - `config.yaml` - YAML configuration system

### Attack Categories (10 total)
| Category | Payloads | Description |
|----------|----------|-------------|
| `prompt_injection` | 12 | Direct instruction override |
| `jailbreak` | 12 | DAN, Developer Mode, roleplay bypass |
| `data_leakage` | 12 | Training data extraction |
| `system_prompt` | 12 | System prompt disclosure |
| `context_manipulation` | 8 | Memory/context attacks |
| `role_play` | 8 | Persona exploitation |
| `encoding` | 10 | Base64, ROT13, Unicode tricks |
| `multi_turn` | 6 | Multi-turn conversation attacks |
| `dos` | 6 | Denial of service |
| `bias` | 6 | Bias and ethics probes |

### Features
- Async HTTP client with configurable concurrency
- Rate limiting support (delay between requests)
- Retry logic for failed requests
- Environment variable interpolation in config
- JSONPath response extraction
- Success/refusal indicator pattern matching
- Beautiful terminal progress bars and tables
- OWASP LLM Top 10 coverage

### CLI Commands
```bash
python cli.py scan      # Run vulnerability scan
python cli.py test      # Test single payload
python cli.py payloads  # List/explore payloads
python cli.py init      # Initialize config
python cli.py info      # Scanner information
```

---

## [0.1.0] - 2026-01-09

### Added
- Project scaffolding and initial architecture
- Basic requirements.txt with dependencies
- Configuration file structure

---

## Roadmap

### Planned Features
- [ ] **Plugin System** - Custom payload/detector plugins
- [ ] **CI/CD Integration** - GitHub Actions, GitLab CI templates
- [ ] **Multi-Model Testing** - Compare vulnerabilities across models
- [ ] **Attack Chaining** - Multi-step attack sequences
- [ ] **PDF Report Export** - Professional PDF reports
- [ ] **API Server Mode** - REST API for integration
- [ ] **Payload Mutation** - Auto-generate payload variants
- [ ] **Defense Testing** - Test guardrail effectiveness

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Adding new payloads
- Improving detection logic
- Reporting issues
- Submitting pull requests

---

## License

MIT License - See [LICENSE](LICENSE) for details.
