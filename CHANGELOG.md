# Changelog

All notable changes to **promptmap** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
