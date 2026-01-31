# WASM Component Model Sandbox

[![Build and Test](https://github.com/booprobot0/wasm-skill-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/booprobot0/wasm-skill-sandbox/actions/workflows/ci.yml)

A capability-based security sandbox using the WASM Component Model. Run untrusted code with precise control over what resources it can access.

## Features

- **Generic WASM Runner**: Run any WASM component with CLI-specified permissions
- **Capability-Based Security**: Grant/deny filesystem, network access per-component
- **Python Skill Scanner**: Detect security issues in agent skills (API key theft, obfuscated code, etc.)
- **Zero-Trust by Default**: Components get NO capabilities unless explicitly granted

## Quick Start

```bash
# Install dependencies
make install-deps

# Build everything
make all

# Run the demo
make demo
```

## Installation

### Prerequisites

1. **Rust toolchain** with wasm32-wasip1 target:
   ```bash
   rustup target add wasm32-wasip1
   ```

2. **cargo-component** for building Rust WASM components:
   ```bash
   cargo install cargo-component
   ```

3. **componentize-py** for building Python WASM components:
   ```bash
   pip install componentize-py
   ```

### Build

```bash
# Build everything (host + all components)
make all

# Or build individually:
make build-host       # Host runtime
make build-components # Rust WASM components
make build-scanner    # Python skill scanner
```

## Usage

### Generic WASM Component Runner

Run any WASM skill component with specified capabilities:

```bash
# Run with NO permissions (sandboxed - all capability requests denied)
cargo run -p host -- run ./component.wasm

# Grant filesystem read capability
cargo run -p host -- run ./component.wasm --allow-fs-read

# Grant filesystem write capability
cargo run -p host -- run ./component.wasm --allow-fs-write

# Grant network capability
cargo run -p host -- run ./component.wasm --allow-network

# Grant multiple capabilities
cargo run -p host -- run ./component.wasm --allow-fs-read --allow-fs-write --allow-network
```

**Example Output (denied):**
```
=== WASM Sandbox - Running Skill Component ===
Component: ./component.wasm
Capabilities:
  filesystem-read:  DENIED
  filesystem-write: DENIED
  network:          DENIED

[DENIED] Component 'component' attempted filesystem-read.read-file("/etc/passwd") without permission

=== Component Result ===
BLOCKED: Failed to read /etc/passwd - Permission denied: filesystem-read capability not granted
```

### Skill Scanner

Scan Python code for security issues:

```bash
# Scan a file
cargo run -p host -- scan component-skill-scanner/skill-scanner.wasm --file skill.py

# Scan inline code
cargo run -p host -- scan component-skill-scanner/skill-scanner.wasm --code 'import os; os.environ["API_KEY"]'
```

**Example Output:**
```json
{
  "findings": [
    {
      "category": "api_exfiltration",
      "severity": "high",
      "line": 1,
      "context": "import os; os.environ[\"API_KEY\"]",
      "description": "Environment variable access - potential API key exfiltration"
    }
  ],
  "safety_score": 0.75,
  "summary": "SUSPICIOUS: Found 1 issues (1 high). Categories: api exfiltration.",
  "total_findings": 1
}
```

### Legacy Demo

Run the original demo components:

```bash
# Run malicious component (denied)
cargo run -p host -- demo malicious

# Run trusted component (allowed)
cargo run -p host -- demo trusted
```

## Skill Scanner

The skill scanner detects common security issues in agent skills:

### Detection Categories

| Category | Severity | Examples |
|----------|----------|----------|
| **API Exfiltration** | Critical/High | `os.environ`, `.env` files, API key variables |
| **Suspicious Network** | Critical/High | webhook.site, pastebin, ngrok tunnels |
| **Credential Access** | Critical/High | SSH keys, AWS credentials, system passwords |
| **Obfuscated Code** | Critical/High | base64 decode + exec, eval, dynamic imports |
| **Dangerous Imports** | Medium/High | subprocess, ctypes, pickle |

### Safety Score

- **1.0**: No issues detected
- **0.8-1.0**: Minor concerns
- **0.6-0.8**: Suspicious
- **0.3-0.6**: Risky
- **0.0-0.3**: Dangerous

### Capability Requirements

The scanner component has **NO capabilities**:
- No filesystem access
- No network access
- Pure computation only

This ensures the scanner itself cannot exfiltrate the code it's analyzing.

## Architecture

```
wasm-sandbox-mvp/
├── wit/skill.wit              # WIT interface definitions
├── host/                       # Host runtime with capability enforcement
├── component-malicious/        # Demo: component with no permissions
├── component-trusted/          # Demo: component with filesystem access
├── component-skill-scanner/    # Python security scanner
└── examples/malicious-skills/  # Test cases for scanner
```

### WIT Interfaces

```wit
// Capabilities (granted by host)
interface filesystem-read {
    read-file: func(path: string) -> result<string, string>;
}

interface filesystem-write {
    write-file: func(path: string, content: string) -> result<_, string>;
}

interface network {
    http-get: func(url: string) -> result<string, string>;
    http-post: func(url: string, body: string) -> result<string, string>;
}

// Component exports
interface skill {
    run: func() -> string;
}

interface scanner {
    scan-code: func(code: string) -> string;
}
```

### Worlds

- **skill-component**: Imports capabilities, exports `skill` interface
- **scanner-component**: Pure computation, exports `scanner` interface

## For Other Agents

### Installing the Skill Scanner

```bash
# One-command install (if pre-built binary available)
curl -L https://github.com/your-org/wasm-sandbox/releases/latest/download/skill-scanner.wasm -o skill-scanner.wasm

# Or build from source
cd component-skill-scanner
componentize-py -d ../wit -w scanner-component componentize scanner -o skill-scanner.wasm
```

### Using the Scanner

```python
# Example: Integrate scanner into your agent workflow
import subprocess
import json

def scan_skill(skill_code: str) -> dict:
    """Scan skill code for security issues"""
    result = subprocess.run(
        ["wasm-sandbox", "scan", "skill-scanner.wasm", "--code", skill_code],
        capture_output=True,
        text=True
    )
    # Parse JSON from output (after the header lines)
    output_lines = result.stdout.strip().split('\n')
    json_start = next(i for i, line in enumerate(output_lines) if line.startswith('{'))
    return json.loads('\n'.join(output_lines[json_start:]))

# Check if a skill is safe
scan_result = scan_skill(untrusted_skill_code)
if scan_result["safety_score"] < 0.5:
    print(f"REJECTED: {scan_result['summary']}")
else:
    print("Skill passed security check")
```

## Security Model

1. **Zero-Trust Default**: Components get NO capabilities unless explicitly granted
2. **Host Enforcement**: All capability calls go through the host, which checks permissions
3. **Compile-Time Isolation**: WASM components cannot access anything outside their sandbox
4. **Audit Trail**: All denied operations are logged with component name and attempted action

## Development

```bash
# Build and test everything
make all
make test-scanner

# Clean build artifacts
make clean

# See all available commands
make help
```

## License

MIT
