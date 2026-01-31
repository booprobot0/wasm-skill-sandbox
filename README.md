# WASM Component Model Sandbox MVP

A proof-of-concept demonstrating capability-based security using the WASM Component Model.

## Overview

This demo shows how a host runtime can selectively grant capabilities to WASM components:
- **component-malicious**: Attempts to read `/etc/passwd` but has NO filesystem permission → DENIED
- **component-trusted**: Reads `./demo.txt` and HAS filesystem permission → ALLOWED

## Prerequisites

1. **Rust toolchain** with wasm32-wasip1 target:
   ```bash
   rustup target add wasm32-wasip1
   ```

2. **cargo-component** for building WASM components:
   ```bash
   cargo install cargo-component
   ```

## Building

```bash
# Build the WASM components
cargo component build -p component-malicious --release
cargo component build -p component-trusted --release

# Build the host runtime
cargo build -p host --release
```

## Running the Demo

### Test the malicious component (should be DENIED):
```bash
cargo run -p host -- malicious
```

Expected output:
```
=== WASM Capability-Based Security Demo ===
Loading component: malicious

[DENIED] Component 'malicious' attempted filesystem.read-file("/etc/passwd") without permission

=== Component Result ===
BLOCKED: Failed to read /etc/passwd - Permission denied: component 'malicious' does not have filesystem capability
```

### Test the trusted component (should SUCCEED):
```bash
cargo run -p host -- trusted
```

Expected output:
```
=== WASM Capability-Based Security Demo ===
Loading component: trusted

[ALLOWED] Component 'trusted' read file './demo.txt' successfully

=== Component Result ===
SUCCESS: Read demo.txt content:
Hello from the sandbox!
This file was read by a trusted WASM component.
Capability-based security is working correctly.
```

## Architecture

```
wasm-sandbox-mvp/
├── wit/skill.wit           # WIT interface definitions
├── host/                   # Host runtime with permission enforcement
├── component-malicious/    # Component with NO capabilities
└── component-trusted/      # Component with filesystem capability
```

## How It Works

1. **WIT Interface** (`skill.wit`): Defines the `filesystem` capability interface and `skill` component interface
2. **Host Runtime**: Loads components and provides capability implementations based on a permission manifest
3. **Components**: Call the `filesystem` interface - success depends on granted permissions

The key insight is that the **host controls the implementation** of imported interfaces. Components cannot bypass this - they can only use what the host provides.
