# WASM Sandbox MVP - Build System
# =================================

.PHONY: all clean build-host build-components build-scanner demo-malicious demo-trusted test-scanner help install-deps

# Default target
all: build-host build-components build-scanner

# =================================
# Dependencies
# =================================

install-deps:
	@echo "=== Installing Dependencies ==="
	rustup target add wasm32-wasip1
	cargo install cargo-component
	pip install componentize-py
	@echo "=== Dependencies Installed ==="

# =================================
# Build Targets
# =================================

build-host:
	@echo "=== Building Host Runtime ==="
	cargo build -p host --release
	@echo "Binary: target/release/wasm-sandbox"

build-components:
	@echo "=== Building WASM Components ==="
	cargo component build -p component-malicious --release
	cargo component build -p component-trusted --release
	@echo "Components built in target/wasm32-wasip1/release/"

build-scanner:
	@echo "=== Building Python Skill Scanner ==="
	cd component-skill-scanner && \
		componentize-py -d ../wit -w scanner-component bindings . && \
		componentize-py -d ../wit -w scanner-component componentize app -o skill-scanner.wasm
	@echo "Scanner: component-skill-scanner/skill-scanner.wasm"

# =================================
# Demo Targets
# =================================

demo-malicious: build-host build-components
	@echo ""
	@echo "=== Running Malicious Component (should be DENIED) ==="
	cargo run -p host --release -- demo malicious

demo-trusted: build-host build-components
	@echo ""
	@echo "=== Running Trusted Component (should be ALLOWED) ==="
	cargo run -p host --release -- demo trusted

demo: demo-malicious
	@echo ""
	@echo "---"
	$(MAKE) demo-trusted

# =================================
# Scanner Tests
# =================================

test-scanner: build-host build-scanner
	@echo ""
	@echo "=== Testing Scanner with Safe Skill ==="
	cargo run -p host --release -- scan \
		component-skill-scanner/skill-scanner.wasm \
		--file examples/malicious-skills/safe_skill.py
	@echo ""
	@echo "=== Testing Scanner with API Key Stealer ==="
	cargo run -p host --release -- scan \
		component-skill-scanner/skill-scanner.wasm \
		--file examples/malicious-skills/api_key_stealer.py
	@echo ""
	@echo "=== Testing Scanner with Obfuscated Payload ==="
	cargo run -p host --release -- scan \
		component-skill-scanner/skill-scanner.wasm \
		--file examples/malicious-skills/obfuscated_payload.py

# =================================
# Generic Component Runner Examples
# =================================

# Run any component with no permissions (sandbox)
run-sandboxed:
	@echo "Usage: cargo run -p host --release -- run ./path/to/component.wasm"
	@echo ""
	@echo "Example (no permissions - will be denied):"
	@echo "  cargo run -p host --release -- run target/wasm32-wasip1/release/component_malicious.wasm"

# Run with filesystem read permission
run-with-fs-read:
	@echo "Example (with filesystem read):"
	@echo "  cargo run -p host --release -- run target/wasm32-wasip1/release/component_trusted.wasm --allow-fs-read"

# =================================
# Release
# =================================

release: all
	@echo ""
	@echo "=== Release Artifacts ==="
	@echo "Host binary:           target/release/wasm-sandbox"
	@echo "Malicious component:   target/wasm32-wasip1/release/component_malicious.wasm"
	@echo "Trusted component:     target/wasm32-wasip1/release/component_trusted.wasm"
	@echo "Skill scanner:         component-skill-scanner/skill-scanner.wasm"
	@echo ""
	@echo "To create a release package:"
	@echo "  mkdir -p dist"
	@echo "  cp target/release/wasm-sandbox dist/"
	@echo "  cp component-skill-scanner/skill-scanner.wasm dist/"

# =================================
# Clean
# =================================

clean:
	cargo clean
	rm -f component-skill-scanner/skill-scanner.wasm
	rm -rf component-skill-scanner/__pycache__

# =================================
# Help
# =================================

help:
	@echo "WASM Sandbox MVP - Build System"
	@echo ""
	@echo "Build targets:"
	@echo "  make all             - Build everything"
	@echo "  make build-host      - Build host runtime"
	@echo "  make build-components- Build Rust WASM components"
	@echo "  make build-scanner   - Build Python skill scanner"
	@echo ""
	@echo "Demo targets:"
	@echo "  make demo            - Run both demo components"
	@echo "  make demo-malicious  - Run malicious component (denied)"
	@echo "  make demo-trusted    - Run trusted component (allowed)"
	@echo ""
	@echo "Scanner tests:"
	@echo "  make test-scanner    - Test scanner with example skills"
	@echo ""
	@echo "Other:"
	@echo "  make install-deps    - Install required dependencies"
	@echo "  make release         - Build release artifacts"
	@echo "  make clean           - Clean build artifacts"
	@echo "  make help            - Show this help"
	@echo ""
	@echo "Generic runner usage:"
	@echo "  cargo run -p host -- run <wasm-file> [--allow-fs-read] [--allow-fs-write] [--allow-network]"
	@echo ""
	@echo "Scanner usage:"
	@echo "  cargo run -p host -- scan <scanner.wasm> --file <code.py>"
	@echo "  cargo run -p host -- scan <scanner.wasm> --code 'import os; os.environ[\"KEY\"]'"
