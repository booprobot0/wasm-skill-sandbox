use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use wasmtime::component::{bindgen, Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiView};

// Generate bindings for skill-component world (imports capabilities)
bindgen!({
    path: "../wit",
    world: "skill-component",
});

// Generate bindings for scanner-component world (pure computation)
mod scanner_bindings {
    wasmtime::component::bindgen!({
        path: "../wit",
        world: "scanner-component",
    });
}

#[derive(Parser)]
#[command(name = "wasm-sandbox")]
#[command(about = "WASM Component Model Sandbox with capability-based security")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a WASM skill component with specified capabilities
    Run {
        /// Path to the .wasm component file
        wasm_file: PathBuf,

        /// Grant filesystem read capability
        #[arg(long)]
        allow_fs_read: bool,

        /// Grant filesystem write capability
        #[arg(long)]
        allow_fs_write: bool,

        /// Grant network capability
        #[arg(long)]
        allow_network: bool,
    },

    /// Run a WASM scanner component (pure computation, no capabilities)
    Scan {
        /// Path to the .wasm scanner component file
        wasm_file: PathBuf,

        /// Code to scan (or use --file to read from file)
        #[arg(short, long)]
        code: Option<String>,

        /// Read code from file instead of --code argument
        #[arg(short, long)]
        file: Option<PathBuf>,
    },

    /// Run legacy demo (malicious or trusted component)
    Demo {
        /// Component to run: malicious or trusted
        component: String,
    },
}

/// Host state containing permission context for skill components
struct SkillHostState {
    component_name: String,
    has_fs_read: bool,
    has_fs_write: bool,
    has_network: bool,
    table: ResourceTable,
    wasi_ctx: WasiCtx,
}

impl SkillHostState {
    fn new(component_name: &str, fs_read: bool, fs_write: bool, network: bool) -> Self {
        // Build a minimal WASI context (no filesystem, no network - we handle those ourselves)
        let wasi_ctx = WasiCtxBuilder::new()
            .build();
        Self {
            component_name: component_name.to_string(),
            has_fs_read: fs_read,
            has_fs_write: fs_write,
            has_network: network,
            table: ResourceTable::new(),
            wasi_ctx,
        }
    }
}

impl WasiView for SkillHostState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }

    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi_ctx
    }
}

// Implement filesystem-read interface
impl sandbox::skill::filesystem_read::Host for SkillHostState {
    fn read_file(&mut self, path: String) -> Result<String, String> {
        if !self.has_fs_read {
            println!(
                "[DENIED] Component '{}' attempted filesystem-read.read-file(\"{}\") without permission",
                self.component_name, path
            );
            return Err(format!(
                "Permission denied: filesystem-read capability not granted"
            ));
        }

        match std::fs::read_to_string(&path) {
            Ok(content) => {
                println!(
                    "[ALLOWED] Component '{}' read file '{}' successfully",
                    self.component_name, path
                );
                Ok(content)
            }
            Err(e) => Err(format!("Failed to read file '{}': {}", path, e)),
        }
    }
}

// Implement filesystem-write interface
impl sandbox::skill::filesystem_write::Host for SkillHostState {
    fn write_file(&mut self, path: String, content: String) -> Result<(), String> {
        if !self.has_fs_write {
            println!(
                "[DENIED] Component '{}' attempted filesystem-write.write-file(\"{}\") without permission",
                self.component_name, path
            );
            return Err(format!(
                "Permission denied: filesystem-write capability not granted"
            ));
        }

        match std::fs::write(&path, &content) {
            Ok(()) => {
                println!(
                    "[ALLOWED] Component '{}' wrote to file '{}' successfully",
                    self.component_name, path
                );
                Ok(())
            }
            Err(e) => Err(format!("Failed to write file '{}': {}", path, e)),
        }
    }
}

// Implement network interface
impl sandbox::skill::network::Host for SkillHostState {
    fn http_get(&mut self, url: String) -> Result<String, String> {
        if !self.has_network {
            println!(
                "[DENIED] Component '{}' attempted network.http-get(\"{}\") without permission",
                self.component_name, url
            );
            return Err(format!(
                "Permission denied: network capability not granted"
            ));
        }

        println!(
            "[ALLOWED] Component '{}' making HTTP GET to '{}'",
            self.component_name, url
        );
        // Stub implementation - would use reqwest/ureq in production
        Ok(format!("HTTP GET to {} - stub response", url))
    }

    fn http_post(&mut self, url: String, body: String) -> Result<String, String> {
        if !self.has_network {
            println!(
                "[DENIED] Component '{}' attempted network.http-post(\"{}\") without permission",
                self.component_name, url
            );
            return Err(format!(
                "Permission denied: network capability not granted"
            ));
        }

        println!(
            "[ALLOWED] Component '{}' making HTTP POST to '{}' with {} bytes",
            self.component_name,
            url,
            body.len()
        );
        // Stub implementation
        Ok(format!("HTTP POST to {} - stub response", url))
    }
}

/// Host state for scanner components (no capabilities needed)
struct ScannerHostState {
    table: ResourceTable,
    wasi_ctx: WasiCtx,
}

impl ScannerHostState {
    fn new() -> Self {
        let wasi_ctx = WasiCtxBuilder::new().build();
        Self {
            table: ResourceTable::new(),
            wasi_ctx,
        }
    }
}

impl WasiView for ScannerHostState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }

    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi_ctx
    }
}

fn run_skill_component(
    wasm_path: &PathBuf,
    fs_read: bool,
    fs_write: bool,
    network: bool,
) -> Result<()> {
    let component_name = wasm_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");

    println!("=== WASM Sandbox - Running Skill Component ===");
    println!("Component: {}", wasm_path.display());
    println!("Capabilities:");
    println!("  filesystem-read:  {}", if fs_read { "GRANTED" } else { "DENIED" });
    println!("  filesystem-write: {}", if fs_write { "GRANTED" } else { "DENIED" });
    println!("  network:          {}", if network { "GRANTED" } else { "DENIED" });
    println!();

    // Create engine with component model support
    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;

    // Load the component
    let component = Component::from_file(&engine, wasm_path).map_err(|e| {
        anyhow!(
            "Failed to load component '{}': {}\nMake sure the file exists and is a valid WASM component.",
            wasm_path.display(),
            e
        )
    })?;

    // Set up the linker with host implementations
    let mut linker = Linker::new(&engine);
    wasmtime_wasi::add_to_linker_sync(&mut linker)?;
    SkillComponent::add_to_linker(&mut linker, |state: &mut SkillHostState| state)?;

    // Create store with permission-aware host state
    let state = SkillHostState::new(component_name, fs_read, fs_write, network);
    let mut store = Store::new(&engine, state);

    // Instantiate and run
    let instance = SkillComponent::instantiate(&mut store, &component, &linker)?;
    let result = instance.sandbox_skill_skill().call_run(&mut store)?;

    println!();
    println!("=== Component Result ===");
    println!("{}", result);

    Ok(())
}

fn run_scanner_component(wasm_path: &PathBuf, code: &str) -> Result<()> {
    println!("=== WASM Sandbox - Running Scanner Component ===");
    println!("Scanner: {}", wasm_path.display());
    println!("Code length: {} bytes", code.len());
    println!("Capabilities: NONE (pure computation)");
    println!();

    // Create engine with component model support
    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;

    // Load the component
    let component = Component::from_file(&engine, wasm_path).map_err(|e| {
        anyhow!(
            "Failed to load scanner component '{}': {}",
            wasm_path.display(),
            e
        )
    })?;

    // Set up the linker (WASI needed for Python runtime)
    let mut linker = Linker::new(&engine);
    wasmtime_wasi::add_to_linker_sync(&mut linker)?;

    // Create store
    let state = ScannerHostState::new();
    let mut store = Store::new(&engine, state);

    // Instantiate and run
    let instance =
        scanner_bindings::ScannerComponent::instantiate(&mut store, &component, &linker)?;
    let result = instance
        .sandbox_skill_scanner()
        .call_scan_code(&mut store, code)?;

    println!("=== Scan Result ===");
    println!("{}", result);

    Ok(())
}

fn run_legacy_demo(component_name: &str) -> Result<()> {
    let (wasm_path, fs_read, fs_write, network) = match component_name {
        "malicious" => (
            PathBuf::from("target/wasm32-wasip1/release/component_malicious.wasm"),
            false,
            false,
            false,
        ),
        "trusted" => (
            PathBuf::from("target/wasm32-wasip1/release/component_trusted.wasm"),
            true,
            true,
            false,
        ),
        _ => {
            return Err(anyhow!(
                "Unknown component: {}. Use 'malicious' or 'trusted'.",
                component_name
            ));
        }
    };

    run_skill_component(&wasm_path, fs_read, fs_write, network)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            wasm_file,
            allow_fs_read,
            allow_fs_write,
            allow_network,
        } => {
            run_skill_component(&wasm_file, allow_fs_read, allow_fs_write, allow_network)?;
        }

        Commands::Scan {
            wasm_file,
            code,
            file,
        } => {
            let code_to_scan = match (code, file) {
                (Some(c), _) => c,
                (None, Some(f)) => std::fs::read_to_string(&f)
                    .map_err(|e| anyhow!("Failed to read code file '{}': {}", f.display(), e))?,
                (None, None) => {
                    return Err(anyhow!(
                        "Must provide either --code or --file argument"
                    ));
                }
            };
            run_scanner_component(&wasm_file, &code_to_scan)?;
        }

        Commands::Demo { component } => {
            run_legacy_demo(&component)?;
        }
    }

    Ok(())
}
