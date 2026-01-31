use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::env;
use wasmtime::component::{bindgen, Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};

// Generate bindings from the WIT file
bindgen!({
    path: "../wit",
    world: "skill-component",
});

/// Permission manifest - which components have which capabilities
fn get_permissions() -> HashMap<String, Vec<String>> {
    let mut perms = HashMap::new();
    // Malicious component has NO permissions
    perms.insert("malicious".to_string(), vec![]);
    // Trusted component has filesystem permission
    perms.insert("trusted".to_string(), vec!["filesystem".to_string()]);
    perms
}

/// Host state containing permission context
struct HostState {
    component_name: String,
    has_filesystem: bool,
    #[allow(dead_code)]
    table: ResourceTable,
}

impl HostState {
    fn new(component_name: &str, permissions: &HashMap<String, Vec<String>>) -> Self {
        let caps = permissions.get(component_name).cloned().unwrap_or_default();
        Self {
            component_name: component_name.to_string(),
            has_filesystem: caps.contains(&"filesystem".to_string()),
            table: ResourceTable::new(),
        }
    }
}

// Implement the filesystem interface for our host
impl sandbox::skill::filesystem::Host for HostState {
    fn read_file(&mut self, path: String) -> Result<String, String> {
        if !self.has_filesystem {
            println!(
                "[DENIED] Component '{}' attempted filesystem.read-file(\"{}\") without permission",
                self.component_name, path
            );
            return Err(format!(
                "Permission denied: component '{}' does not have filesystem capability",
                self.component_name
            ));
        }

        // Real implementation for permitted components
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

    fn write_file(&mut self, path: String, content: String) -> Result<(), String> {
        if !self.has_filesystem {
            println!(
                "[DENIED] Component '{}' attempted filesystem.write-file(\"{}\") without permission",
                self.component_name, path
            );
            return Err(format!(
                "Permission denied: component '{}' does not have filesystem capability",
                self.component_name
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

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <malicious|trusted>", args[0]);
        eprintln!();
        eprintln!("  malicious - Run the malicious component (no filesystem permission)");
        eprintln!("  trusted   - Run the trusted component (has filesystem permission)");
        std::process::exit(1);
    }

    let component_name = &args[1];
    let wasm_path = match component_name.as_str() {
        "malicious" => "target/wasm32-wasip1/release/component_malicious.wasm",
        "trusted" => "target/wasm32-wasip1/release/component_trusted.wasm",
        _ => {
            eprintln!("Unknown component: {}. Use 'malicious' or 'trusted'.", component_name);
            std::process::exit(1);
        }
    };

    println!("=== WASM Capability-Based Security Demo ===");
    println!("Loading component: {}", component_name);
    println!();

    // Create engine with component model support
    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;

    // Load the component
    let component = Component::from_file(&engine, wasm_path)
        .map_err(|e| anyhow!("Failed to load component '{}': {}\nDid you run 'cargo component build'?", wasm_path, e))?;

    // Set up the linker with our host implementations
    let mut linker = Linker::new(&engine);
    SkillComponent::add_to_linker(&mut linker, |state: &mut HostState| state)?;

    // Create store with permission-aware host state
    let permissions = get_permissions();
    let state = HostState::new(component_name, &permissions);
    let mut store = Store::new(&engine, state);

    // Instantiate and run
    let instance = SkillComponent::instantiate(&mut store, &component, &linker)?;
    let result = instance.sandbox_skill_skill().call_run(&mut store)?;

    println!();
    println!("=== Component Result ===");
    println!("{}", result);

    Ok(())
}
