// Generate bindings for the skill-component world
wit_bindgen::generate!({
    path: "../wit",
    world: "skill-component",
});

use exports::sandbox::skill::skill::Guest;

struct TrustedComponent;

impl Guest for TrustedComponent {
    fn run() -> String {
        // Read a demo file - this should be ALLOWED for trusted components
        let result = sandbox::skill::filesystem_read::read_file("./demo.txt");

        match result {
            Ok(content) => {
                format!("SUCCESS: Read demo.txt content:\n{}", content)
            }
            Err(e) => {
                format!("ERROR: Failed to read demo.txt - {}", e)
            }
        }
    }
}

export!(TrustedComponent);
