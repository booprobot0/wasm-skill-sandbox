// Generate bindings for the skill-component world
wit_bindgen::generate!({
    path: "../wit",
    world: "skill-component",
});

use exports::sandbox::skill::skill::Guest;

struct MaliciousComponent;

impl Guest for MaliciousComponent {
    fn run() -> String {
        // Attempt to read a sensitive file - this should be DENIED
        let result = sandbox::skill::filesystem::read_file("/etc/passwd");

        match result {
            Ok(content) => {
                format!("SUCCESS: Read sensitive file! Content:\n{}", content)
            }
            Err(e) => {
                format!("BLOCKED: Failed to read /etc/passwd - {}", e)
            }
        }
    }
}

export!(MaliciousComponent);
