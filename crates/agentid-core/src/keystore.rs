use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::agent::{Agent, AgentKeypair};

/// Read all agent records from `<base_dir>/agents.json`.
/// Returns an empty list if the file does not yet exist.
pub fn load_agents(base_dir: &Path) -> Result<Vec<Agent>, Box<dyn std::error::Error>> {
    let agents_file = base_dir.join("agents.json");
    if !agents_file.exists() {
        return Ok(Vec::new());
    }
    let contents = fs::read_to_string(&agents_file)?;
    let agents: Vec<Agent> = serde_json::from_str(&contents)?;
    Ok(agents)
}

/// Persist an `AgentKeypair` to the keystore under `base_dir`.
///
/// - Appends the public `Agent` record to `<base_dir>/agents.json`.
/// - Writes the raw secret-key bytes to `<base_dir>/keys/<id_hex>.key` with mode 0600.
pub fn save_agent(base_dir: &Path, keypair: &AgentKeypair) -> Result<(), Box<dyn std::error::Error>> {
    // Ensure directory structure exists.
    let keys_dir = base_dir.join("keys");
    fs::create_dir_all(&keys_dir)?;

    // --- Write secret key file (chmod 600) ---
    // Strip the "urn:agent:sha256:" prefix to get the bare hex for the filename.
    let id_hex = keypair
        .agent
        .id
        .strip_prefix("urn:agent:sha256:")
        .ok_or("agent ID does not have the expected 'urn:agent:sha256:' prefix")?;
    let key_path = keys_dir.join(format!("{id_hex}.key"));
    fs::write(&key_path, &keypair.secret_key)?;
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;

    // --- Append agent record to agents.json ---
    let agents_file = base_dir.join("agents.json");
    let mut agents = load_agents(base_dir)?;
    // Avoid duplicates: skip if the ID is already present.
    if !agents.iter().any(|a| a.id == keypair.agent.id) {
        agents.push(keypair.agent.clone());
    }
    let json = serde_json::to_string_pretty(&agents)?;
    fs::write(&agents_file, json)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::AgentKeypair;
    use tempfile::TempDir;

    fn temp_dir() -> TempDir {
        tempfile::tempdir().expect("failed to create temp dir")
    }

    #[test]
    fn load_agents_returns_empty_when_no_file() {
        let dir = temp_dir();
        let agents = load_agents(dir.path()).unwrap();
        assert!(agents.is_empty());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = temp_dir();
        let kp = AgentKeypair::generate();
        let agent_id = kp.agent.id.clone();

        save_agent(dir.path(), &kp).unwrap();

        let agents = load_agents(dir.path()).unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].id, agent_id);
    }

    #[test]
    fn secret_key_file_has_mode_600() {
        let dir = temp_dir();
        let kp = AgentKeypair::generate();
        let id_hex = kp.agent.id.strip_prefix("urn:agent:sha256:").unwrap().to_string();
        save_agent(dir.path(), &kp).unwrap();

        let key_path = dir.path().join("keys").join(format!("{id_hex}.key"));
        let meta = fs::metadata(&key_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file must be mode 0600, got {mode:o}");
    }

    #[test]
    fn secret_key_file_contents_match() {
        let dir = temp_dir();
        let kp = AgentKeypair::generate();
        let id_hex = kp.agent.id.strip_prefix("urn:agent:sha256:").unwrap().to_string();
        let expected_secret = kp.secret_key.clone();
        save_agent(dir.path(), &kp).unwrap();

        let key_path = dir.path().join("keys").join(format!("{id_hex}.key"));
        let actual = fs::read(&key_path).unwrap();
        assert_eq!(actual, expected_secret);
    }

    #[test]
    fn save_agent_is_idempotent() {
        let dir = temp_dir();
        let kp = AgentKeypair::generate();
        save_agent(dir.path(), &kp).unwrap();
        save_agent(dir.path(), &kp).unwrap();

        let agents = load_agents(dir.path()).unwrap();
        assert_eq!(agents.len(), 1, "duplicate saves must not produce duplicate records");
    }

    #[test]
    fn multiple_agents_saved_and_loaded() {
        let dir = temp_dir();
        let kp1 = AgentKeypair::generate();
        let kp2 = AgentKeypair::generate();
        save_agent(dir.path(), &kp1).unwrap();
        save_agent(dir.path(), &kp2).unwrap();

        let agents = load_agents(dir.path()).unwrap();
        assert_eq!(agents.len(), 2);
    }
}
