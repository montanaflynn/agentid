use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// A public agent record — safe to store and share without secret key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    /// Deterministic identifier: `urn:agent:sha256:<hex(sha256(public_key_bytes))>`
    pub id: String,
    /// Raw Ed25519 public key bytes (32 bytes).
    pub public_key: Vec<u8>,
    /// Unix timestamp (seconds) when the agent was created.
    pub created_at: u64,
}

/// An agent together with its signing (secret) key.
/// The secret key MUST NOT be serialised or exported outside of the local keystore.
#[derive(Debug)]
pub struct AgentKeypair {
    pub agent: Agent,
    /// Raw Ed25519 secret key bytes (32-byte seed).
    pub secret_key: Vec<u8>,
}

impl AgentKeypair {
    /// Generate a brand-new Ed25519 keypair and derive the agent ID from the public key.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key_bytes = signing_key.verifying_key().to_bytes().to_vec();
        let secret_key_bytes = signing_key.to_bytes().to_vec();

        let id = derive_agent_id(&public_key_bytes);
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs();

        AgentKeypair {
            agent: Agent {
                id,
                public_key: public_key_bytes,
                created_at,
            },
            secret_key: secret_key_bytes,
        }
    }

    /// Return the agent's unique identifier.
    pub fn id(&self) -> &str {
        &self.agent.id
    }
}

/// Derive the canonical agent ID from raw public key bytes.
/// Format: `urn:agent:sha256:<lower-hex(sha256(public_key_bytes))>`
pub fn derive_agent_id(public_key_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key_bytes);
    let digest = hasher.finalize();
    format!("urn:agent:sha256:{}", hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_id_is_deterministic() {
        // Same public key bytes must always produce the same agent ID.
        let public_key = vec![0u8; 32];
        let id1 = derive_agent_id(&public_key);
        let id2 = derive_agent_id(&public_key);
        assert_eq!(id1, id2);
    }

    #[test]
    fn agent_id_has_correct_prefix() {
        let public_key = vec![1u8; 32];
        let id = derive_agent_id(&public_key);
        assert!(
            id.starts_with("urn:agent:sha256:"),
            "agent ID must start with 'urn:agent:sha256:', got: {id}"
        );
    }

    #[test]
    fn agent_id_hex_is_64_chars() {
        // SHA-256 produces 32 bytes → 64 hex characters.
        let public_key = vec![42u8; 32];
        let id = derive_agent_id(&public_key);
        let hex_part = id.strip_prefix("urn:agent:sha256:").unwrap();
        assert_eq!(hex_part.len(), 64, "hex portion must be 64 characters");
    }

    #[test]
    fn generate_produces_unique_agents() {
        let kp1 = AgentKeypair::generate();
        let kp2 = AgentKeypair::generate();
        assert_ne!(kp1.id(), kp2.id(), "two generated agents must have distinct IDs");
    }

    #[test]
    fn generate_id_matches_derived_id() {
        let kp = AgentKeypair::generate();
        let expected = derive_agent_id(&kp.agent.public_key);
        assert_eq!(kp.id(), &expected);
    }
}
