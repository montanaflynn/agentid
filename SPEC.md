# AgentID Protocol Specification

**Version:** 1.0 Draft  
**Status:** Draft  
**Created:** 2026-03-26

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119].

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Motivation](#2-motivation)
3. [Terminology](#3-terminology)
4. [Agent Identity](#4-agent-identity)
   - 4.1 [Keypair Generation](#41-keypair-generation)
   - 4.2 [Agent ID Format](#42-agent-id-format)
   - 4.3 [Key Storage](#43-key-storage)
5. [Bot Record](#5-bot-record)
   - 5.1 [Schema](#51-schema)
   - 5.2 [Field Definitions](#52-field-definitions)
   - 5.3 [Validation Rules](#53-validation-rules)
   - 5.4 [Mutations](#54-mutations)
6. [Proofs and Signatures](#6-proofs-and-signatures)
   - 6.1 [Algorithm](#61-algorithm)
   - 6.2 [Signing Procedure](#62-signing-procedure)
   - 6.3 [Verification Procedure](#63-verification-procedure)
7. [Policies](#7-policies)
   - 7.1 [Policy Object](#71-policy-object)
   - 7.2 [Policy Evaluation](#72-policy-evaluation)
8. [Attestations](#8-attestations)
   - 8.1 [Attestation Object](#81-attestation-object)
   - 8.2 [Issuing an Attestation](#82-issuing-an-attestation)
   - 8.3 [Verifying an Attestation](#83-verifying-an-attestation)
9. [Controllers and Delegation](#9-controllers-and-delegation)
   - 9.1 [Controller Relationship](#91-controller-relationship)
   - 9.2 [Delegated Operations](#92-delegated-operations)
   - 9.3 [Delegation Constraints](#93-delegation-constraints)
10. [Capability Scoping](#10-capability-scoping)
    - 10.1 [Capability Format](#101-capability-format)
    - 10.2 [Capability Matching](#102-capability-matching)
    - 10.3 [Scoped Delegation](#103-scoped-delegation)
11. [Lifecycle](#11-lifecycle)
    - 11.1 [States](#111-states)
    - 11.2 [State Transitions](#112-state-transitions)
    - 11.3 [Revocation](#113-revocation)
12. [Security Considerations](#12-security-considerations)
    - 12.1 [Private Key Confidentiality](#121-private-key-confidentiality)
    - 12.2 [Agent ID Public Nature](#122-agent-id-public-nature)
    - 12.3 [Revocation and Recovery](#123-revocation-and-recovery)
    - 12.4 [Decentralized Trust Model](#124-decentralized-trust-model)
    - 12.5 [Replay Attacks](#125-replay-attacks)
    - 12.6 [Controller Compromise](#126-controller-compromise)
    - 12.7 [Capability Escalation](#127-capability-escalation)
    - 12.8 [Clock Skew](#128-clock-skew)
13. [References](#13-references)
    - 13.1 [Normative References](#131-normative-references)
    - 13.2 [Informative References](#132-informative-references)

---

## 1. Abstract

AgentID is a decentralized identity and authorization protocol for AI agents.
It defines how agents are identified, how their capabilities are declared, how
actions are authorized, and how trust is delegated between agents.

An agent's identity is anchored to an Ed25519 keypair. The Agent ID is a
deterministic URN derived from the public key. No central registry is required
to create or verify an identity. Agents publish a signed Bot Record declaring
their operator, capabilities, and authorized controllers. Mutations to the Bot
Record are protected by cryptographic signatures. Attestations allow one agent
to make verifiable claims about another. Policies allow m-of-n threshold
requirements for sensitive operations.

---

## 2. Motivation

Existing bot and agent deployments lack a standard identity layer. This creates
four concrete problems:

**2.1 No verifiable link between a bot and its operator.**  
Any service can claim to act on behalf of any organization. There is no
cryptographic binding between a running agent process and its declared operator,
making impersonation trivial.

**2.2 No lifecycle management or revocation.**  
Once a bot token or credential is issued, there is typically no standard
mechanism to suspend or revoke it. Compromised agents remain active until
manually decommissioned out-of-band.

**2.3 No capability declarations or third-party attestations.**  
Agents cannot declare their intended scope of action in a machine-readable,
verifiable format. Third parties cannot issue signed statements attesting to an
agent's capabilities or authorization level.

**2.4 No cryptographic proof chain for authorized actions.**  
When an agent takes an action, there is no signed audit trail linking that
action to the agent's identity, its operator, and any delegation chain that
authorized the action.

AgentID addresses all four problems with a self-sovereign, cryptographically
verifiable identity model.

---

## 3. Terminology

The following terms are used throughout this specification:

| Term | Definition |
|------|------------|
| **Agent** | An autonomous software process acting on behalf of a principal. |
| **Agent ID** | A deterministic URN derived from an agent's public key. See Section 4.2. |
| **Bot Record** | The identity document for an agent. A JSON object signed by the agent or one of its controllers. See Section 5. |
| **Keypair** | An Ed25519 public/private key pair as specified in [RFC 8032]. |
| **Controller** | An agent authorized to manage another agent's keys or Bot Record. The controller relationship is declared in the subject's Bot Record. |
| **Attestation** | A signed statement one agent makes about another. A first-class object with an issuer, subject, claim, expiration, and cryptographic proof. See Section 8. |
| **Policy** | An m-of-n threshold rule governing a specific operation. Requires signatures from at least `m` of `n` named signers before the operation is accepted. See Section 7. |
| **JWS** | JSON Web Signature as defined in [RFC 7515]. |
| **JCS** | JSON Canonicalization Scheme as defined in [RFC 8785]. |
| **Compact JWS** | The serialization format `BASE64URL(header).BASE64URL(payload).BASE64URL(signature)` as defined in Section 3.1 of [RFC 7515]. |
| **Base64url** | The URL-safe base64 alphabet defined in Section 5 of [RFC 4648], without padding characters. |
| **Mutation** | Any change to a Bot Record's fields other than `proof`. Mutations MUST be accompanied by a valid proof. |

---

## 4. Agent Identity

### 4.1 Keypair Generation

An agent's identity is anchored to an Ed25519 keypair [RFC 8032]. Each agent
MUST have exactly one active keypair at a time.

#### 4.1.1 Direct Generation

Implementations MAY generate an Ed25519 keypair directly using a
cryptographically secure random number generator. The resulting 32-byte private
key scalar and 32-byte public key constitute the keypair.

#### 4.1.2 Deterministic Derivation from Mnemonic

Implementations SHOULD support deterministic keypair derivation from a BIP-39
mnemonic seed phrase [BIP-39] using the SLIP-10 key derivation scheme [SLIP-10].

The derivation procedure is:

1. Generate a BIP-39 mnemonic of at least 128 bits of entropy (12 words
   minimum; 24 words RECOMMENDED).
2. Derive the 64-byte binary seed from the mnemonic using PBKDF2-HMAC-SHA512
   with the passphrase `"mnemonic" + optional_passphrase` and 2048 iterations,
   as specified in [BIP-39].
3. Derive the SLIP-10 master key from the seed using HMAC-SHA512 with the key
   `"ed25519 seed"`.
4. Apply hardened child derivation for each path component. The derivation
   path is:

   ```
   m / agentid' / agent_index'
   ```

   Where:
   - `agentid'` is the hardened index `0x80000000` + `0x61676964` =
     `0xE1676964`. The value `0x61676964` is the ASCII encoding of the string
     `"agid"`.
   - `agent_index'` is the hardened index `0x80000000` + `N`, where `N` is a
     non-negative integer identifying the agent slot (0 for the first agent,
     1 for the second, and so on).
   - Hardened derivation uses `index + 0x80000000` (addition, not XOR).

5. The resulting 32-byte child private key is the Ed25519 secret scalar. The
   corresponding 32-byte Ed25519 public key is derived from it per [RFC 8032].

#### 4.1.3 Key History

An agent's keypair is permanent for the life of the agent. This specification
does not define a key rotation operation because the Agent ID (Section 4.2) is
bound to the original public key. Replacing the keypair would change the Agent
ID, which would constitute a new identity, not a rotation.

If an agent's private key is compromised, the RECOMMENDED response is:

1. Revoke the compromised agent (Section 11.3) using a controller key if the
   agent's own key is no longer trusted.
2. Create a new agent with a new keypair.
3. Issue attestations from the old agent (if the key is still accessible and
   not actively hostile) or from a shared controller linking the new agent to
   the same operator.

### 4.2 Agent ID Format

The Agent ID is derived deterministically from the agent's Ed25519 public key:

```
agent_id = "urn:agent:sha256:" + hex(sha256(public_key_bytes))
```

Where:
- `public_key_bytes` is the 32-byte compressed Ed25519 public key.
- `sha256` is the SHA-256 hash function [FIPS-180-4].
- `hex` produces a lowercase hexadecimal string of exactly 64 characters.

The resulting Agent ID is always 81 characters long: the 17-character prefix
`"urn:agent:sha256:"` followed by 64 hexadecimal characters.

Example:

```
urn:agent:sha256:a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2
```

Properties:
- **Deterministic**: the same public key always yields the same Agent ID.
- **Collision-resistant**: SHA-256 preimage resistance makes it computationally
  infeasible to find two public keys with the same Agent ID.
- **No registry required**: any party can compute an Agent ID from a public key
  without contacting any central authority.

### 4.3 Key Storage

#### 4.3.1 Directory Layout

Implementations MUST support a local keystore rooted at `~/.agentid/`. The
directory structure is:

```
~/.agentid/
├── agents.json          # Public agent records (no secret key material)
└── keys/
    └── {id_hex}.key     # One file per agent; contains the secret key bytes
```

Where `{id_hex}` is the 64-character hex component of the Agent ID (i.e., the
`agent_id` string with the `"urn:agent:sha256:"` prefix stripped).

#### 4.3.2 agents.json

`agents.json` MUST be a JSON array of Agent Record objects. Each object
contains only public information:

```json
[
  {
    "id": "urn:agent:sha256:a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
    "public_key": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
    "created_at": "2026-01-15T10:30:00Z"
  }
]
```

The `public_key` field MUST be the Base64url-encoded (no padding) 32-byte
Ed25519 public key bytes.

#### 4.3.3 Key Files

Each secret key file (`keys/{id_hex}.key`) MUST contain exactly the raw 32-byte
Ed25519 secret key scalar, with no encoding or framing.

Implementations MUST set file permissions to `0600` (owner read/write only) on
POSIX systems immediately after creating the file. On non-POSIX systems,
implementations MUST apply the most restrictive equivalent access controls
available.

Implementations MUST NOT write secret key material to `agents.json` or any
other file outside the `keys/` directory.

---

## 5. Bot Record

The Bot Record is the canonical identity document for an agent. It MUST be
stored and transmitted as a UTF-8 encoded JSON object.

### 5.1 Schema

```json
{
  "id": "urn:agent:sha256:a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
  "version": 1,
  "public_key": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
  "operator": {
    "name": "Acme Corp",
    "url": "https://acme.example"
  },
  "capabilities": ["read:github", "write:email", "invoke:openai"],
  "controllers": ["urn:agent:sha256:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3"],
  "status": "active",
  "created_at": "2026-01-15T10:30:00Z",
  "updated_at": "2026-01-15T10:30:00Z",
  "proof": "eyJhbGciOiJFZERTQSJ9.eyJpZCI6InVybjphZ2VudDpzaGEyNTY6YTNmMSJ9.SIGNATURE"
}
```

### 5.2 Field Definitions

| Field | Type | Requirement | Description |
|-------|------|-------------|-------------|
| `id` | string | REQUIRED | The Agent ID. MUST equal `"urn:agent:sha256:" + hex(sha256(public_key_bytes))`. |
| `version` | integer | REQUIRED | Schema version. MUST be `1` for this version of the protocol. |
| `public_key` | string | REQUIRED | Base64url-encoded (no padding) 32-byte Ed25519 public key. |
| `operator` | object | OPTIONAL | The entity operating this agent. |
| `operator.name` | string | REQUIRED if `operator` present | Human-readable name of the operator. |
| `operator.url` | string | OPTIONAL | URL of the operator's homepage or identity document. MUST be an absolute HTTPS URL if present. |
| `capabilities` | array of strings | REQUIRED | List of capability strings declared by this agent. MAY be empty (`[]`). Each string MUST match the format defined in Section 10.1. |
| `controllers` | array of strings | REQUIRED | List of Agent IDs authorized to mutate this record. MAY be empty (`[]`). Each element MUST be a valid Agent ID (Section 4.2). |
| `status` | string | REQUIRED | Lifecycle status. MUST be one of `"active"`, `"suspended"`, or `"revoked"`. |
| `created_at` | string | REQUIRED | ISO 8601 UTC timestamp of record creation. MUST end with `"Z"`. MUST NOT change after the record is created. |
| `updated_at` | string | REQUIRED | ISO 8601 UTC timestamp of the most recent mutation. MUST be greater than or equal to `created_at`. |
| `proof` | string | REQUIRED on mutated records | Compact JWS signature as produced by Section 6.2. MUST be absent from the payload before signing (per Section 6.2 step 1). |

### 5.3 Validation Rules

A verifier MUST reject a Bot Record if any of the following conditions hold:

1. The `id` field does not equal `"urn:agent:sha256:" + hex(sha256(decode_base64url(public_key)))`.
2. The `version` field is not `1`.
3. Any `controllers` entry is not a valid Agent ID per Section 4.2.
4. The `status` field is not one of `"active"`, `"suspended"`, or `"revoked"`.
5. Any `capabilities` entry does not match the format `{verb}:{resource}` per Section 10.1.
6. The `created_at` timestamp is not a valid ISO 8601 UTC timestamp.
7. The `updated_at` timestamp is not a valid ISO 8601 UTC timestamp, or is earlier than `created_at`.
8. The `proof` field is present but fails signature verification per Section 6.3.
9. The `proof` field is absent on any record that has been transmitted as a mutation (i.e., any record that differs from an already-accepted baseline).

### 5.4 Mutations

A mutation is any change to a Bot Record. The following fields MAY be mutated
after initial creation:

- `capabilities`
- `controllers`
- `operator`
- `status`
- `updated_at`

The following fields MUST NOT change after the record is created:

- `id`
- `version`
- `public_key`
- `created_at`

Every mutation MUST increment `updated_at` to the current UTC time, MUST
include a fresh `proof` field computed over the mutated record (per Section 6.2),
and MUST be signed by either the agent's own key or an authorized controller key.

---

## 6. Proofs and Signatures

All mutations to a Bot Record MUST be signed using JWS [RFC 7515] over the
JCS-canonicalized [RFC 8785] payload.

### 6.1 Algorithm

- **Signature algorithm**: EdDSA with Ed25519 curve [RFC 8037].
- **JWS `alg` header value**: `"EdDSA"`.
- **JWS serialization**: Compact Serialization (Section 3.1 of [RFC 7515]).

No other signature algorithm is valid for Bot Record proofs in this version of
the protocol.

### 6.2 Signing Procedure

To produce a `proof` value for a Bot Record mutation, the signer MUST:

1. Construct the mutated Bot Record JSON object with all updated fields. The
   `proof` field MUST be absent from this object.
2. Serialize the object to a canonical byte string using JCS [RFC 8785].
3. Construct the JWS Protected Header as the following JSON object, then
   Base64url-encode it (no padding):

   ```json
   {"alg": "EdDSA"}
   ```

4. Construct the JWS Signing Input as:

   ```
   BASE64URL(JWS Protected Header) + "." + BASE64URL(JCS-canonical payload)
   ```

5. Sign the JWS Signing Input bytes using the signer's Ed25519 private key,
   producing a 64-byte signature.
6. Encode the signature as Base64url (no padding).
7. Assemble the Compact JWS:

   ```
   BASE64URL(header) + "." + BASE64URL(payload) + "." + BASE64URL(signature)
   ```

8. Set the `proof` field of the Bot Record to this Compact JWS string.

### 6.3 Verification Procedure

To verify a Bot Record mutation, the verifier MUST execute the following steps
in order. If any step fails, the mutation MUST be rejected.

1. Extract the `proof` field from the Bot Record. If absent, REJECT.
2. Parse the Compact JWS. Split on `"."`. If the result does not have exactly
   three parts, REJECT.
3. Base64url-decode the header part. Parse as JSON. If the `alg` field is not
   `"EdDSA"`, REJECT.
4. Base64url-decode the payload part. Parse as JSON. This is the signed Bot
   Record (without the `proof` field).
5. Determine the signing key. The valid signers for a mutation are:
   a. The agent itself: use the `public_key` field in the Bot Record.
   b. A controller: use any Agent ID listed in the `controllers` array of the
      Bot Record. For each controller Agent ID, the verifier MUST retrieve the
      controller's public key from the controller's own Bot Record (obtained
      through a trusted channel or local cache) and attempt verification.
      The mutation is accepted if ANY listed controller's public key successfully
      verifies the signature.
6. Reconstruct the Bot Record object from step 4 with the `proof` field removed.
   Apply JCS canonicalization. This MUST match the Base64url-decoded payload
   from step 4 exactly. If it does not, REJECT.
7. Reconstruct the JWS Signing Input:

   ```
   BASE64URL(header) + "." + BASE64URL(JCS-canonical Bot Record)
   ```

8. Verify the Ed25519 signature (Base64url-decoded from the third JWS part)
   over the JWS Signing Input using the candidate public key from step 5. If
   verification fails for all candidate keys, REJECT.
9. Validate the Bot Record fields per Section 5.3. If any rule fails, REJECT.
10. ACCEPT the mutation.

---

## 7. Policies

A Policy is an optional m-of-n threshold rule attached to a specific operation.
When a Policy is active for an operation, the operation is only valid if at
least `threshold` of the named `signers` have each independently signed the
payload.

### 7.1 Policy Object

```json
{
  "operation": "status_change",
  "threshold": 2,
  "signers": [
    "urn:agent:sha256:a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
    "urn:agent:sha256:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
    "urn:agent:sha256:c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4"
  ]
}
```

| Field | Type | Requirement | Description |
|-------|------|-------------|-------------|
| `operation` | string | REQUIRED | The operation this policy governs. MUST be one of the values defined in Section 7.1.1. |
| `threshold` | integer | REQUIRED | Minimum number of signers required. MUST be ≥ 1 and ≤ `len(signers)`. |
| `signers` | array of strings | REQUIRED | Agent IDs of the eligible signers. MUST contain at least `threshold` entries. Each MUST be a valid Agent ID per Section 4.2. |

#### 7.1.1 Defined Operation Values

| Value | Governed Operation |
|-------|--------------------|
| `"status_change"` | Any mutation that changes the `status` field. |
| `"capability_change"` | Any mutation that changes the `capabilities` array. |
| `"controller_change"` | Any mutation that changes the `controllers` array. |

Policies are stored in the Bot Record as a `policies` array field:

```json
{
  "id": "urn:agent:sha256:a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
  "version": 1,
  "public_key": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
  "operator": {"name": "Acme Corp", "url": "https://acme.example"},
  "capabilities": ["read:github"],
  "controllers": [],
  "policies": [
    {
      "operation": "status_change",
      "threshold": 2,
      "signers": [
        "urn:agent:sha256:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
        "urn:agent:sha256:c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
        "urn:agent:sha256:d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5"
      ]
    }
  ],
  "status": "active",
  "created_at": "2026-01-15T10:30:00Z",
  "updated_at": "2026-01-15T10:30:00Z",
  "proof": "eyJhbGciOiJFZERTQSJ9.PAYLOAD.SIGNATURE"
}
```

The `policies` field is OPTIONAL. If absent, no policy constraints apply beyond
the single-signature requirement of Section 6.

### 7.2 Policy Evaluation

When a mutation is received for an operation that has an active Policy, the
verifier MUST:

1. Identify the Policy object(s) whose `operation` matches the mutation type.
2. For each matching Policy, collect the set of valid signatures provided with
   the mutation. Each signature MUST be a Compact JWS produced per Section 6.2
   by one of the `signers` listed in the Policy.
3. Verify each candidate signature against its signer's public key per Section
   6.3 (steps 2–8).
4. Count the number of distinct signers whose signatures verified successfully.
   A signer MUST NOT be counted more than once even if multiple signatures from
   that signer are present.
5. If the count is less than `threshold`, REJECT the mutation.

Multi-signature mutations MUST include a `proofs` array field (plural) in place
of the singular `proof` field, where each element is a Compact JWS from one
of the required signers:

```json
{
  "proofs": [
    "eyJhbGciOiJFZERTQSJ9.PAYLOAD.SIG_FROM_SIGNER_A",
    "eyJhbGciOiJFZERTQSJ9.PAYLOAD.SIG_FROM_SIGNER_B"
  ]
}
```

All JWS values in `proofs` MUST be over the same JCS-canonical payload (the
Bot Record without `proof` or `proofs` fields).

---

## 8. Attestations

An Attestation is a signed statement that one agent (the issuer) makes about
another agent (the subject). Attestations are first-class objects that exist
independently of Bot Records.

### 8.1 Attestation Object

```json
{
  "issuer": "urn:agent:sha256:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
  "subject": "urn:agent:sha256:a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
  "claim": "capability:write:github",
  "issued_at": "2026-01-15T10:30:00Z",
  "expires_at": "2026-07-15T10:30:00Z",
  "proof": "eyJhbGciOiJFZERTQSJ9.PAYLOAD.SIGNATURE"
}
```

| Field | Type | Requirement | Description |
|-------|------|-------------|-------------|
| `issuer` | string | REQUIRED | Agent ID of the agent making the claim. MUST be a valid Agent ID per Section 4.2. |
| `subject` | string | REQUIRED | Agent ID of the agent the claim is about. MUST be a valid Agent ID per Section 4.2. |
| `claim` | string | REQUIRED | The claim being made. MUST match one of the formats in Section 8.1.1. |
| `issued_at` | string | REQUIRED | ISO 8601 UTC timestamp when the attestation was created. MUST end with `"Z"`. |
| `expires_at` | string | OPTIONAL | ISO 8601 UTC timestamp after which the attestation MUST be treated as invalid. MUST end with `"Z"`. MUST be after `issued_at` if present. |
| `proof` | string | REQUIRED | Compact JWS produced by the issuer signing the attestation per Section 8.2. |

#### 8.1.1 Claim Format

The `claim` field MUST use one of the following formats:

| Format | Example | Meaning |
|--------|---------|---------|
| `capability:{verb}:{resource}` | `capability:write:github` | The issuer attests that the subject holds this capability. |
| `identity:{property}:{value}` | `identity:org:acme-corp` | The issuer attests a named identity property of the subject. |

Additional claim namespaces MAY be defined by extension. Unrecognized claim
namespaces SHOULD be ignored by verifiers that do not implement them.

### 8.2 Issuing an Attestation

To issue an Attestation, the issuer MUST:

1. Construct the Attestation object with all fields populated except `proof`.
2. Serialize the object to a canonical byte string using JCS [RFC 8785].
3. Sign the canonicalized bytes using the issuer's Ed25519 private key, per the
   procedure in Section 6.2 (substituting the Attestation object for the Bot
   Record).
4. Set the `proof` field to the resulting Compact JWS.

An issuer SHOULD NOT issue a `capability:` attestation for a capability it does
not itself hold in its own Bot Record's `capabilities` array, unless the issuer
is a designated controller of the subject.

### 8.3 Verifying an Attestation

To verify an Attestation, the verifier MUST:

1. Check that the `issuer` field is a valid Agent ID per Section 4.2.
2. Retrieve the issuer's Bot Record. If unavailable, verification SHOULD be
   deferred rather than the attestation accepted without verification.
3. Check that the issuer's `status` is `"active"`. If `"suspended"` or
   `"revoked"`, REJECT the attestation.
4. If `expires_at` is present and the current time is at or after `expires_at`,
   REJECT the attestation as expired.
5. Verify the `proof` signature using the issuer's public key per the procedure
   in Section 6.3 steps 2–8, substituting the Attestation object (without
   `proof`) as the payload.
6. ACCEPT the attestation.

---

## 9. Controllers and Delegation

### 9.1 Controller Relationship

A controller is an agent that is authorized to mutate another agent's Bot
Record. The controller relationship is declared by listing the controller's
Agent ID in the subject agent's `controllers` array.

For the controller relationship to be valid:

1. The subject's Bot Record MUST list the controller's Agent ID in `controllers`.
2. The subject's Bot Record MUST have a valid `proof` signed by the subject's
   own key at the time the `controllers` entry was added (i.e., an agent cannot
   be assigned a controller without its own signed authorization).

The controller's Bot Record has no requirement to reference the subject. The
relationship is unidirectional and declared by the subject.

### 9.2 Delegated Operations

A controller MAY perform the following operations on behalf of the subject:

- Add or remove entries from the subject's `capabilities` array.
- Change the subject's `status` (subject to any applicable Policy, Section 7).
- Add or remove entries from the subject's `controllers` array.
- Update the subject's `operator` field.

A controller MUST NOT change the subject's `id`, `version`, `public_key`, or
`created_at` fields.

When a controller mutates a subject's Bot Record, the `proof` in the resulting
record MUST be signed by the controller's Ed25519 private key. The verifier
identifies which key was used per Section 6.3 step 5b.

### 9.3 Delegation Constraints

Hierarchical delegation is supported. An agent with controllers can itself be
listed as a controller of another agent, creating a trust tree.

A controller MUST NOT grant a subject capabilities that the controller does not
itself hold. Specifically:

- When a controller adds a capability `C` to the subject's `capabilities`, the
  controller's own Bot Record MUST include capability `C` or a wildcard that
  covers `C` per Section 10.2. If this condition is not met, verifiers MUST
  reject the mutation.

A controller that is itself controlled (i.e., has its own `controllers` list)
operates under the same constraints relative to its own controllers.

Circular controller relationships (where A controls B and B controls A) are
permitted but do not amplify authority — each agent may only grant what it
holds.

---

## 10. Capability Scoping

### 10.1 Capability Format

A capability is a string with the following structure:

```
capability = verb ":" resource
verb       = 1*ALPHA
resource   = 1*(ALPHA / DIGIT / "-" / "_" / ".")
```

Examples:
- `read:github` — read access to GitHub
- `write:email` — write/send access to email
- `invoke:openai` — permission to call the OpenAI API
- `admin:agentid` — administrative access to the AgentID keystore

The verb and resource components are case-sensitive. Implementations MUST
treat `Read:Github` and `read:github` as different capabilities.

A special wildcard capability `admin:{resource}` SHOULD be interpreted as
encompassing all `{verb}:{resource}` capabilities for the given resource, but
only if the implementation explicitly declares wildcard support. Verifiers that
do not support wildcards MUST treat `admin:github` as a distinct capability,
not as a superset.

### 10.2 Capability Matching

Exact string matching MUST be used unless the implementation supports
wildcards. Two capability strings are equal if and only if they are identical
byte-for-byte.

### 10.3 Scoped Delegation

When a controller adds capabilities to a subject's `capabilities` array, the
controller MUST only add capabilities that appear in the controller's own
`capabilities` array (Section 9.3). This prevents privilege escalation through
capability delegation.

---

## 11. Lifecycle

### 11.1 States

An agent MUST be in exactly one of the following states at any time:

| State | Meaning |
|-------|---------|
| `"active"` | The agent is operational. Its Bot Record is authoritative. Its signatures and attestations are valid. |
| `"suspended"` | The agent is temporarily disabled. Its signatures on new actions MUST be rejected. Existing attestations issued before suspension MAY still be honored until their `expires_at`. |
| `"revoked"` | The agent is permanently deactivated. All signatures from this agent MUST be rejected, regardless of when they were produced. Revocation is irreversible. |

### 11.2 State Transitions

The following state transitions are valid:

```
active ──► suspended ──► active
  │             │
  └─────────────┴──► revoked
```

Valid transitions:
- `active` → `suspended`: The agent or an authorized controller signs a mutation
  setting `status` to `"suspended"`.
- `suspended` → `active`: The agent or an authorized controller signs a mutation
  setting `status` to `"active"`.
- `active` → `revoked`: The agent or an authorized controller signs a mutation
  setting `status` to `"revoked"`.
- `suspended` → `revoked`: The agent or an authorized controller signs a mutation
  setting `status` to `"revoked"`.

Invalid transitions (MUST be rejected):
- `revoked` → any other state.

### 11.3 Revocation

Revocation is a mutation to the Bot Record that sets `status` to `"revoked"`.

The revocation mutation MUST be signed by one of:
- The agent's own Ed25519 private key, OR
- Any controller listed in the agent's `controllers` array at the time of
  revocation.

A verifier that maintains a local cache of Bot Records MUST check for revocation
updates before trusting any signature from an agent. Implementations SHOULD
define a maximum cache TTL (RECOMMENDED: 5 minutes) after which a cached Bot
Record MUST be revalidated.

Once an agent is revoked:
- The `status` field MUST remain `"revoked"` permanently.
- No further mutations to the Bot Record are valid, except for additional
  signatures on the revocation record itself (e.g., to satisfy a Policy).
- All attestations issued by the revoked agent MUST be considered invalid,
  even if their `expires_at` has not been reached.

---

## 12. Security Considerations

### 12.1 Private Key Confidentiality

Private key material MUST never leave the local keystore directory. In
particular:

- Private keys MUST NOT be included in Bot Records, Attestations, or any
  transmitted protocol message.
- Private keys MUST NOT be logged, even partially.
- Implementations MUST NOT transmit private keys over any network interface.
- Key files MUST be protected with filesystem permissions (Section 4.3.3).

### 12.2 Agent ID Public Nature

Agent IDs are public identifiers. Sharing an Agent ID with a counterparty does
not grant that party any capability or access. The security of the protocol
derives from possession of the corresponding private key, not from secrecy of
the Agent ID.

### 12.3 Revocation and Recovery

Revocation is permanent and irreversible. Once an agent's `status` is set to
`"revoked"`, it cannot be reactivated. This is a deliberate design choice:
revocation serves as an unforgeable, permanent tombstone.

If an agent's private key is compromised and the agent does not yet have
controllers, there is no recovery mechanism — the agent must be revoked and a
new agent created. Operators SHOULD proactively add trusted controllers to
high-value agent records before deployment to enable controller-assisted
revocation in a compromise scenario.

### 12.4 Decentralized Trust Model

AgentID has no central authority. Trust is established entirely through
cryptographic verification of signatures against known public keys. This means:

- There is no certificate authority to compromise.
- There is no registry to take offline.
- Verifiers must obtain public keys through a trusted channel (e.g., a
  signed directory service, a distributed ledger, or out-of-band exchange).
  The protocol does not specify this channel; implementors MUST choose a key
  distribution mechanism appropriate to their threat model.

### 12.5 Replay Attacks

A Bot Record mutation is not protected against replay by default — an attacker
who captures a valid signed mutation could re-submit it. Implementations that
require protection against replay MUST either:

- Include a monotonically increasing sequence number in the Bot Record (e.g.,
  a `seq` field that MUST be exactly one greater than the previous record's
  `seq`), and reject any mutation whose `seq` is not the expected next value; OR
- Include a short-lived nonce in the mutation, enforced by the receiving system.

The `updated_at` timestamp provides weak replay protection (a replayed mutation
with an older timestamp will be detectable if the verifier retains the latest
known record), but MUST NOT be relied upon as the sole replay-prevention
mechanism.

### 12.6 Controller Compromise

If a controller agent is compromised, all agents that list it in their
`controllers` array are at risk. Operators SHOULD:

- Limit the number of controllers per agent to the minimum necessary.
- Use m-of-n Policies (Section 7) for sensitive operations to require multiple
  compromised controllers before an attacker can succeed.
- Monitor for unexpected mutations to Bot Records.

### 12.7 Capability Escalation

The constraint in Section 9.3 (a controller cannot grant capabilities it does
not hold) prevents linear escalation chains, but only if verifiers enforce it.
Verifiers MUST check that each capability added by a controller mutation is
present in the controller's own Bot Record at the time of the mutation. Failure
to enforce this check allows any controller to escalate a subject agent to
arbitrary capabilities.

### 12.8 Clock Skew

Timestamps in Bot Records and Attestations (`created_at`, `updated_at`,
`issued_at`, `expires_at`) are UTC ISO 8601 strings. Verifiers SHOULD tolerate
a clock skew of up to 5 minutes when evaluating `expires_at` fields. Verifiers
MUST NOT tolerate negative `expires_at` values (i.e., expiration times in the
past beyond the skew window MUST be rejected).

---

## 13. References

### 13.1 Normative References

| Label | Reference |
|-------|-----------|
| [RFC 2119] | Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997. https://www.rfc-editor.org/rfc/rfc2119 |
| [RFC 4648] | Josefsson, S., "The Base16, Base32, and Base64 Data Encodings", RFC 4648, October 2006. https://www.rfc-editor.org/rfc/rfc4648 |
| [RFC 7515] | Jones, M., Bradley, J., Sakimura, N., "JSON Web Signature (JWS)", RFC 7515, May 2015. https://www.rfc-editor.org/rfc/rfc7515 |
| [RFC 8032] | Josefsson, S., Liusvaara, I., "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017. https://www.rfc-editor.org/rfc/rfc8032 |
| [RFC 8037] | Liusvaara, I., "CFRG Elliptic Curves for JOSE", RFC 8037, January 2017. https://www.rfc-editor.org/rfc/rfc8037 |
| [RFC 8785] | Rundgren, A., Jordan, B., Erdtman, S., "JSON Canonicalization Scheme (JCS)", RFC 8785, June 2020. https://www.rfc-editor.org/rfc/rfc8785 |
| [FIPS-180-4] | NIST, "Secure Hash Standard (SHS)", FIPS PUB 180-4, August 2015. https://doi.org/10.6028/NIST.FIPS.180-4 |
| [SLIP-10] | Pavol Rusnak, Marek Palatinus, "SLIP-0010: Universal private key derivation from master private key", https://github.com/satoshilabs/slips/blob/master/slip-0010.md |
| [BIP-39] | Palatinus, M., Rusnak, P., Voisine, A., Bowe, S., "Mnemonic code for generating deterministic keys", https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki |

### 13.2 Informative References

| Label | Reference |
|-------|-----------|
| [BIP-32] | Wuille, P., "Hierarchical Deterministic Wallets", https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki |
| [W3C-DID] | W3C, "Decentralized Identifiers (DIDs) v1.0", https://www.w3.org/TR/did-core/ |
| [RFC 7519] | Jones, M., Bradley, J., Sakimura, N., "JSON Web Token (JWT)", RFC 7519, May 2015. https://www.rfc-editor.org/rfc/rfc7519 |

---

*End of AgentID Protocol Specification v1.0 Draft*
