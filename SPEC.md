# AgentID Protocol Specification

**Version:** 1.0.0-draft
**Status:** Draft
**Date:** 2026-03-24

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
6. [Proofs and Signatures](#6-proofs-and-signatures)
7. [Policies](#7-policies)
8. [Attestations](#8-attestations)
9. [Controllers and Delegation](#9-controllers-and-delegation)
10. [Capability Scoping](#10-capability-scoping)
11. [Lifecycle](#11-lifecycle)
12. [Security Considerations](#12-security-considerations)
13. [References](#13-references)

---

## 1. Abstract

AgentID is a decentralized identity and authorization protocol for AI agents. It defines how agents are identified by cryptographic keypairs, how their capabilities are declared and scoped, how actions are authorized through signed proofs, and how trust is delegated between agents via controller relationships and attestations.

An agent's identity is derived deterministically from its Ed25519 public key. No central registry is required to create or verify an agent identity. Trust is established through cryptographic signatures, not through third-party issuance.

This specification defines the data formats, cryptographic primitives, key derivation scheme, identity document structure, signature verification procedures, policy evaluation rules, attestation format, capability scoping model, and agent lifecycle state machine that together constitute the AgentID protocol.

---

## 2. Motivation

Existing bot and agent frameworks lack a coherent identity layer. Specifically, four problems remain unsolved:

### 2.1 No Verifiable Link Between a Bot and Its Operator

Current bot tokens and API keys do not cryptographically bind an agent to its operator. An observer cannot verify who deployed a given agent, nor confirm the agent's claimed identity without trusting a third-party platform. Compromised tokens can be used by any party, and there is no way to distinguish legitimate use from impersonation.

### 2.2 No Lifecycle Management or Revocation

Agents may be decommissioned, compromised, or reassigned, yet no standard mechanism exists to signal these state changes in a verifiable way. There is no defined process for suspending an agent temporarily or permanently revoking its authorization. Without lifecycle signals, relying parties cannot detect stale or compromised agents.

### 2.3 No Capability Declarations or Third-Party Attestations

Agents perform actions on external systems but provide no machine-readable declaration of what they are authorized to do. There is no mechanism for a third party — such as an enterprise identity provider or another trusted agent — to issue a signed attestation that a given agent possesses a specific capability. Relying parties must grant access based on trust rather than verifiable claims.

### 2.4 No Cryptographic Proof Chain for Authorized Actions

When an agent takes an action, there is no artifact that proves the action was authorized by the agent's controller, that the controller was itself authorized, or that the authorization was in scope at the time of the action. Audit trails are limited to platform logs that may be tampered with or unavailable.

AgentID addresses all four problems through a combination of Ed25519 keypairs, deterministic agent IDs, signed Bot Records, scoped capabilities, controller delegation, and threshold policies.

---

## 3. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

**Agent**
An autonomous software process acting on behalf of a principal. An agent is uniquely identified by its Ed25519 keypair. An agent MAY act autonomously or under the direction of a human operator.

**Agent ID**
A deterministic URN derived from an agent's Ed25519 public key. The Agent ID is the canonical identifier for an agent and is computed as described in Section 4.2. Agent IDs are stable: the same public key always produces the same Agent ID.

**Bot Record**
The identity document for an agent. A Bot Record is a JSON object containing the agent's public key, operator metadata, declared capabilities, controller list, and lifecycle status. The authoritative structure is defined in Section 5.

**Keypair**
An Ed25519 public/private key pair as defined in RFC 8032. The public key is 32 bytes. The private key (secret scalar) is 32 bytes. Implementations MUST use the signing and verification algorithms defined in RFC 8032.

**Controller**
An agent authorized to manage another agent's keys or Bot Record. A controller relationship is declared in the subject agent's Bot Record and MUST be signed by the subject agent's private key. Controller authority is scoped by the operations listed in the Bot Record.

**Attestation**
A signed statement made by one agent about another. An attestation asserts that the subject agent possesses a specific capability or property. Attestations are first-class objects with a defined JSON structure, expiry, and cryptographic proof. See Section 8.

**Policy**
An m-of-n threshold rule governing a key operation. A policy specifies a minimum number of controller signatures required before a given operation (such as key rotation) may be executed. See Section 7.

**JWS**
JSON Web Signature as defined in RFC 7515. All proofs in this protocol are compact-serialized JWS objects using the EdDSA algorithm.

**JCS**
JSON Canonicalization Scheme as defined in RFC 8785. Before signing, JSON payloads MUST be canonicalized using JCS to produce a deterministic byte sequence.

**Principal**
The human or organization on whose behalf an agent acts. Principals are identified by the operator metadata in the Bot Record.

---

## 4. Agent Identity

### 4.1 Keypair Generation

Implementations MUST support two modes of keypair generation:

#### 4.1.1 Random Generation

For simple deployments, an Ed25519 keypair MAY be generated by sampling 32 bytes from a cryptographically secure random number generator (CSRNG) to produce the private key seed, then computing the corresponding public key per RFC 8032 Section 5.1.

#### 4.1.2 Deterministic Derivation from BIP-39 Mnemonic

For hierarchical deployments, keypairs MUST be derived from a BIP-39 mnemonic seed using SLIP-10.

**Step 1: Mnemonic to Seed.**
A BIP-39 mnemonic of 12, 18, or 24 words MUST be converted to a 512-bit seed using PBKDF2-HMAC-SHA512 with the passphrase `"mnemonic"` concatenated with an optional user-supplied password, 2048 iterations, and output length 64 bytes, as specified in BIP-39.

**Step 2: Master Key Derivation.**
The 64-byte seed MUST be passed to the SLIP-10 master key generation function using the curve identifier `"ed25519 seed"` as the HMAC-SHA512 key, producing a 32-byte master private key and a 32-byte chain code.

**Step 3: Child Key Derivation.**
Child keys MUST be derived using the SLIP-10 hardened child key derivation function with the following path:

```
m/agentid'/agent_index'
```

where:
- `agentid'` is the hardened index `0x80000000` + `0x61676964` (the ASCII encoding of `"agid"` interpreted as a 32-bit big-endian integer, value `1633771364`, plus the hardened offset, resulting in index `0xE1716B44`)
- `agent_index'` is the hardened index `0x80000000` + `agent_index`, where `agent_index` is a non-negative integer uniquely identifying the agent within the keystore

All derivation steps MUST use hardened derivation (apostrophe notation). Non-hardened derivation MUST NOT be used for AgentID keypairs.

The resulting 32-byte child private key is the Ed25519 private key seed for the agent. The public key is computed per RFC 8032 Section 5.1.5.

### 4.2 Agent ID Format

The Agent ID is computed from the Ed25519 public key bytes using SHA-256:

```
agent_id = "urn:agent:sha256:" + lowercase_hex(sha256(public_key_bytes))
```

Where:
- `public_key_bytes` is the 32-byte compressed Ed25519 public key as defined in RFC 8032 Section 5.1.5
- `sha256()` is the SHA-256 hash function producing a 32-byte digest
- `lowercase_hex()` encodes the digest as a 64-character lowercase hexadecimal string

**Properties:**
- **Deterministic:** The same public key always yields the same Agent ID.
- **Decentralized:** No central registry or coordination is required to generate a valid Agent ID.
- **Non-reversible:** The public key cannot be recovered from the Agent ID alone; the full public key MUST be stored separately in the Bot Record.

**Example:**

Given a 32-byte Ed25519 public key whose SHA-256 digest begins `a3f1c2...`, the Agent ID is:

```
urn:agent:sha256:a3f1c2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
```

Agent IDs MUST be treated as case-insensitive for comparison purposes. Implementations MUST canonicalize Agent IDs to lowercase before storing or comparing.

### 4.3 Key Storage

Implementations MUST store key material in a local keystore directory. The default keystore path is `~/.agentid/`. Implementations MUST allow this path to be overridden via environment variable `AGENTID_HOME` or equivalent configuration.

#### 4.3.1 Directory Structure

```
~/.agentid/
├── agents.json          # List of Agent records (public metadata only)
└── keys/
    └── {id_hex}.key     # One file per agent: the raw 32-byte private key seed
```

Where `{id_hex}` is the 64-character lowercase hexadecimal SHA-256 digest used in the Agent ID (i.e., the portion after `urn:agent:sha256:`).

#### 4.3.2 `agents.json`

The `agents.json` file MUST contain a JSON array of Agent record objects. Each object MUST contain at minimum the fields `id`, `public_key`, and `created_at`. This file MUST NOT contain secret key material.

Example:

```json
[
  {
    "id": "urn:agent:sha256:a3f1c2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "public_key": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
    "created_at": "2026-03-24T17:00:00Z",
    "name": "primary-agent"
  }
]
```

#### 4.3.3 Key Files

Each file under `keys/` MUST contain exactly 32 bytes: the raw Ed25519 private key seed for the corresponding agent.

Key files MUST be created with permissions `0600` (owner read/write only) on POSIX systems. On non-POSIX systems, implementations MUST apply the most restrictive access control available to the platform.

Implementations MUST refuse to read a key file whose permissions allow access by any user other than the owner, and MUST emit a warning or error in this case.

---

## 5. Bot Record

A Bot Record is the authoritative identity document for an agent. It declares the agent's public key, operator metadata, capabilities, controllers, and lifecycle status.

### 5.1 Structure

A Bot Record MUST be a JSON object conforming to the following schema:

```json
{
  "id": "urn:agent:sha256:a3f1c2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
  "version": 1,
  "public_key": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
  "operator": {
    "name": "Acme Corp",
    "url": "https://acme.example"
  },
  "capabilities": ["read:github", "write:email", "invoke:openai"],
  "controllers": ["urn:agent:sha256:b4e2d3c4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"],
  "policies": [],
  "status": "active",
  "created_at": "2026-03-24T17:00:00Z",
  "updated_at": "2026-03-24T17:00:00Z",
  "proof": "eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkifQ.eyJpZCI6InVybjphZ2VudDpzaGEyNTY6YTNmMWMyLi4uIn0.SIGNATURE"
}
```

### 5.2 Field Definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | REQUIRED | The Agent ID as defined in Section 4.2. MUST match `sha256(base64url_decode(public_key))`. |
| `version` | integer | REQUIRED | Protocol version. MUST be `1` for this version of the specification. |
| `public_key` | string | REQUIRED | Base64url-encoded (no padding) 32-byte Ed25519 public key. |
| `operator` | object | OPTIONAL | Metadata about the human or organization operating this agent. |
| `operator.name` | string | OPTIONAL | Human-readable name of the operator. |
| `operator.url` | string | OPTIONAL | URL identifying the operator. MUST be a valid absolute HTTPS URL if present. |
| `capabilities` | array of strings | REQUIRED | List of capability strings as defined in Section 10. MAY be empty. |
| `controllers` | array of strings | REQUIRED | List of Agent IDs authorized to manage this agent. MAY be empty. |
| `policies` | array of objects | OPTIONAL | List of policy objects as defined in Section 7. MAY be empty or absent. |
| `status` | string | REQUIRED | Lifecycle status. MUST be one of `"active"`, `"suspended"`, `"revoked"`. |
| `created_at` | string | REQUIRED | ISO 8601 UTC timestamp of record creation. MUST include timezone designator `Z`. |
| `updated_at` | string | REQUIRED | ISO 8601 UTC timestamp of last mutation. MUST be greater than or equal to `created_at`. |
| `proof` | string | REQUIRED (on mutated records) | Compact JWS signature as produced by Section 6.2. MUST be absent from the payload before signing (per Section 6.2 step 1). |

### 5.3 Validation Rules

Implementations MUST enforce the following:

1. The `id` field MUST equal `"urn:agent:sha256:" + lowercase_hex(sha256(base64url_decode(public_key)))`. If this check fails, the Bot Record is invalid and MUST be rejected.
2. The `version` field MUST be `1`. Bot Records with other version values MUST be rejected by implementations of this specification.
3. `created_at` and `updated_at` MUST be parseable as RFC 3339 timestamps with `Z` UTC offset.
4. All entries in `capabilities` MUST conform to the format defined in Section 10.1.
5. All entries in `controllers` MUST be syntactically valid Agent IDs (matching the pattern `urn:agent:sha256:[0-9a-f]{64}`).

### 5.4 Mutations

Any change to a Bot Record is a mutation. Every mutation MUST be accompanied by a JWS proof as defined in Section 6. The `updated_at` field MUST be updated to the current UTC time on every mutation. Mutations that do not include a valid proof MUST be rejected.

---

## 6. Proofs and Signatures

### 6.1 Overview

All mutations to a Bot Record MUST include a cryptographic proof. A proof is a compact-serialized JWS (RFC 7515) over the JCS-canonicalized (RFC 8785) mutation payload, signed using EdDSA with an Ed25519 key.

### 6.2 Signing Procedure

To produce a proof for a mutation:

1. **Construct the payload object.** The payload is the full Bot Record JSON object after applying the mutation, with the `proof` field absent.

2. **Canonicalize.** Apply JCS (RFC 8785) to the payload object to produce a deterministic UTF-8 byte sequence. JCS sorts object keys lexicographically and removes insignificant whitespace.

3. **Encode.** Base64url-encode (no padding) the JCS output to produce the JWS payload.

4. **Construct the JWS header.** The header MUST be:
   ```json
   {"alg": "EdDSA", "crv": "Ed25519"}
   ```
   Base64url-encode (no padding) the JSON header to produce the JWS header.

5. **Sign.** Compute the Ed25519 signature over the ASCII bytes of:
   ```
   BASE64URL(header) + "." + BASE64URL(payload)
   ```
   using the signing agent's private key per RFC 8032 Section 5.1.6. The signature is 64 bytes.

6. **Serialize.** The compact JWS is:
   ```
   BASE64URL(header) + "." + BASE64URL(payload) + "." + BASE64URL(signature)
   ```

The resulting compact JWS string is the `proof` value. It MUST be included in the transmitted Bot Record.

### 6.3 Verification Procedure

To verify a proof:

1. Extract and base64url-decode the three components of the compact JWS.
2. Verify the JWS header contains `"alg": "EdDSA"` and `"crv": "Ed25519"`. If not, reject.
3. Decode the JWS payload from base64url to obtain the canonicalized Bot Record bytes.
4. Parse the canonicalized bytes as JSON. The `id` field is the subject agent's Agent ID. Determine the signing key as follows:
   - **Self-signed mutation:** Retrieve the 32-byte Ed25519 public key from the `public_key` field of the Bot Record. The signature MUST verify using this key.
   - **Controller-initiated mutation:** Iterate over the subject's `controllers` list. For each controller Agent ID, retrieve the controller's Bot Record and extract its `public_key`. Attempt Ed25519 signature verification using each controller's public key in turn. Accept the mutation if any one controller's key successfully verifies the signature. If no listed controller's key verifies, reject.
5. Verify the Ed25519 signature over `BASE64URL(header) + "." + BASE64URL(payload)` using the candidate public key(s) identified in step 4, per RFC 8032 Section 5.1.7.
6. If verification fails for all candidate keys, reject the mutation.

### 6.4 Who May Sign

- An agent MAY sign mutations to its own Bot Record using its own private key.
- A controller MAY sign mutations to a subject agent's Bot Record, provided the controller's Agent ID appears in the subject's `controllers` list and the mutation is within the scope of the controller's authorized operations.
- For policy-governed operations (see Section 7), the required threshold of signers MUST have each produced a valid proof before the operation is accepted.

---

## 7. Policies

### 7.1 Overview

A policy defines an m-of-n threshold rule for a specific operation on a Bot Record. Policies are OPTIONAL. When a policy is defined for an operation, that operation MUST NOT be executed unless the threshold of valid signatures is met.

### 7.2 Policy Object Structure

```json
{
  "operation": "status_update",
  "threshold": 2,
  "signers": [
    "urn:agent:sha256:a3f1c2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "urn:agent:sha256:b4e2d3c4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
    "urn:agent:sha256:c5f3e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3"
  ]
}
```

### 7.3 Field Definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `operation` | string | REQUIRED | The operation governed by this policy. MUST be one of the defined operation identifiers (see Section 7.4). |
| `threshold` | integer | REQUIRED | Minimum number of distinct valid signatures required. MUST be greater than zero and less than or equal to the length of `signers`. |
| `signers` | array of strings | REQUIRED | Ordered list of Agent IDs eligible to sign for this policy. MUST contain at least `threshold` entries. All entries MUST be valid Agent IDs. |

### 7.4 Defined Operations

| Operation Identifier | Description |
|---|---|
| `status_update` | Changing the agent's `status` field. |
| `controller_update` | Adding or removing entries in the agent's `controllers` list. |
| `capability_update` | Adding or removing entries in the agent's `capabilities` list. |

### 7.5 Multi-Signature Evaluation

When a policy applies to an operation, the implementation MUST:

1. Collect all proof objects submitted for the operation. Each proof MUST be a valid compact JWS as defined in Section 6.
2. Verify each proof independently per Section 6.3.
3. Determine the set of distinct signers whose proofs verify successfully and whose Agent IDs appear in the policy's `signers` list.
4. If the count of distinct valid signers is less than `threshold`, reject the operation.
5. If the count meets or exceeds `threshold`, the operation MAY proceed.

Duplicate signatures from the same signer MUST NOT be counted more than once toward the threshold.

---

## 8. Attestations

### 8.1 Overview

An attestation is a signed statement made by one agent (the issuer) about another agent (the subject). Attestations assert that the subject possesses a specific capability or property, as declared by the issuer. Attestations are first-class objects with their own lifecycle and MUST NOT be embedded in Bot Records.

### 8.2 Attestation Object Structure

```json
{
  "issuer": "urn:agent:sha256:a3f1c2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
  "subject": "urn:agent:sha256:b4e2d3c4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
  "claim": "capability:write:github",
  "issued_at": "2026-03-24T17:00:00Z",
  "expires_at": "2026-06-24T17:00:00Z",
  "proof": "eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkifQ.eyJpc3N1ZXIiOi4uLn0.SIGNATURE"
}
```

### 8.3 Field Definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `issuer` | string | REQUIRED | Agent ID of the agent making the attestation. |
| `subject` | string | REQUIRED | Agent ID of the agent being attested about. |
| `claim` | string | REQUIRED | The claim being asserted. MUST follow the format defined in Section 8.4. |
| `issued_at` | string | REQUIRED | ISO 8601 UTC timestamp when the attestation was created. MUST include `Z`. |
| `expires_at` | string | OPTIONAL | ISO 8601 UTC timestamp after which the attestation is no longer valid. If absent, the attestation does not expire. MUST be after `issued_at` if present. |
| `proof` | string | REQUIRED | Compact JWS signature by the issuer over the JCS-canonicalized attestation object (with `proof` field absent). |

### 8.4 Claim Format

Claims MUST be strings in the format:

```
claim_type ":" claim_value
```

Where:
- `claim_type` identifies the category of the claim. Defined values: `capability` (asserting the subject possesses a capability).
- `claim_value` is the value being asserted. For `capability` claims, this MUST be a valid capability string as defined in Section 10.1.

Example: `capability:write:github` asserts the subject agent is authorized to perform `write:github` operations.

### 8.5 Signing an Attestation

To produce a proof for an attestation:

1. Construct the full attestation JSON object with all required fields except `proof`.
2. Apply JCS (RFC 8785) canonicalization.
3. Sign using the issuer's Ed25519 private key per the procedure in Section 6.2, steps 3–6.
4. Set the `proof` field to the resulting compact JWS string.

### 8.6 Verifying an Attestation

To verify an attestation:

1. Verify the `issuer` field is a syntactically valid Agent ID.
2. Retrieve the issuer's Bot Record and extract the issuer's 32-byte Ed25519 public key.
3. Verify the issuer's Bot Record has `status` equal to `"active"`. Attestations from suspended or revoked agents MUST be rejected.
4. Verify the `proof` using the procedure in Section 6.3, substituting the attestation object for the Bot Record.
5. If `expires_at` is present, verify the current UTC time is before `expires_at`. Expired attestations MUST be rejected.
6. If all checks pass, the attestation is valid.

---

## 9. Controllers and Delegation

### 9.1 Overview

A controller is an agent authorized to manage another agent's Bot Record. The controller relationship enables hierarchical trust structures, such as an organization-level agent controlling department-level agents, which in turn control individual task agents.

### 9.2 Declaring a Controller

A controller is declared by including the controller's Agent ID in the `controllers` array of the subject's Bot Record. This declaration MUST be signed by the subject agent's private key (or by an existing controller with `controller_update` authority).

An agent MAY have zero or more controllers. An agent with no controllers can only be managed by operations signed with its own private key.

### 9.3 Controller Authority

A controller MAY perform the following operations on a subject agent's Bot Record:

- Update the `status` field (subject to applicable policies).
- Add or remove capabilities from the `capabilities` list (subject to applicable policies and Section 9.4).
- Add or remove controllers from the `controllers` list (subject to applicable policies).

All controller-initiated mutations MUST be signed by the controller's private key and MUST include the controller's Agent ID in the proof metadata. The controller's Agent ID MUST appear in the subject's `controllers` list at the time the mutation is applied.

### 9.4 Scoped Capability Delegation

A controller MUST NOT grant the subject agent a capability that the controller does not itself possess, unless the controller holds the `admin:agentid` capability, which grants unrestricted capability delegation authority.

When a controller adds a capability to a subject's `capabilities` list, the implementation MUST verify that the controller's own Bot Record includes the same capability or `admin:agentid`.

### 9.5 Controller Chain Verification

When verifying a controller-initiated mutation, implementations MUST:

1. Verify that the signing agent's Agent ID appears in the subject's `controllers` list.
2. Retrieve the controller's Bot Record and verify its `status` is `"active"`. Mutations signed by suspended or revoked controllers MUST be rejected.
3. Verify the controller's proof per Section 6.3.
4. For capability additions, verify scoped delegation rules per Section 9.4.

---

## 10. Capability Scoping

### 10.1 Capability String Format

A capability is a string in the format:

```
verb ":" resource
```

Where:
- `verb` is a lowercase ASCII string identifying the type of operation. Defined verbs: `read`, `write`, `invoke`, `admin`.
- `resource` is a lowercase ASCII string identifying the resource or system the verb applies to.

**Examples:**

| Capability String | Meaning |
|---|---|
| `read:github` | Read access to GitHub resources |
| `write:email` | Write (send) access to email |
| `invoke:openai` | Permission to call OpenAI APIs |
| `admin:agentid` | Administrative authority over AgentID operations |
| `read:slack` | Read access to Slack messages |
| `write:github` | Write access to GitHub resources (push, PR creation, etc.) |

Capability strings MUST match the regular expression `^[a-z][a-z0-9_-]*:[a-z][a-z0-9_:-]*$`. Implementations MUST reject capability strings that do not match this pattern.

### 10.2 Wildcard Capabilities

The `admin:agentid` capability is the only defined wildcard authority and confers the following specific rights:

- Create and manage Bot Records for other agents.
- Grant any capability to any agent, regardless of the `admin:agentid` holder's own capability list.
- Revoke any agent.

No other implicit wildcard semantics are defined. Capability matching MUST be exact string equality unless explicitly specified otherwise.

### 10.3 Capability Verification

When verifying whether an agent is authorized to perform an operation:

1. Retrieve the agent's Bot Record.
2. Verify the agent's `status` is `"active"`. Agents with `status` other than `"active"` MUST NOT be considered authorized.
3. Check whether the required capability string appears in the agent's `capabilities` list using exact string equality.
4. If the required capability is not present, check whether `admin:agentid` appears in the agent's `capabilities` list. If so, the operation is authorized.
5. If neither check passes, the agent is not authorized for the operation.

---

## 11. Lifecycle

### 11.1 States

An agent's lifecycle is represented by the `status` field in its Bot Record. The defined states are:

| State | Description |
|---|---|
| `active` | The agent is operational and authorized to act within its declared capabilities. |
| `suspended` | The agent is temporarily disabled. Suspended agents MUST NOT be treated as authorized. Suspension is reversible. |
| `revoked` | The agent is permanently disabled. Revoked agents MUST NOT be treated as authorized. Revocation is irreversible. |

### 11.2 State Transitions

The permitted state transitions are:

```
active --> suspended
active --> revoked
suspended --> active
suspended --> revoked
revoked --> (no transition permitted)
```

Implementations MUST reject any mutation that attempts a transition not listed above. In particular, a transition from `revoked` to any other state MUST be rejected.

### 11.3 Performing a Status Update

To update an agent's status:

1. Construct the updated Bot Record with the new `status` value and updated `updated_at` timestamp.
2. If a `status_update` policy is defined for this agent, collect and verify the required threshold of signatures per Section 7.5.
3. If no policy is defined, sign the mutation with the agent's own private key or a controller's private key per Section 9.3.
4. Transmit the signed Bot Record.

### 11.4 Revocation

Revocation is a status update that sets `status` to `"revoked"`. Revocation MAY be performed by:

- The agent itself, using its own private key.
- Any agent listed in the agent's `controllers` list, per Section 9.3.

Once an agent is revoked:

- Its Bot Record MUST be retained (not deleted) to allow audit and verification of historical proofs.
- All attestations issued by the revoked agent that were valid at the time of issuance remain valid for historical audit purposes but MUST NOT be accepted as current authorization by relying parties.
- All attestations issued to the revoked agent MUST be treated as invalid immediately upon revocation.

---

## 12. Security Considerations

### 12.1 Private Key Confidentiality

Private key seeds MUST never leave the local keystore. Implementations MUST NOT transmit private keys over any network interface. Private keys MUST NOT be included in Bot Records, attestations, or any other protocol object.

When exporting an agent for backup or migration, the exported bundle MUST be encrypted using a key derived from a user-supplied passphrase via a memory-hard key derivation function (e.g., Argon2id with parameters meeting current OWASP recommendations).

### 12.2 Agent ID Confidentiality

Agent IDs are public identifiers and are NOT secret. They MUST be treated as stable, public references to an agent and MAY be shared freely. Implementations MUST NOT assume that keeping an Agent ID secret provides any security property.

### 12.3 Revocation Requirements

Revocation requires either:

- The agent's own private key, or
- The private key of a listed controller.

If all of the above keys are lost or compromised, the agent cannot be revoked through the protocol. Operators SHOULD establish at least one trusted controller for each agent to allow revocation in the event the agent's own key is compromised.

### 12.4 Decentralized Trust Model

There is no central authority in the AgentID protocol. Trust is established through:

1. Cryptographic verification of Ed25519 signatures.
2. The declared controller hierarchy in Bot Records.
3. Attestations from trusted issuers.

Relying parties MUST decide independently which issuers they trust for attestations. The protocol does not define a root of trust; this is left to the deploying organization.

### 12.5 Replay Attacks

Signed Bot Records and attestations include `updated_at` and `issued_at` timestamps. Implementations SHOULD reject mutations with `updated_at` values more than a configurable tolerance (default: 5 minutes) behind the current UTC time to mitigate replay attacks.

Attestations with `expires_at` in the past MUST be rejected. Attestations without `expires_at` are not subject to expiry but SHOULD be treated with appropriate skepticism for long-lived authorization decisions.

### 12.6 Side-Channel Considerations

Ed25519 signing implementations MUST use deterministic nonce generation per RFC 8032 to eliminate nonce-reuse vulnerabilities. Implementations SHOULD use a constant-time signature verification routine to mitigate timing side channels.

---

## 13. References

### 13.1 Normative References

**BIP-39**
Palatinus, M., Rusnak, P., Voisine, A., and S. Bowe, "Mnemonic code for generating deterministic keys," Bitcoin Improvement Proposal 39, 2013. Available at: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

**SLIP-10**
Rusnak, P., "Universal private key derivation from master private key," SatoshiLabs Improvement Proposal 10, 2016. Available at: https://github.com/satoshilabs/slips/blob/master/slip-0010.md

**RFC 8032**
Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)," RFC 8032, January 2017. DOI: 10.17487/RFC8032.

**RFC 7515**
Jones, M., Bradley, J., and N. Sakimura, "JSON Web Signature (JWS)," RFC 7515, May 2015. DOI: 10.17487/RFC7515.

**RFC 8785**
Rundgren, A., Jordan, B., and S. Erdtman, "JSON Canonicalization Scheme (JCS)," RFC 8785, June 2020. DOI: 10.17487/RFC8785.

**RFC 2119**
Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels," BCP 14, RFC 2119, March 1997. DOI: 10.17487/RFC2119.

**RFC 3339**
Klyne, G. and C. Newman, "Date and Time on the Internet: Timestamps," RFC 3339, July 2002. DOI: 10.17487/RFC3339.

### 13.2 Informative References

**BIP-44**
Palatinus, M. and P. Rusnak, "Multi-Account Hierarchy for Deterministic Wallets," Bitcoin Improvement Proposal 44, 2014. Available at: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

**RFC 7517**
Jones, M., "JSON Web Key (JWK)," RFC 7517, May 2015. DOI: 10.17487/RFC7517.

**RFC 7519**
Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token (JWT)," RFC 7519, May 2015. DOI: 10.17487/RFC7519.

---

*End of AgentID Protocol Specification v1.0.0-draft*
