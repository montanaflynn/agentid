# AgentID Protocol Specification
## Signed Identity Grants (SIG)
### Version 1.0 — Draft

---

## Abstract

AgentID (Signed Identity Grants, "SIG") is a decentralized identity and authorization protocol for AI agents. It defines how agents are identified via cryptographic keypairs, and how principals issue signed Grants to agents scoping exactly what they are permitted to do and for how long.

The central primitive is a **Grant** — a signed token issued by a principal (human, organization, or agent) to an agent. Identity (keypairs, Agent IDs, Bot Records) is the foundation that makes Grants cryptographically verifiable. Any party can verify a Grant without consulting a central authority.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Terminology](#2-terminology)
3. [Agent Identity](#3-agent-identity)
   - 3.1 [Keypair Generation](#31-keypair-generation)
   - 3.2 [Agent ID Format](#32-agent-id-format)
   - 3.3 [Key Storage](#33-key-storage)
4. [Bot Record](#4-bot-record)
   - 4.1 [Schema](#41-schema)
   - 4.2 [Record Mutations](#42-record-mutations)
5. [Grants](#5-grants)
   - 5.1 [Grant Structure](#51-grant-structure)
   - 5.2 [Scope Format](#52-scope-format)
   - 5.3 [Grant Issuance](#53-grant-issuance)
   - 5.4 [Grant Verification](#54-grant-verification)
   - 5.5 [Grant Revocation](#55-grant-revocation)
   - 5.6 [Delegation](#56-delegation)
6. [Proofs and Signatures](#6-proofs-and-signatures)
   - 6.1 [Signature Algorithm](#61-signature-algorithm)
   - 6.2 [Canonicalization](#62-canonicalization)
   - 6.3 [JWS Encoding](#63-jws-encoding)
7. [Policies](#7-policies)
8. [Attestations](#8-attestations)
9. [Controllers](#9-controllers)
10. [Agent Lifecycle](#10-agent-lifecycle)
11. [Security Considerations](#11-security-considerations)
12. [References](#12-references)

---

## 1. Motivation

AI agents operating in multi-system environments present a novel authorization challenge. Unlike traditional service accounts, agents:

- Act autonomously across many systems and APIs
- May be delegated authority by other agents
- Need to prove their identity and authorization to third parties on demand
- Must be revocable without disrupting unrelated agents

Existing systems do not address these requirements:

- There is no verifiable cryptographic link between a running agent process and the human or organization that deployed it.
- There is no standard lifecycle management — no way for an operator to suspend or revoke an agent's authority.
- There are no capability declarations that third parties can inspect and trust.
- There is no cryptographic proof chain demonstrating that an agent was authorized to take a specific action.

AgentID addresses all four gaps. The Grant is the core instrument: a signed, scoped, time-limited token that proves authorization from issuer to subject without requiring any central registry.

---

## 2. Terminology

| Term | Definition |
|---|---|
| **Agent** | An autonomous software process acting on behalf of a principal. |
| **Agent ID** | A deterministic URN derived from an agent's public key: `urn:agent:sha256:{hex}`. |
| **Principal** | A human, organization, or agent that has authority to issue Grants. |
| **Grant** | A signed token authorizing an agent to act within defined scopes for a defined duration. |
| **Scope** | A permission string in the format `{verb}:{resource}`. |
| **Bot Record** | The canonical identity document for an agent, containing public key, operator info, and status. |
| **Keypair** | An Ed25519 public/private key pair. The private key MUST remain local; the public key MAY be shared freely. |
| **Controller** | An agent explicitly authorized to manage another agent's keys or Bot Record. |
| **Attestation** | A signed statement one agent makes about another, asserting a claim. |
| **Policy** | An m-of-n threshold rule governing key operations for an agent. |
| **Revocation Record** | A signed document canceling a previously issued Grant before its natural expiry. |
| **JWS** | JSON Web Signature, as defined in RFC 7515. |
| **JCS** | JSON Canonicalization Scheme, as defined in RFC 8785. |

---

## 3. Agent Identity

### 3.1 Keypair Generation

Agents MUST be identified by an Ed25519 keypair as defined in RFC 8032.

**Standalone key generation**: An implementation MAY generate a random Ed25519 keypair directly using a cryptographically secure random number generator.

**Deterministic key derivation**: An implementation SHOULD support key derivation from a BIP-39 mnemonic seed phrase via SLIP-10. The derivation path for the nth agent is:

```
m/agentid'/agent_index'
```

Where `agentid'` is a hardened child at index `0x80000000 + sha256("agentid")[0:4]` interpreted as a 32-bit big-endian unsigned integer, and `agent_index'` is a hardened child at the agent's sequential index.

The private key bytes MUST be kept in local storage only. They MUST NOT be transmitted over any network interface. They MUST NOT be logged or included in any diagnostic output.

### 3.2 Agent ID Format

An Agent ID is deterministically derived from the agent's Ed25519 public key bytes:

```
agent_id = "urn:agent:sha256:" + hex(sha256(public_key_bytes))
```

Where:
- `public_key_bytes` is the 32-byte compressed Ed25519 public key
- `sha256(...)` is the SHA-256 digest (RFC 6234)
- `hex(...)` is lowercase hexadecimal encoding
- The resulting string is 81 characters: the prefix `urn:agent:sha256:` (17 chars) plus 64 hex characters

**Example:**
```
urn:agent:sha256:3b4c2a1d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b
```

Agent IDs are deterministic: the same public key MUST always yield the same Agent ID. Agent IDs are stable identifiers: an agent's ID MUST NOT change unless a new keypair is generated, in which case a new Agent ID is produced.

Agent IDs are public identifiers. They carry no secret information and MAY be shared freely.

### 3.3 Key Storage

The default local keystore is located at `~/.agentid/`. The layout is:

```
~/.agentid/
  agents.json          # Array of Bot Records (public info only, no secret keys)
  keys/
    {agent_id_hex}.key  # Raw secret key bytes for each agent
```

**`agents.json`**: A JSON array of Bot Record objects (see Section 4). MUST NOT contain any private key material.

**`keys/{agent_id_hex}.key`**: The raw 32-byte Ed25519 secret key for the agent whose ID is `{agent_id_hex}`. This file:
- MUST have permissions `0600` (owner read/write only) on POSIX systems
- MUST NOT be readable by any process other than the owning user
- SHOULD be stored on a filesystem that does not sync to remote storage without explicit user consent

An implementation MUST refuse to operate if key files are found with world-readable or group-readable permissions.

---

## 4. Bot Record

The Bot Record is the canonical public identity document for an agent. It contains the agent's public key, operator information, list of controllers, and current lifecycle status.

### 4.1 Schema

```json
{
  "id": "urn:agent:sha256:3b4c2a1d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b",
  "version": 1,
  "public_key": "MCowBQYDK2VwAyEA...",
  "operator": {
    "name": "Acme Corp",
    "url": "https://acme.example"
  },
  "controllers": [
    "urn:agent:sha256:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b"
  ],
  "status": "active",
  "created_at": "2026-03-24T17:00:00Z",
  "updated_at": "2026-03-24T17:00:00Z"
}
```

**Field definitions:**

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | REQUIRED | The agent's Agent ID (Section 3.2). MUST match `sha256(public_key_bytes)`. |
| `version` | integer | REQUIRED | Schema version. MUST be `1` for this specification. |
| `public_key` | string | REQUIRED | Base64url-encoded Ed25519 public key bytes (RFC 4648 §5, no padding). |
| `operator` | object | OPTIONAL | Human-readable info about the deploying operator. |
| `operator.name` | string | OPTIONAL | Display name of the operator. |
| `operator.url` | string | OPTIONAL | URL for the operator's homepage or documentation. |
| `controllers` | array | OPTIONAL | List of Agent IDs authorized to manage this agent. MAY be empty. |
| `status` | string | REQUIRED | One of: `active`, `suspended`, `revoked`. |
| `created_at` | string | REQUIRED | ISO 8601 UTC timestamp of record creation. |
| `updated_at` | string | REQUIRED | ISO 8601 UTC timestamp of last modification. |

### 4.2 Record Mutations

Any mutation to a Bot Record (status change, controller update) MUST be signed by the agent itself or by an authorized controller (Section 9). The mutation MUST include a `proof` field containing a JWS signature over the JCS-canonicalized updated record, as described in Section 6.

---

## 5. Grants

> **This is the central section of the AgentID protocol.** Everything else in this specification exists to make Grants possible and verifiable.

A Grant is a signed token issued by a principal to an agent. It authorizes the subject agent to act within the listed scopes, for the duration between `issued_at` and `expires_at`. Grants are the mechanism by which authority flows through a system of agents.

### 5.1 Grant Structure

```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "version": 1,
  "issuer": "urn:agent:sha256:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b",
  "subject": "urn:agent:sha256:3b4c2a1d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b",
  "scopes": [
    "read:github",
    "write:email"
  ],
  "issued_at": "2026-03-24T17:00:00Z",
  "expires_at": "2026-03-25T17:00:00Z",
  "proof": "eyJhbGciOiJFZERTQSJ9.eyJpZCI6ImY0N2FjMTBiLi4uIn0.signature_bytes_base64url"
}
```

**Field definitions:**

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | REQUIRED | A UUID v4 (RFC 4122) uniquely identifying this Grant. MUST be globally unique. |
| `version` | integer | REQUIRED | Schema version. MUST be `1` for this specification. |
| `issuer` | string | REQUIRED | Agent ID of the principal issuing this Grant. MUST hold all scopes being granted (or be a root authority). |
| `subject` | string | REQUIRED | Agent ID of the agent receiving this Grant. |
| `scopes` | array | REQUIRED | Non-empty array of scope strings (Section 5.2). |
| `issued_at` | string | REQUIRED | ISO 8601 UTC timestamp of issuance. |
| `expires_at` | string | REQUIRED | ISO 8601 UTC timestamp of expiry. MUST be after `issued_at`. |
| `proof` | string | REQUIRED | JWS signature over the JCS-canonicalized Grant payload (excluding `proof` field), signed by the issuer's private key. See Section 6. |

**Key properties of Grants:**

- **Non-transferable**: A subject agent MUST NOT present a Grant to another agent as if it were a Grant from itself to that agent. A subject can only re-grant authority it holds via explicit `delegate:` scopes (Section 5.6).
- **Verifiable offline**: Any party with the issuer's public key (obtained from their Bot Record) can verify a Grant's authenticity and validity without contacting any central service.
- **Time-bounded**: All Grants carry a mandatory `expires_at`. Implementations MUST NOT accept expired Grants. Short-lived Grants (hours to days) are RECOMMENDED over long-lived ones.
- **Scoped**: A Grant authorizes only the listed scopes. A subject MUST NOT act outside the union of scopes granted to it.

### 5.2 Scope Format

Scopes are strings in the format:

```
{verb}:{resource}
```

The `verb` describes the operation class; the `resource` describes the target system or resource. Both components are lowercase ASCII with hyphens permitted. Neither component may contain a colon except in the `delegate:` prefix form described below.

**Standard verbs (non-exhaustive):**

| Verb | Meaning |
|---|---|
| `read` | Read-only access to the resource |
| `write` | Write or mutate access to the resource |
| `invoke` | Call or trigger the resource (e.g., an API or model) |
| `admin` | Full administrative access to the resource |
| `delegate` | Authority to re-grant the following scope to sub-agents |

**Examples:**

```
read:github
write:email
invoke:openai
admin:agentid
read:postgres-prod
write:slack-channel-alerts
```

**Delegation scopes** use a three-part form:

```
delegate:{verb}:{resource}
```

For example: `delegate:read:github` grants the subject the ability to issue `read:github` grants to other agents. An agent MUST NOT issue a `delegate:` scope it does not itself hold.

Scope matching is exact string equality. Implementations MUST NOT implement wildcard or glob matching unless a future version of this specification explicitly defines a wildcard syntax.

### 5.3 Grant Issuance

To issue a Grant, the issuer MUST:

1. Construct the Grant object with all required fields populated (excluding `proof`).
2. Verify that it holds each scope listed in `scopes` — either as a root authority, or via a valid un-revoked Grant from a prior issuer that includes each scope (or the corresponding `delegate:` variant).
3. Set `expires_at` to a value no greater than the earliest `expires_at` among any Grants that delegated the issued scopes to the issuer. An issuer MUST NOT grant authority beyond the lifetime of the authority it received.
4. Compute the JCS-canonicalized JSON of the Grant object (without the `proof` field).
5. Sign the canonical bytes with the issuer's Ed25519 private key per Section 6.
6. Attach the resulting JWS as the `proof` field.

### 5.4 Grant Verification

A verifier MUST perform all of the following checks. Failure of any single check MUST result in rejection of the Grant.

**Step 1 — Structural validation**

- The Grant object MUST contain all REQUIRED fields.
- `version` MUST be `1`.
- `id` MUST be a valid UUID v4 (RFC 4122).
- `issued_at` and `expires_at` MUST be valid ISO 8601 UTC timestamps.
- `expires_at` MUST be strictly after `issued_at`.
- `scopes` MUST be a non-empty array of non-empty strings.
- Each scope string MUST conform to the format defined in Section 5.2.

**Step 2 — Expiry check**

- The current time MUST be before `expires_at`.
- The current time MUST be at or after `issued_at`.
- Implementations SHOULD allow a clock skew tolerance of no more than 60 seconds.

**Step 3 — Issuer resolution**

- Resolve the issuer's Bot Record by their Agent ID.
- The issuer's Bot Record MUST have `status` equal to `active`. Grants from `suspended` or `revoked` agents MUST be rejected.
- Derive the issuer's Agent ID from their Bot Record `public_key` field and verify it matches the `issuer` field in the Grant.

**Step 4 — Signature verification**

- Reconstruct the JCS-canonicalized JSON of the Grant object with the `proof` field removed.
- Verify the JWS `proof` signature against the issuer's public key (from their Bot Record) per Section 6.
- If verification fails, reject the Grant.

**Step 5 — Revocation check**

- Check whether a valid Revocation Record exists referencing this Grant's `id`.
- If a valid Revocation Record is found (see Section 5.5), the Grant MUST be rejected.

**Step 6 — Issuer authority check**

- For each scope in `scopes`, verify that the issuer holds that scope.
- Issuer authority is established either by: (a) being a designated root authority for the scope's resource namespace, or (b) holding a valid, un-revoked, non-expired Grant that includes the scope or `delegate:{scope}` from a principal that itself holds the scope.
- This check MAY be skipped if the verifier trusts the issuer as a root principal by out-of-band agreement.

**Step 7 — Subject check (contextual)**

- Verify the entity presenting the Grant is the `subject` agent. The subject MUST prove possession of the private key corresponding to their Agent ID (e.g., via a challenge-response or by signing the request payload with their key).

### 5.5 Grant Revocation

Grants expire naturally when the current time exceeds `expires_at`. No action is required for natural expiry.

For early revocation, the issuer MUST publish a signed Revocation Record:

```json
{
  "type": "revocation",
  "version": 1,
  "grant_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "issuer": "urn:agent:sha256:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b",
  "revoked_at": "2026-03-24T20:00:00Z",
  "reason": "Compromised agent",
  "proof": "eyJhbGciOiJFZERTQSJ9..."
}
```

**Field definitions:**

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | REQUIRED | MUST be the string `"revocation"`. |
| `version` | integer | REQUIRED | MUST be `1`. |
| `grant_id` | string | REQUIRED | The `id` of the Grant being revoked. |
| `issuer` | string | REQUIRED | Agent ID of the revoking principal. MUST match the `issuer` of the original Grant. |
| `revoked_at` | string | REQUIRED | ISO 8601 UTC timestamp of revocation. |
| `reason` | string | OPTIONAL | Human-readable reason for revocation. |
| `proof` | string | REQUIRED | JWS signature over the JCS-canonicalized Revocation Record (excluding `proof`), signed by the issuer's private key. |

A Revocation Record is valid only if:
- Its `proof` signature is valid under the issuer's public key.
- The `issuer` matches the `issuer` of the original Grant.

Revocation Records SHOULD be stored and propagated by all participating systems. Verifiers SHOULD maintain a local revocation cache. The mechanism for propagating Revocation Records between systems is outside the scope of this specification.

### 5.6 Delegation

An agent MAY re-grant authority it holds to another agent if and only if it possesses a `delegate:{verb}:{resource}` scope for each scope being re-granted.

**Example delegation chain:**

```
Root  ──[delegate:write:email]──► Operator Agent A
                                          │
                              [write:email Grant]
                                          │
                                          ▼
                                     Sub-agent B
```

In this example:
1. Root issues a Grant to Operator Agent A with scope `delegate:write:email`.
2. Operator Agent A issues a Grant to Sub-agent B with scope `write:email`.
3. A verifier checking Sub-agent B's Grant MUST verify the full chain: B←A←Root.

**Constraints on delegation:**

- An agent MUST NOT grant a scope it does not hold.
- An agent MUST NOT grant a `delegate:` scope unless it itself holds `delegate:delegate:{scope}` (i.e., explicit permission to further delegate the delegation right). Implementations SHOULD limit delegation depth to prevent unbounded chains.
- The `expires_at` of a delegated Grant MUST NOT exceed the `expires_at` of the Grant that authorized the delegation.
- Delegated Grants are automatically invalidated (and MUST be rejected) if any Grant in the chain above them is revoked or expires.

---

## 6. Proofs and Signatures

### 6.1 Signature Algorithm

All proofs in this specification — on Grants, Bot Record mutations, Attestations, Revocation Records, and Policies — MUST use the EdDSA signature algorithm with the Ed25519 curve as defined in RFC 8032.

No other signature algorithm is defined in this version of the specification.

### 6.2 Canonicalization

Before signing, the JSON object MUST be canonicalized using the JSON Canonicalization Scheme (JCS) as defined in RFC 8785. JCS produces a deterministic byte representation of a JSON value by:

1. Sorting object keys lexicographically by Unicode code point.
2. Removing all insignificant whitespace.
3. Representing numbers and strings in canonical form.

The `proof` field MUST be removed from the object before canonicalization. The canonical bytes are then signed. This ensures that the proof does not sign itself and that the signature is deterministic.

### 6.3 JWS Encoding

The proof is encoded as a JWS Compact Serialization (RFC 7515 §7.1):

```
BASE64URL(JWS Protected Header) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)
```

**JWS Protected Header:**

```json
{
  "alg": "EdDSA"
}
```

**JWS Payload:** The JCS-canonical bytes of the signed object (with `proof` removed), base64url-encoded.

**JWS Signature:** The 64-byte Ed25519 signature over the ASCII bytes `BASE64URL(header) || '.' || BASE64URL(payload)`, base64url-encoded (RFC 7515 §7.2.1).

Implementations MUST reject any proof with `alg` other than `"EdDSA"`.

---

## 7. Policies

A Policy defines an m-of-n threshold requirement for sensitive operations on an agent's record. Policies are OPTIONAL.

```json
{
  "agent_id": "urn:agent:sha256:3b4c2a1d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b",
  "operation": "key_rotation",
  "threshold": 2,
  "signers": [
    "urn:agent:sha256:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b",
    "urn:agent:sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
    "urn:agent:sha256:c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1"
  ],
  "version": 1
}
```

**Field definitions:**

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_id` | string | REQUIRED | The Agent ID this policy governs. |
| `operation` | string | REQUIRED | The operation requiring multi-party approval. Defined values: `key_rotation`, `status_change`, `controller_update`. |
| `threshold` | integer | REQUIRED | Minimum number of `signers` that MUST sign for the operation to be valid. MUST be ≥ 1 and ≤ `len(signers)`. |
| `signers` | array | REQUIRED | Array of Agent IDs eligible to provide signatures. MUST have at least `threshold` elements. |
| `version` | integer | REQUIRED | MUST be `1`. |

When a Policy is active, the operation it governs MUST collect `threshold` independent JWS signatures from distinct `signers` agents before the operation is applied. The mechanism for collecting and aggregating these signatures is implementation-defined.

---

## 8. Attestations

An Attestation is a signed statement one agent makes about another, asserting a specific claim. Attestations are OPTIONAL supporting evidence and do not themselves confer authority.

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "version": 1,
  "issuer": "urn:agent:sha256:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b",
  "subject": "urn:agent:sha256:3b4c2a1d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b",
  "claim": "capability:write:github",
  "issued_at": "2026-03-24T17:00:00Z",
  "expires_at": "2026-06-24T17:00:00Z",
  "proof": "eyJhbGciOiJFZERTQSJ9..."
}
```

**Field definitions:**

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | REQUIRED | UUID v4 (RFC 4122) uniquely identifying this Attestation. |
| `version` | integer | REQUIRED | MUST be `1`. |
| `issuer` | string | REQUIRED | Agent ID of the attesting agent. |
| `subject` | string | REQUIRED | Agent ID of the agent being attested about. |
| `claim` | string | REQUIRED | The claim being made, in the format `{namespace}:{value}`. Examples: `capability:write:github`, `audit:passed:soc2`, `identity:verified:kyc`. |
| `issued_at` | string | REQUIRED | ISO 8601 UTC timestamp of attestation issuance. |
| `expires_at` | string | OPTIONAL | ISO 8601 UTC timestamp of attestation expiry. If absent, the attestation does not expire. |
| `proof` | string | REQUIRED | JWS signature over the JCS-canonicalized Attestation (excluding `proof`), signed by the issuer's private key. |

**Verification of an Attestation** follows the same structural and signature steps as Grant verification (Section 5.4 Steps 1–4). Attestations do not require issuer authority checks (Step 6) — any agent MAY attest about any other agent, and relying parties determine how much weight to assign.

Attestations MUST NOT be used as a substitute for Grants. An Attestation that claims `capability:write:github` does not grant `write:github` authority; only a valid Grant does.

---

## 9. Controllers

A controller is an agent explicitly authorized in a subject's Bot Record to manage the subject's keys or record. The `controllers` array in the Bot Record lists the Agent IDs of all authorized controllers.

### 9.1 Controller Authorization

A controller relationship is established when the `controllers` field of a Bot Record is set to include the controller's Agent ID. This mutation MUST be signed by the subject agent itself (or by an existing controller per the policy, if one is set).

### 9.2 Permitted Controller Operations

A controller MAY perform the following operations on behalf of the subject agent:

- Update the Bot Record's `operator` field.
- Add or remove controllers (subject to Policy if one is set).
- Change the agent's `status` from `active` to `suspended`, or from `suspended` to `active`.
- Perform key rotation (replacing `public_key` with a new keypair's public key and updating `id` accordingly, producing a new Agent ID).

A controller MUST NOT:

- Issue Grants on behalf of the subject agent. Only the subject's own private key may sign Grants.
- Perform key rotation without updating the Agent ID consistently.
- Set status to `revoked` without explicit authorization from a root principal or Policy.

### 9.3 Hierarchical Trust

Controllers enable hierarchical trust structures. An organization MAY designate an "org-level" agent that controls multiple "department-level" agents, which in turn control "task-level" agents:

```
Org Agent (controller)
    ├── Dept Agent A (controller → task agents)
    │       ├── Task Agent 1
    │       └── Task Agent 2
    └── Dept Agent B
            └── Task Agent 3
```

Each agent in this hierarchy holds its own keypair and Agent ID. Authority flows through Grants (Section 5), not through the controller relationship. The controller relationship governs record management only.

---

## 10. Agent Lifecycle

An agent's `status` field in its Bot Record MAY take one of three values:

| Status | Description |
|---|---|
| `active` | The agent is operating normally. Grants issued by this agent are valid subject to other checks. |
| `suspended` | The agent's operations are temporarily halted. Grants issued by a suspended agent MUST be rejected. |
| `revoked` | The agent is permanently decommissioned. Grants issued by a revoked agent MUST be rejected. This transition is irreversible. |

**Permitted transitions:**

```
active ──► suspended ──► active   (suspension is reversible)
active ──► revoked              (revocation is irreversible)
suspended ──► revoked           (revocation from suspension is permitted)
```

Status changes MUST be recorded as signed mutations to the Bot Record (Section 4.2). The `updated_at` field MUST be updated to the current time on any status change.

Verifiers MUST re-check an issuer's status at verification time. A cached Bot Record SHOULD NOT be used without revalidation if the cache is older than a locally configured maximum staleness (RECOMMENDED: no more than 5 minutes).

---

## 11. Security Considerations

### 11.1 Key Management

Private keys are the root of trust for all AgentID operations. Implementations MUST:

- Store private keys only in the local keystore with restrictive file permissions (Section 3.3).
- Never transmit private keys over any network interface.
- Never include private keys in logs, error messages, or diagnostic output.
- Zeroize private key memory after use where the runtime environment supports it.

### 11.2 Grant Lifetime

Long-lived Grants increase the window of opportunity for a compromised agent to cause harm. Implementations SHOULD issue Grants with the shortest practical lifetime. Grants longer than 24 hours SHOULD require explicit operator justification.

Implementations SHOULD prefer short-lived Grants with automated renewal over long-lived Grants with manual revocation.

### 11.3 Delegation Depth

Unbounded delegation chains can obscure the true origin of authority and complicate revocation. Implementations SHOULD enforce a maximum delegation depth (RECOMMENDED: no greater than 5 hops). Verifiers MUST reject delegation chains that exceed the locally configured maximum.

### 11.4 Issuer Status Checking

A Grant that was valid at issuance time becomes invalid if the issuer is later suspended or revoked. Verifiers MUST check the current issuer status at verification time, not only at the time the Grant was first received.

### 11.5 Agent ID Stability

Agent IDs are derived from public keys. Key rotation produces a new Agent ID. Any Grants issued under the old Agent ID remain bound to the old Agent ID and MUST NOT be transferred to the new one. Operators MUST re-issue Grants after key rotation.

### 11.6 Replay Attacks

The `id` field (UUID v4) on Grants enables replay detection. Verifiers SHOULD maintain a cache of recently seen Grant IDs and reject any Grant whose ID has been presented before within its validity window.

### 11.7 Clock Skew

Implementations SHOULD allow a clock skew tolerance of no more than 60 seconds when evaluating `issued_at` and `expires_at`. Larger tolerances increase the risk of accepting expired or premature Grants.

### 11.8 Public Key Resolution

The `public_key` field in a Bot Record is the root credential for verifying all signed artifacts from that agent. Implementations MUST obtain Bot Records from trustworthy sources (signed records or trusted local cache). An attacker who can substitute a fraudulent `public_key` can forge any Grant from that agent.

---

## 12. References

### Normative References

| Reference | Document |
|---|---|
| RFC 2119 | Key words for use in RFCs to Indicate Requirement Levels. Bradner, 1997. |
| RFC 4122 | A Universally Unique IDentifier (UUID) URN Namespace. Leach et al., 2005. |
| RFC 4648 | The Base16, Base32, and Base64 Data Encodings. Josefsson, 2006. |
| RFC 6234 | US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF). Eastlake, Hansen, 2011. |
| RFC 7515 | JSON Web Signature (JWS). Jones et al., 2015. |
| RFC 8032 | Edwards-Curve Digital Signature Algorithm (EdDSA). Josefsson, Liusvaara, 2017. |
| RFC 8785 | JSON Canonicalization Scheme (JCS). Rundgren et al., 2020. |

### Informative References

| Reference | Document |
|---|---|
| BIP-39 | Mnemonic code for generating deterministic keys. Palatinus et al., 2013. https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki |
| SLIP-10 | Universal private key derivation from master private key. SatoshiLabs, 2016. https://github.com/satoshilabs/slips/blob/master/slip-0010.md |

---

*End of AgentID Protocol Specification v1.0 — Draft*
