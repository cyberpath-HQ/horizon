# Horizon Implementation Plan

## Cyberpath Horizon - CMDB and Asset Inventory System

**Version:** 4.0.0  
**Status:** Planning Phase  
**Last Updated:** 2026-01-30

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Introduction and Vision](#introduction-and-vision)
3. [Architecture Overview](#architecture-overview)
4. [Core Components](#core-components)
5. [Database Schema Design](#database-schema-design)
6. [API Design Specification](#api-design-specification)
7. [Agent Architecture and Design](#agent-architecture-and-design)
8. [Feature Specifications](#feature-specifications)
9. [Security Framework](#security-framework)
10. [Configuration Management](#configuration-management)
11. [Docker Deployment](#docker-deployment)
12. [Implementation Phases](#implementation-phases)
13. [Technical Decisions and Justifications](#technical-decisions-and-justifications)
14. [Action Items and Roadmap](#action-items-and-roadmap)

---

## 1. Executive Summary

Horizon is a self-hostable Configuration Management Database (CMDB) system designed to provide comprehensive visibility
into an organization's IT infrastructure. The system combines a powerful backend with a lightweight, cross-platform
agent to automatically discover and inventory hardware assets, software installations, network configurations, and
security-relevant information.

The platform encompasses twelve core functional areas: asset inventory management, network flow mapping, vendor
relationship tracking, vulnerability monitoring, security configuration assessment, configuration management, software
version tracking, patch management, AI-powered insights, data interoperability, comprehensive notification systems, and
Business Impact Analysis (BIA).

---

## 2. Introduction and Vision

### 2.1 Purpose and Scope

Horizon provides organizations with complete control over their IT asset data through a self-hostable solution with no
licensing costs and complete data ownership. The system supports organizations ranging from small businesses to
enterprises managing thousands of distributed systems.

### 2.2 Strategic Goals

- **Comprehensiveness**: Capture all information relevant to IT asset management
- **Automation**: Lightweight agent collection with minimal configuration
- **Flexibility**: Support both automated and manual data entry
- **Integrity**: Complete audit trails and data quality assessment
- **Intelligence**: AI-powered pattern recognition and anomaly detection via inference providers
- **Accessibility**: Multiple interfaces including web and desktop applications

---

## 3. Architecture Overview

### 3.1 High-Level Architecture

Three-tier architecture with presentation layer (web/desktop), business logic layer (API server with AI inference), and
data persistence layer (PostgreSQL and Redis).

### 3.2 Technology Stack Selection

**Version Policy:** All components use the latest stable or nightly versions available. Rust version requirement:
**minimum 1.94.0-nightly**.

**Core Crates Selection:**

| Category        | Primary Crates                          | Purpose                            |
| --------------- | --------------------------------------- | ---------------------------------- |
| Web Framework   | **axum** , **tokio** , **tower**        | REST API server with async support |
| Database ORM    | **sea-orm** , **sqlx**                  | Entity management with migrations  |
| Database Driver | **tokio-postgres** , **postgres-types** | PostgreSQL driver                  |
| Redis           | **redis-rs**                            | Caching and session management     |
| Serialization   | **serde** , **serde_json** , **prost**  | JSON and Protocol Buffer handling  |
| Error Handling  | **thiserror** , **anyhow**              | Error types and propagation        |
| Logging         | **tracing** , **tracing-subscriber**    | Structured logging                 |
| Validation      | **validator** , **regex**               | Input validation                   |
| Date/Time       | **chrono**                              | Date and time handling             |
| CSV/Excel       | **csv** , **calamine**                  | Import/export file handling        |
| Compression     | **flate2** , **zstd**                   | Message compression                |

**Encryption Stack (RustCrypto - Best Security Standards):**

| Operation            | Crate                    | Algorithm             | Constant-Time | Notes                              |
| -------------------- | ------------------------ | --------------------- | ------------- | ---------------------------------- |
| Password Hashing     | **argon2**               | Argon2id              | Yes           | Gold standard for password hashing |
| Symmetric Encryption | **chacha20poly1305**     | XChaCha20-Poly1305    | Yes           | Preferred default encryption       |
| Hashing              | **blake3**               | BLAKE3                | Yes           | Faster than SHA-2/3, constant-time |
| Backup Hashing       | **sha3**                 | SHA3-256/512          | Yes           | NIST standard alternative          |
| MAC                  | **hmac**                 | HMAC-BLAKE3/HMAC-SHA3 | Yes           | Message authentication             |
| Digital Signatures   | **ed25519**              | Ed25519               | Yes           | Modern elliptic curve signatures   |
| Key Exchange         | **x25519**               | X25519                | Yes           | ECDH key exchange                  |
| Key Derivation       | **argon2**               | Argon2id              | Yes           | Primary key derivation             |
| Random               | **rand** + **getrandom** | CSPRNG                | Yes           | OS-level random                    |
| Memory Clearing      | **zeroize**              | N/A                   | N/A           | Explicit secure memory wiping      |

**Why These Algorithms:**

1. **Argon2id** - Winner of the Password Hashing Competition, resistant to GPU/ASIC attacks
2. **XChaCha20-Poly1305** - Constant-time, no timing attacks, excellent for all platforms
3. **BLAKE3** - Faster than SHA-2/3, SIMD-optimized, cryptographically secure
4. **Ed25519** - Modern, high-security elliptic curve signature scheme
5. **X25519** - Modern ECDH for forward secrecy

**External AI Provider Support (Inference-First):**

AI capabilities are provided primarily through inference providers. Local ML models are only used when strictly
necessary and are pre-trained at build time.

| Provider              | Type             | Integration Method | Description                              |
| --------------------- | ---------------- | ------------------ | ---------------------------------------- |
| **OpenAI**            | Remote Inference | REST API           | GPT-4 and related models                 |
| **Anthropic**         | Remote Inference | REST API           | Claude models                            |
| **GitHub Copilot**    | Remote Inference | REST API           | Copilot Chat API                         |
| **OpenAI Compatible** | Remote Inference | REST API           | Self-hosted compatible APIs              |
| **opencode**          | CLI Inference    | Subprocess         | Local AI CLI tool                        |
| **copilot-cli**       | CLI Inference    | Subprocess         | GitHub Copilot CLI                       |
| **ollama**            | Local Inference  | REST API           | Local model serving (if strictly needed) |

**Local ML Models (Only If Strictly Needed):**

| Crate       | Purpose                          | Use Case                                  |
| ----------- | -------------------------------- | ----------------------------------------- |
| **candle**  | Pre-trained ONNX model execution | Anomaly detection with pre-built models   |
| **ndarray** | Tensor operations                | Pre-trained model input/output processing |

Local models are pre-trained at build time and embedded in the binary. No runtime model training occurs.

---

## 4. Core Components

### 4.1 API Server

| Module         | Primary Crates                                                         | Purpose                  |
| -------------- | ---------------------------------------------------------------------- | ------------------------ |
| Authentication | **axum**, **jsonwebtoken**, **argon2**, **totp**                       | User login, token, MFA   |
| Assets         | **sea-orm**, **sqlx**, **serde**                                       | CRUD operations          |
| Agents         | **rustls**, **webpki**, **x509-parser**, **rcgen**                     | Agent registration       |
| AI Providers   | **reqwest**, **async-openai**, **anthropic**, **tokio::process**       | Remote and CLI AI        |
| Encryption     | **chacha20poly1305**, **blake3**, **ed25519**, **argon2**, **zeroize** | Cryptographic operations |
| Notifications  | **lettre**, **reqwest**, **hmac**                                      | Email, webhooks          |

### 4.2 Database Layer

PostgreSQL with Redis for caching.

### 4.3 Agent Communication Service

mTLS with server-issued certificates and bidirectional Ed25519 message signing.

### 4.4 Background Processing System

Work queue architecture with async job processing.

### 4.5 AI Inference Service

Multi-provider inference architecture with CLI and remote API support.

### 4.6 Notification Service

Multi-channel notification delivery.

### 4.7 Import/Export Service

CSV, Excel, JSON, XML data interoperability.

---

## 5. Database Schema Design

### 5.1 Core Entity Model

Asset types, assets, relationships, and history tables.

### 5.2 Business Impact Analysis (BIA) Model

Business functions, critical systems, dependencies, recovery contacts.

### 5.3 Vulnerability Model

Multi-source vulnerability tracking (CVE, pentest, red team).

### 5.4 Security Configuration and Baseline Model

Baselines, rules, violations with AI analysis.

### 5.5 Notification Model

Triggers, subscriptions, webhook endpoints.

---

## 6. API Design Specification

### 6.1 RESTful API Architecture

Standard REST API with hierarchical resource organization.

### 6.2 Authentication and Authorization

JWT-based authentication with RBAC permissions.

### 6.3 Import/Export Endpoints

All data types support CSV, XLSX, JSON, XML formats.

### 6.4 AI Analysis Endpoints

Multi-provider AI inference configuration and execution.

### 6.5 Configuration Management Endpoints

Dynamic configuration via API.

---

## 7. Agent Architecture and Design

### 7.1 Agent Overview

Lightweight agent (<50MB memory) for cross-platform data collection.

### 7.2 Agent Components and Crates

| Category                | Crates                                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------------------------ |
| Runtime                 | **tokio** , **async-trait**                                                                            |
| Database                | **sqlx** , **rusqlite**                                                                                |
| Communication           | **reqwest** , **rustls** , **prost** , **flate2**                                                      |
| Encryption (RustCrypto) | **chacha20poly1305**, **blake3**, **hmac**, **ed25519**, **x25519**, **argon2**, **zeroize**, **rand** |
| System Info             | **sysinfo** , **heim** , **pnet**                                                                      |
| Files                   | **notify** , **walkdir**                                                                               |

### 7.3 Communication Protocol Security

**Security Layers:**

1. **mTLS with Server-Issuued Certificates**
   - Server operates as Certificate Authority using **rcgen**
   - Agents generate X25519/Ed25519 key pairs and submit CSRs
   - Server signs certificates with server CA
   - Automatic certificate renewal before expiration

2. **Message Signing**
   - All messages signed with agent's Ed25519 private key
   - Server verifies signatures using agent certificate public key
   - Server responses signed with server's Ed25519 private key
   - Uses constant-time Ed25519 verification

3. **Encryption**
   - All messages encrypted with ChaCha20-Poly1305
   - Forward secrecy through X25519 key exchange
   - All cryptographic operations use constant-time implementations
   - Password hashing with Argon2id

### 7.4 Collection Modules

Hardware, OS, software, network, processes, security, configuration.

### 7.5 Desktop Agent (Tauri)

Multi-server profiles, offline mode, system tray, native integration.

---

## 8. Feature Specifications

### 8.1 Asset Inventory Management

Comprehensive tracking with AI-powered classification.

### 8.2 Network Flow Mapping

Traffic visibility with behavioral baselining.

### 8.3 Vulnerability Management

Multi-source vulnerability tracking.

### 8.4 Security Configuration Assessment

CIS, DISA STIG, NIST CSF benchmarks.

### 8.5 Business Impact Analysis (BIA)

Critical system mapping with dependencies.

### 8.6 Notification System

Multi-channel notifications.

---

## 9. Security Framework

### 9.1 Encryption Standards (RustCrypto)

All encryption uses the highest security standards:

```rust
// Password Hashing with Argon2id (best practice)
use argon2::{Argon2, PasswordHash, PasswordVerifier};

let argon2 = Argon2::default();
let parsed = PasswordHash::new(password_hash)?;
argon2.verify_password(password, &parsed)?;

// Symmetric Encryption with ChaCha20-Poly1305
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, AeadInPlace};

let key = Key::from_slice(key_bytes);
let cipher = ChaCha20Poly1305::new(key);
let nonce = Nonce::from_slice(nonce_bytes);
cipher.encrypt(nonce, plaintext)

// Hashing with BLAKE3 (faster than SHA-3)
use blake3::Hasher;

let mut hasher = Hasher::new();
hasher.update(data);
let hash = hasher.finalize();

// MAC with HMAC-BLAKE3
use hmac::{Hmac, Mac};
use blake3::BLAKE3_OUTPUT_LEN;

let mut mac = Hmac::<blake3::Blake3>::new_from_slice(key)?;
mac.update(data);
let result = mac.finalize();

// Digital Signatures with Ed25519
use ed25519_dalek::{SigningKey, VerifyingKey, Signature};
use rand::rngs::OsRng;

let signing_key = SigningKey::generate(&mut OsRng);
let signature = signing_key.sign(message);

// Key Exchange with X25519
use x25519_dalek::{Ephemeral, PublicKey};

let alice = Ephemeral::generate();
let bob_public = PublicKey::from(bob_bytes);
let shared_secret = alice.diffie_hellman(&bob_public);
```

**Security Algorithm Selection Justification:**

| Use Case               | Algorithm          | Justification                                                |
| ---------------------- | ------------------ | ------------------------------------------------------------ |
| Password Storage       | Argon2id           | Winner of Password Hashing Competition, GPU/ASIC resistant   |
| Message Encryption     | XChaCha20-Poly1305 | Constant-time, no timing attacks, excellent performance      |
| General Hashing        | BLAKE3             | Faster than SHA-2/3, SIMD-optimized, cryptographically sound |
| Backup/Archive Hashing | SHA3-256/512       | NIST standard, different design from BLAKE3                  |
| Message Signing        | Ed25519            | Modern elliptic curve, high security, constant-time          |
| Key Exchange           | X25519             | Modern ECDH, constant-time scalar multiplication             |
| Key Derivation         | Argon2id           | Same as password hashing for consistency                     |
| Random Generation      | OS CSPRNG          | /dev/urandom or equivalent                                   |

### 9.2 Authentication Methods

- Password with Argon2id hashing
- SSO (SAML 2.0)
- OpenID Connect
- API keys
- JWT tokens
- TOTP MFA
- WebAuthn/FIDO2

### 9.3 Data Protection

- Encryption at rest: XChaCha20-Poly1305 + BLAKE3 authentication
- Encryption in transit: TLS 1.3
- Sensitive fields: Additional Argon2id-based encryption

### 9.4 Agent Security

- mTLS with server-issued certificates
- Ed25519 message signing
- XChaCha20-Poly1305 encryption
- Certificate renewal
- Signed installation packages

---

## 10. Configuration Management

### 10.1 Configuration Architecture

Three-level configuration hierarchy:

1. **Runtime API Configuration** - Changes applied immediately via API
2. **Environment Variables** - Container and deployment-time configuration
3. **Configuration Files** - Installation script configuration

All runtime changes are immediately applied and persisted.

### 10.2 Environment Variables

All configuration exposed via `HORIZON_*` environment variables.

### 10.3 Runtime Configuration API

```yaml
GET    /api/v1/system/config PUT    /api/v1/system/config/{key} PATCH  /api/v1/system/config
POST   /api/v1/system/config/validate
```

### 10.4 AI Provider Configuration

**Remote Inference Providers:**

```yaml
ai:
  providers:
    openai:
      enabled: true
      api_key: ${OPENAI_API_KEY}
      endpoint: "https://api.openai.com/v1"
      model: "gpt-4o"
    anthropic:
      enabled: true
      api_key: ${ANTHROPIC_API_KEY}
      endpoint: "https://api.anthropic.com"
      model: "claude-sonnet-4-20250514"
    github_copilot:
      enabled: true
      token: ${GITHUB_COPILOT_TOKEN}
```

**CLI Inference Providers:**

```yaml
ai:
  providers:
    opencode:
      enabled: true
      cli_path: "/usr/local/bin/opencode"
      timeout_seconds: 60
    copilot_cli:
      enabled: true
      cli_path: "/usr/local/bin/github-copilot"
      timeout_seconds: 60
```

**Local Models (Only If Strictly Needed):**

```yaml
ai:
  local_models:
    anomaly_detection:
      enabled: false # Disabled by default
      model_path: "/usr/share/horizon/models/anomaly.onnx"
      threshold: 0.85
```

---

## 11. Docker Deployment

### 11.1 Docker Images

| Image                | Base Image               | Description         |
| -------------------- | ------------------------ | ------------------- |
| `horizon/server`     | `rust:1.94-nightly-slim` | Latest Rust nightly |
| `horizon/worker`     | `rust:1.94-nightly-slim` | Background workers  |
| `horizon/agent`      | `alpine:3.21`            | Lightweight agent   |
| `horizon/web`        | `node:22-alpine`         | Latest Node.js      |
| `horizon/all-in-one` | `debian:bookworm-slim`   | Combined services   |

### 11.2 Docker Compose

Complete multi-service deployment with PostgreSQL, Redis, server, worker, web.

### 11.3 Kubernetes

Full manifests with ConfigMap, Secret, Deployment, Service.

### 11.4 Helm Chart

Complete Helm chart for Kubernetes deployment.

---

## 12. Implementation Phases

### 12.1 Phase 1: Foundation (Weeks 1-12)

**Deliverables:**

- Project infrastructure with latest Rust nightly (1.94.0+)
- Database foundation with Sea-ORM
- API foundation with Axum
- Web interface with React
- Docker images build successfully

**Crates:**

- All crates at latest versions
- Rust 1.94.0-nightly minimum

**Success Criteria:**

- Functional API and web UI
- Docker images build

### 12.2 Phase 2: Agent and Discovery (Weeks 13-24)

**Deliverables:**

- Agent core with cross-platform support
- Data collection modules
- Secure communication with RustCrypto best standards
- Server integration

**Encryption (RustCrypto Best Standards):**

- **argon2** for password hashing
- **chacha20poly1305** for encryption
- **blake3** for hashing
- **ed25519** for signatures
- **x25519** for key exchange
- **zeroize** for memory clearing

**Success Criteria:**

- Agent with RustCrypto encryption
- mTLS communication

### 12.3 Phase 3: Software, Configuration, and BIA (Weeks 25-36)

**Deliverables:**

- Software management
- Configuration management
- Security baselines
- Business Impact Analysis

**Success Criteria:**

- Complete tracking capabilities

### 12.4 Phase 4: Vulnerability and Notification Systems (Weeks 37-48)

**Deliverables:**

- Vulnerability framework
- Penetration test integration
- Red team integration
- Notification system

**Success Criteria:**

- Comprehensive vulnerability management

### 12.5 Phase 5: AI, Import/Export, and Desktop App (Weeks 49-60)

**Deliverables:**

- AI inference service with providers
- Import/export system
- Desktop application

**AI Strategy:**

- **Remote Inference First**: OpenAI, Anthropic, GitHub Copilot APIs
- **CLI Inference**: opencode, copilot-cli
- **Local Models Only If Strictly Needed**: Pre-trained ONNX models at build time

**Crates:**

- **reqwest**, **async-openai**, **anthropic** for remote APIs
- **tokio::process** for CLI tools
- **candle**, **onnxruntime** only if strictly needed for local models

**Success Criteria:**

- AI inference via providers (remote + CLI)
- Desktop application

### 12.6 Phase 6: Configuration, Docker, Production (Weeks 61-72)

**Deliverables:**

- Configuration management system
- Docker/K8s deployment
- Production hardening

**Success Criteria:**

- Production-ready deployment

---

## 13. Technical Decisions and Justifications

### 13.1 Encryption: Best Security Standards with RustCrypto

**Decision:** Use RustCrypto with the highest security algorithms.

| Operation            | Algorithm         | Crate                | Justification                       |
| -------------------- | ----------------- | -------------------- | ----------------------------------- |
| Password Hashing     | Argon2id          | **argon2**           | Gold standard, GPU/ASIC resistant   |
| Symmetric Encryption | ChaCha20-Poly1305 | **chacha20poly1305** | Constant-time, no timing attacks    |
| Hashing              | BLAKE3            | **blake3**           | Faster than SHA-2/3, SIMD-optimized |
| Backup Hashing       | SHA3              | **sha3**             | NIST standard alternative           |
| MAC                  | HMAC-BLAKE3       | **hmac**             | Message authentication              |
| Signatures           | Ed25519           | **ed25519**          | Modern high-security signatures     |
| Key Exchange         | X25519            | **x25519**           | Modern ECDH                         |
| Key Derivation       | Argon2id          | **argon2**           | Consistent with password hashing    |

**Why Not Alternatives:**

- PBKDF2 rejected: Lower security than Argon2id
- AES-GCM rejected: ChaCha20-Poly1305 is constant-time on all platforms
- SHA-256 rejected: BLAKE3 is faster and equally secure

### 13.2 AI: Inference-First Strategy

**Decision:** AI is provided through inference providers (remote APIs and CLI tools). Local ML models are only used when
strictly necessary.

**Justification:**

1. **Remote Inference (OpenAI, Anthropic, Copilot)**: State-of-the-art models, always up-to-date
2. **CLI Inference (opencode, copilot-cli)**: Local execution, data sovereignty
3. **Local Models Only If Strictly Needed**: Pre-trained at build time, embedded in binary

**Local Models Policy:**

- Disabled by default
- Only enabled when provider-based inference is not feasible
- Pre-trained models embedded at build time
- No runtime model training or downloading

### 13.3 Version Policy

**Decision:** Always use the latest available versions.

- **Rust**: 1.94.0-nightly minimum, always update to latest nightly
- **Docker Images**: Latest tags, rebuild regularly
- **Crates**: Latest versions via `cargo update`
- **Node.js**: Latest LTS or current
- **PostgreSQL**: Latest stable
- **Redis**: Latest stable

---

## 14. Action Items and Roadmap

### 14.1 Immediate Action Items

1. **Repository Setup**: Git, Docker, CI/CD with latest versions
2. **Development Environment**: Docker Compose, Rust 1.94.0-nightly
3. **CI/CD Pipeline**: GitHub Actions with nightly Rust
4. **API Specification**: OpenAPI v1
5. **Database Schema**: Core entities
6. **Security Review**: RustCrypto implementation review
7. **Docker Setup**: Initial Dockerfiles

### 14.2 Success Criteria Summary

| Phase   | Key Success Criteria                                           |
| ------- | -------------------------------------------------------------- |
| Phase 1 | Latest Rust (1.94.0+), functional API/web UI, Docker builds    |
| Phase 2 | RustCrypto best security (Argon2id, ChaCha20, BLAKE3, Ed25519) |
| Phase 3 | Software, configuration, BIA tracking                          |
| Phase 4 | Vulnerability management, notifications                        |
| Phase 5 | AI inference (providers first, CLI, local only if needed)      |
| Phase 6 | Configuration management, Docker/K8s, production ready         |

---

## Appendix A: Glossary

| Term      | Definition                               |
| --------- | ---------------------------------------- |
| **Agent** | Lightweight software for data collection |
| **Asset** | Any discrete IT infrastructure component |
| **BIA**   | Business Impact Analysis                 |
| **CVE**   | Common Vulnerabilities and Exposures     |
| **mTLS**  | Mutual TLS authentication                |
| **CMDB**  | Configuration Management Database        |

---

## Appendix B: Technology Stack Reference

**Backend Stack:**

- Language: Rust 1.94.0-nightly (minimum, always latest)
- Web Framework: Axum
- ORM: Sea-ORM
- Async Runtime: Tokio
- Database: PostgreSQL (latest stable)
- Cache: Redis (latest stable)
- Serialization: Protocol Buffers, JSON

**Encryption (RustCrypto Best Standards):**

- argon2, chacha20poly1305, blake3, sha3
- hmac, ed25519, x25519
- rand, getrandom, zeroize

**AI Providers (Inference-First):**

- Remote: OpenAI, Anthropic, GitHub Copilot
- CLI: opencode, copilot-cli
- Local: ONNX only if strictly needed

**Frontend Stack:**

- React , TypeScript , Vite
- Tailwind CSS , shadcn/ui

**Desktop Stack:**

- Tauri , React

**Deployment:**

- Docker , Docker Compose
- Kubernetes , Helm

---

_This implementation plan uses the highest security standards and latest technology versions. All cryptographic
operations use RustCrypto with Argon2id, ChaCha20-Poly1305, BLAKE3, Ed25519, and X25519. AI is provided through
inference providers with local models only when strictly necessary._
