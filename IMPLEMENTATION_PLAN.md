# Horizon Implementation Plan

## Cyberpath Horizon - CMDB and Asset Inventory System

**Version:** 3.0.0  
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
security-relevant information. Horizon addresses the critical need for organizations to maintain accurate, real-time
records of their technology assets while providing the flexibility for manual data entry and modification.

The platform encompasses twelve core functional areas: asset inventory management, network flow mapping, vendor
relationship tracking, vulnerability monitoring, security configuration assessment, configuration management, software
version tracking, patch management, AI-powered insights, data interoperability, comprehensive notification systems, and
Business Impact Analysis (BIA). Each module has been designed to operate independently while contributing to a unified,
interconnected view of the IT environment. The system prioritizes data integrity through comprehensive audit trails,
supports both automated and manual data entry workflows, and provides extensible mechanisms for future enhancements.

This implementation plan provides a detailed roadmap for building Horizon, including architectural decisions, technology
selections justified by specific requirements, database schema designs that support complex relationships and queries,
API specifications that enable both frontend consumption and third-party integrations, agent designs that minimize
resource consumption while maximizing data collection capabilities, and comprehensive development phases with specific
crates and implementation details.

---

## 2. Introduction and Vision

### 2.1 Purpose and Scope

The modern IT environment presents significant challenges for organizations attempting to maintain accurate inventories
of their technology assets. Traditional spreadsheet-based approaches quickly become unmanageable as infrastructure
grows, while enterprise-grade CMDB solutions often introduce prohibitive costs, excessive complexity, or vendor lock-in.
Horizon exists to fill the gap between these extremes, providing a capable, self-hostable solution that gives
organizations complete control over their data while eliminating ongoing licensing costs and dependency on external
service providers.

### 2.2 Strategic Goals

Horizon pursues six strategic goals that guide all implementation decisions.

- **comprehensiveness**: capturing all information relevant to IT asset management.
- **automation**: lightweight agent collection with minimal configuration.
- **flexibility**: supporting both automated and manual data entry.
- **integrity**: complete audit trails and data quality assessment.
- **intelligence**: AI-powered pattern recognition and anomaly detection.
- **accessibility**: multiple interfaces including web and desktop applications.

---

## 3. Architecture Overview

### 3.1 High-Level Architecture

Horizon employs a three-tier architecture with presentation layer (web and desktop applications), business logic layer
(API server with AI inference), and data persistence layer (PostgreSQL and Redis).

### 3.2 Technology Stack Selection

**Core Crates Selection:**

| Category        | Primary Crates                         | Purpose                            |
| --------------- | -------------------------------------- | ---------------------------------- |
| Web Framework   | **axum**, **tokio**, **tower**         | REST API server with async support |
| Database ORM    | **sea-orm**, **sqlx**                  | Entity management with migrations  |
| Database Driver | **tokio-postgres**, **postgres-types** | PostgreSQL driver                  |
| Redis           | **redis-rs**                           | Caching and session management     |
| Serialization   | **serde**, **serde_json**, **prost**   | JSON and Protocol Buffer handling  |
| Error Handling  | **thiserror**, **anyhow**              | Error types and propagation        |
| Logging         | **tracing**, **tracing-subscriber**    | Structured logging                 |
| Validation      | **validator**, **regex**               | Input validation                   |
| Date/Time       | **chrono**                             | Date and time handling             |
| CSV/Excel       | **csv**, **calamine**                  | Import/export file handling        |
| Compression     | **flate2**, **zstd**                   | Message compression                |

**AI/ML Stack:**

| Crate           | Purpose                                      |
| --------------- | -------------------------------------------- |
| **candle**      | Rust-native ML framework for local inference |
| **candle-nn**   | Neural network building blocks               |
| **tokenizers**  | Hugging Face tokenizers for NLP tasks        |
| **onnxruntime** | For running pre-trained ONNX models          |
| **ndarray**     | Numerical array operations                   |
| **linfa**       | Machine learning algorithms in Rust          |

**External AI Provider Support:**

| Provider           | Integration Method   | Crate                         |
| ------------------ | -------------------- | ----------------------------- |
| **OpenAI**         | REST API with OAuth  | **reqwest**, **async-openai** |
| **Anthropic**      | REST API             | **reqwest**, **anthropic**    |
| **GitHub Copilot** | REST API             | **reqwest**, **copilot-api**  |
| **Local CLI**      | Subprocess execution | **tokio::process**            |

**Encryption Stack (RustCrypto):**

| Crate                | Purpose                      | Constant-Time       |
| -------------------- | ---------------------------- | ------------------- |
| **aes-gcm**          | AES-256-GCM encryption       | Yes                 |
| **chacha20poly1305** | ChaCha20-Poly1305 encryption | Yes                 |
| **sha2**             | SHA-256/512 hashing          | Yes                 |
| **hmac**             | HMAC-SHA256/512              | Yes                 |
| **pbkdf2**           | PBKDF2 key derivation        | Yes (constant-time) |
| **scrypt**           | Scrypt key derivation        | Yes                 |
| **ed25519**          | Ed25519 signatures           | Yes                 |
| **x25519**           | X25519 key exchange          | Yes                 |
| **zeroize**          | Secure memory clearing       | N/A                 |
| **rand**             | Cryptographic random         | CSPRNG              |

---

## 4. Core Components

### 4.1 API Server

The API server handles all client requests, coordinates background tasks, and serves as the authoritative source for
asset information.

| Module          | Primary Crates                                                   | Purpose                                    |
| --------------- | ---------------------------------------------------------------- | ------------------------------------------ |
| Authentication  | **axum**, **jsonwebtoken**, **bcrypt**, **totp**                 | User login, token issuance, MFA            |
| Assets          | **sea-orm**, **sqlx**, **serde**                                 | CRUD operations for assets                 |
| Agents          | **rustls**, **webpki**, **x509-parser**, **rcgen**               | Agent registration, certificate management |
| Vulnerabilities | **sqlx**, **reqwest**, **quick-xml**                             | CVE synchronization                        |
| AI Providers    | **reqwest**, **async-openai**, **anthropic**, **tokio::process** | Remote and local AI                        |
| Encryption      | **aes-gcm**, **sha2**, **hmac**, **ed25519**, **zeroize**        | Cryptographic operations                   |
| Notifications   | **lettre**, **reqwest**, **hmac**                                | Email, webhook, notification dispatch      |
| Configuration   | **serde_yaml**, **toml-rs**, **figment**                         | Configuration management                   |

### 4.2 Database Layer

PostgreSQL with Redis for caching. Key extensions: pg_trgm, pgcrypto, hstore.

### 4.3 Agent Communication Service

Agent communication uses mTLS with server-issued certificates and bidirectional message signing using RustCrypto
ed25519.

### 4.4 Background Processing System

Work queue architecture with job processing workers.

### 4.5 AI Inference Service

Comprehensive AI support with multiple provider types.

### 4.6 Notification Service

Multi-channel notification delivery with configurable triggers.

### 4.7 Import/Export Service

Data interoperability for all data types.

---

## 5. Database Schema Design

### 5.1 Core Entity Model

Asset types, assets, relationships, and history tables.

### 5.2 Business Impact Analysis (BIA) Model

Business functions, critical systems, dependencies, and recovery contacts.

### 5.3 Vulnerability Model

Vulnerability records with multiple sources (CVE, pentest, red team, threat intel).

### 5.4 Security Configuration and Baseline Model

Security baselines, rules, violations with AI analysis.

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

Multi-provider AI analysis configuration and execution.

### 6.5 Configuration Management Endpoints

Dynamic configuration updates via API.

---

## 7. Agent Architecture and Design

### 7.1 Agent Overview

Lightweight agent (<50MB memory) for cross-platform data collection.

### 7.2 Agent Components and Crates

| Category                | Crates                                                              |
| ----------------------- | ------------------------------------------------------------------- |
| Runtime                 | **tokio**, **async-trait**                                          |
| Database                | **sqlx**, **rusqlite**                                              |
| Communication           | **reqwest**, **rustls**, **prost**, **flate2**                      |
| Encryption (RustCrypto) | **aes-gcm**, **sha2**, **hmac**, **ed25519**, **zeroize**, **rand** |
| System Info             | **sysinfo**, **heim**, **pnet**                                     |
| Files                   | **notify**, **walkdir**                                             |

### 7.3 Communication Protocol Security

**Security Layers:**

1. **mTLS with Server-Issuued Certificates**
   - Server operates as Certificate Authority using **rcgen**
   - Agents generate Ed25519/X25519 key pairs and submit CSRs
   - Server signs certificates with server CA
   - Automatic certificate renewal before expiration

2. **Message Signing**
   - All messages signed with agent's Ed25519 private key (**ed25519** crate)
   - Server verifies signatures using agent certificate public key
   - Server responses signed with server's private key
   - Uses constant-time signature verification

3. **Encryption**
   - All messages encrypted with ChaCha20-Poly1305 (**chacha20poly1305**) or AES-256-GCM (**aes-gcm**)
   - Forward secrecy through X25519 key exchange (**x25519**)
   - All cryptographic operations use constant-time implementations where available

### 7.4 Collection Modules

Hardware, OS, software, network, processes, security, and configuration collection.

### 7.5 Desktop Agent (Tauri)

Multi-server profiles, offline mode, system tray, native integration.

---

## 8. Feature Specifications

### 8.1 Asset Inventory Management

Comprehensive asset tracking with AI-powered classification and anomaly detection.

### 8.2 Network Flow Mapping

Network traffic visibility with behavioral baselining.

### 8.3 Vulnerability Management

Multi-source vulnerability tracking (CVE, pentest, red team).

### 8.4 Security Configuration Assessment

CIS, DISA STIG, NIST CSF, PCI-DSS benchmarks with AI analysis.

### 8.5 Business Impact Analysis (BIA)

Critical system mapping with dependencies and recovery objectives.

### 8.6 Notification System

Multi-channel notifications with configurable triggers and escalation.

---

## 9. Security Framework

### 9.1 Encryption (RustCrypto)

All encryption operations use RustCrypto with constant-time implementations:

| Operation            | Crate                    | Constant-Time                      |
| -------------------- | ------------------------ | ---------------------------------- |
| Symmetric Encryption | **aes-gcm**              | Yes (AES-NI when available)        |
| Symmetric Encryption | **chacha20poly1305**     | Yes                                |
| Hashing              | **sha2**                 | Yes (constant-time for comparison) |
| MAC                  | **hmac**                 | Yes (constant-time)                |
| Key Derivation       | **pbkdf2**               | Yes (constant-time)                |
| Key Derivation       | **scrypt**               | Yes                                |
| Signatures           | **ed25519**              | Yes (EdDSA constant-time)          |
| Key Exchange         | **x25519**               | Yes (X25519 constant-time)         |
| Random               | **rand** / **getrandom** | CSPRNG                             |
| Memory Clearing      | **zeroize**              | N/A (explicit clearing)            |

**Example Usage:**

```rust
use aes_gcm::{Aes256Gcm, Key, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

// Constant-time AES-256-GCM encryption
let key = Key::<Aes256Gcm>::from_slice(key_bytes);
let cipher = Aes256Gcm::new(key);
let nonce = Nonce::from_slice(nonce_bytes);
cipher.encrypt(nonce, plaintext)

// Constant-time HMAC
let mut mac = Hmac::<Sha256>::new_from_slice(key_bytes)?;
mac.update(data);
let result = mac.finalize();

// Constant-time comparison
use subtle::ConstantTimeEq;
let eq = a.ct_eq(b);
```

### 9.2 Authentication Methods

Username/password (argon2id), SSO (SAML 2.0), OpenID Connect, API keys, JWT tokens.

### 9.3 Data Protection

Encryption at rest (pgcrypto, RustCrypto), in transit (TLS 1.3), sensitive fields.

### 9.4 Agent Security

mTLS, message signing, certificate renewal, signed packages.

---

## 10. Configuration Management

### 10.1 Configuration Architecture

Horizon implements a hierarchical configuration system with three levels of precedence (highest to lowest):

1. **Runtime API Configuration** - Changes applied immediately via the configuration API
2. **Environment Variables** - Container and deployment-time configuration
3. **Configuration Files** - Installation script and file-based configuration

All configuration changes made at runtime are immediately applied and persisted to the database for consistency across
restarts.

### 10.2 Configuration Levels

#### 10.2.1 Installation Script Configuration

Installation scripts support initial configuration through:

```bash
# Installation script environment file
HORIZON_DATABASE_URL="postgresql://user:pass@localhost:5432/horizon"
HORIZON_REDIS_URL="redis://localhost:6379"
HORIZON_SERVER_HOST="0.0.0.0"
HORIZON_SERVER_PORT="8080"
HORIZON_ENCRYPTION_KEY="base64-encoded-256-bit-key"
HORIZON_JWT_SECRET="your-jwt-secret-key"
HORIZON_ADMIN_EMAIL="admin@example.com"
HORIZON_DEFAULT_TIMEZONE="UTC"

# AI Provider Configuration
HORIZON_AI_ENABLED="true"
HORIZON_AI_DEFAULT_PROVIDER="openai"
HORIZON_AI_OPENAI_API_KEY="sk-..."
HORIZON_AI_ANTHROPIC_API_KEY="sk-ant-..."
HORIZON_AI_GITHUB_COPILOT_TOKEN="ghp_..."
HORIZON_AI_LOCAL_CLI_PATH="/usr/local/bin"

# Notification Configuration
HORIZON_SMTP_HOST="smtp.example.com"
HORIZON_SMTP_PORT="587"
HORIZON_SMTP_USER="noreply@example.com"
HORIZON_SMTP_PASSWORD="smtp-password"
HORIZON_WEBHOOK_SECRET="webhook-signing-secret"

# Docker Configuration
HORIZON_POSTGRES_PASSWORD="postgres-password"
HORIZON_REDIS_PASSWORD="redis-password"
```

#### 10.2.2 Environment Variables

All configuration is exposed through environment variables for container deployment:

| Category          | Variable                                | Type   | Default                       | Description                                 |
| ----------------- | --------------------------------------- | ------ | ----------------------------- | ------------------------------------------- |
| **Server**        | `HORIZON_SERVER_HOST`                   | String | `"0.0.0.0"`                   | Server bind address                         |
|                   | `HORIZON_SERVER_PORT`                   | u16    | `8080`                        | Server bind port                            |
|                   | `HORIZON_SERVER_TLS_ENABLED`            | Bool   | `false`                       | Enable TLS                                  |
|                   | `HORIZON_SERVER_TLS_CERT`               | Path   | None                          | TLS certificate path                        |
|                   | `HORIZON_SERVER_TLS_KEY`                | Path   | None                          | TLS private key path                        |
| **Database**      | `HORIZON_DATABASE_URL`                  | String | Required                      | PostgreSQL connection URL                   |
|                   | `HORIZON_DATABASE_POOL_SIZE`            | u32    | `10`                          | Connection pool size                        |
|                   | `HORIZON_DATABASE_TIMEOUT`              | u64    | `30`                          | Query timeout in seconds                    |
| **Redis**         | `HORIZON_REDIS_URL`                     | String | Required                      | Redis connection URL                        |
|                   | `HORIZON_REDIS_POOL_SIZE`               | u32    | `10`                          | Connection pool size                        |
| **Security**      | `HORIZON_ENCRYPTION_KEY`                | String | Required                      | Master encryption key (base64)              |
|                   | `HORIZON_JWT_SECRET`                    | String | Required                      | JWT signing secret                          |
|                   | `HORIZON_JWT_EXPIRY`                    | u64    | `3600`                        | JWT expiry in seconds                       |
|                   | `HORIZON_BCRYPT_COST`                   | u32    | `12`                          | Bcrypt cost factor                          |
| **AI Providers**  | `HORIZON_AI_ENABLED`                    | Bool   | `true`                        | Enable AI features                          |
|                   | `HORIZON_AI_DEFAULT_PROVIDER`           | String | `"local"`                     | Default AI provider                         |
|                   | `HORIZON_AI_OPENAI_API_KEY`             | String | None                          | OpenAI API key                              |
|                   | `HORIZON_AI_OPENAI_ENDPOINT`            | String | `"https://api.openai.com/v1"` | OpenAI endpoint                             |
|                   | `HORIZON_AI_OPENAI_MODEL`               | String | `"gpt-4"`                     | OpenAI model                                |
|                   | `HORIZON_AI_ANTHROPIC_API_KEY`          | String | None                          | Anthropic API key                           |
|                   | `HORIZON_AI_ANTHROPIC_ENDPOINT`         | String | `"https://api.anthropic.com"` | Anthropic endpoint                          |
|                   | `HORIZON_AI_ANTHROPIC_MODEL`            | String | `"claude-3-opus-20240229"`    | Anthropic model                             |
|                   | `HORIZON_AI_GITHUB_COPILOT_TOKEN`       | String | None                          | GitHub Copilot token                        |
|                   | `HORIZON_AI_GITHUB_COPILOT_ENDPOINT`    | String | `"https://api.github.com"`    | GitHub API endpoint                         |
|                   | `HORIZON_AI_LOCAL_CLI_PATH`             | String | `"/usr/local/bin"`            | Local CLI tools directory                   |
|                   | `HORIZON_AI_LOCAL_CLI_OPENCODE_PATH`    | String | None                          | Path to opencode CLI                        |
|                   | `HORIZON_AI_LOCAL_CLI_COPILOT_CLI_PATH` | String | None                          | Path to copilot CLI                         |
|                   | `HORIZON_AI_LOCAL_CLI_TIMEOUT`          | u64    | `30`                          | Local CLI timeout in seconds                |
| **Notifications** | `HORIZON_SMTP_HOST`                     | String | None                          | SMTP server host                            |
|                   | `HORIZON_SMTP_PORT`                     | u16    | `587`                         | SMTP port                                   |
|                   | `HORIZON_SMTP_USER`                     | String | None                          | SMTP username                               |
|                   | `HORIZON_SMTP_PASSWORD`                 | String | None                          | SMTP password                               |
|                   | `HORIZON_SMTP_TLS_ENABLED`              | Bool   | `true`                        | Enable SMTP TLS                             |
|                   | `HORIZON_WEBHOOK_SECRET`                | String | None                          | Webhook HMAC secret                         |
| **Agent**         | `HORIZON_AGENT_CERT_DAYS`               | u32    | `365`                         | Agent certificate validity days             |
|                   | `HORIZON_AGENT_RENEWAL_DAYS`            | u32    | `30`                          | Days before expiry to renew                 |
| **Logging**       | `HORIZON_LOG_LEVEL`                     | String | `"info"`                      | Log level (trace, debug, info, warn, error) |
|                   | `HORIZON_LOG_FORMAT`                    | String | `"json"`                      | Log format (json, compact, pretty)          |
|                   | `HORIZON_LOG_OUTPUT`                    | String | `"stdout"`                    | Log output (stdout, file)                   |
| **Metrics**       | `HORIZON_METRICS_ENABLED`               | Bool   | `false`                       | Enable Prometheus metrics                   |
|                   | `HORIZON_METRICS_PORT`                  | u16    | `9090`                        | Metrics server port                         |

#### 10.2.3 Runtime Configuration via API

All configuration can be managed at runtime through the Configuration API:

```yaml
# Configuration API Endpoints

GET    /api/v1/system/config           # Get all configuration
GET    /api/v1/system/config/{key}     # Get specific config value
PUT    /api/v1/system/config/{key}     # Update specific config
PATCH  /api/v1/system/config           # Batch update configuration
POST   /api/v1/system/config/validate  # Validate configuration
POST   /api/v1/system/config/export    # Export configuration
POST   /api/v1/system/config/import    # Import configuration
POST   /api/v1/system/config/reset     # Reset to defaults
```

**Configuration Schema:**

```rust
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub tls: Option<TlsConfig>,
    pub max_request_size: usize,
    pub request_timeout: u64,
}

pub struct DatabaseConfig {
    pub url: String,
    pub pool_size: u32,
    pub max_connections: u32,
    pub connection_timeout: u64,
    pub query_timeout: u64,
}

pub struct AiConfig {
    pub enabled: bool,
    pub default_provider: AiProviderType,
    pub providers: HashMap<String, AiProviderConfig>,
    pub local_cli: LocalCliConfig,
    pub cache_enabled: bool,
    pub cache_ttl_seconds: u64,
}

pub enum AiProviderType {
    OpenAi,
    Anthropic,
    GitHubCopilot,
    LocalCli,
    OpenCode,
    Custom,
}

pub struct AiProviderConfig {
    pub provider_type: AiProviderType,
    pub api_key: Option<Secret<String>>,
    pub endpoint: Option<String>,
    pub model: Option<String>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub timeout_seconds: u64,
    pub retry_attempts: u32,
}

pub struct LocalCliConfig {
    pub cli_path: String,
    pub opencode_path: Option<String>,
    pub copilot_cli_path: Option<String>,
    pub timeout_seconds: u64,
    pub environment: HashMap<String, String>,
}

pub struct NotificationConfig {
    pub smtp: Option<SmtpConfig>,
    pub webhook: Option<WebhookConfig>,
    pub default_channel: NotificationChannel,
    pub rate_limit_per_minute: u32,
    pub batch_size: usize,
}

pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Secret<String>,
    pub from_address: String,
    pub tls_enabled: bool,
}

pub struct WebhookConfig {
    pub default_secret: Option<Secret<String>>,
    pub retry_attempts: u32,
    pub retry_delay_ms: u64,
}
```

### 10.3 Configuration Application Flow

```
Configuration Loading Priority:
1. Defaults (hardcoded sensible values)
2. Configuration file (config.yaml, config.toml)
3. Environment variables
4. Runtime API updates

Configuration Application:
- On startup: Load from file, then override with env vars
- On API update: Apply immediately, persist to database
- On restart: Load persisted config from database
- All changes audit-logged
```

### 10.4 AI Provider Configuration

AI providers are fully configurable at multiple levels:

#### 10.4.1 Global AI Configuration

```rust
// Global AI settings in configuration
pub struct GlobalAiConfig {
    pub enabled: bool,
    pub default_provider: AiProviderType,
    pub providers: HashMap<String, AiProviderConfig>,
    pub local_cli: LocalCliConfig,
    pub model_preferences: ModelPreferences,
}

pub struct ModelPreferences {
    pub security_analysis: Option<String>,
    pub vulnerability_assessment: Option<String>,
    pub anomaly_detection: Option<String>,
    pub recommendation_generation: Option<String>,
}
```

#### 10.4.2 Provider-Specific Configuration

**OpenAI Configuration:**

```yaml
ai:
  providers:
    openai:
      enabled: true
      api_key: ${OPENAI_API_KEY}
      endpoint: "https://api.openai.com/v1"
      model: "gpt-4"
      max_tokens: 4096
      temperature: 0.1
      timeout_seconds: 30
      retry_attempts: 3
      models:
        security_analysis: "gpt-4"
        vulnerability_assessment: "gpt-4-turbo"
        anomaly_detection: "gpt-4"
        recommendations: "gpt-4"
```

**Anthropic Configuration:**

```yaml
ai:
  providers:
    anthropic:
      enabled: true
      api_key: ${ANTHROPIC_API_KEY}
      endpoint: "https://api.anthropic.com"
      model: "claude-3-opus-20240229"
      max_tokens: 4096
      temperature: 0.1
      timeout_seconds: 30
      retry_attempts: 3
      models:
        security_analysis: "claude-3-opus-20240229"
        vulnerability_assessment: "claude-3-sonnet-20240229"
```

**GitHub Copilot Configuration:**

```yaml
ai:
  providers:
    github_copilot:
      enabled: true
      token: ${GITHUB_COPILOT_TOKEN}
      endpoint: "https://api.github.com"
      timeout_seconds: 30
      retry_attempts: 3
      organization: "my-org"
```

**Local CLI Tools Configuration:**

```yaml
ai:
  providers:
    opencode:
      enabled: true
      cli_path: "/usr/local/bin/opencode"
      timeout_seconds: 60
      environment:
        OPENCODE_API_KEY: "${OPENCODE_API_KEY}"
      models:
        security_analysis: "default"
        vulnerability_assessment: "default"
    copilot_cli:
      enabled: true
      cli_path: "/usr/local/bin/copilot"
      timeout_seconds: 60
      environment:
        GITHUB_TOKEN: "${GITHUB_TOKEN}"
```

#### 10.4.3 Per-Analysis AI Configuration

Individual AI analysis requests can override the default provider:

```rust
pub struct AnalysisRequest {
    pub analysis_type: AnalysisType,
    pub provider: Option<AiProviderType>,  // Override default
    pub model: Option<String>,
    pub prompt_template: Option<String>,
    pub context: AnalysisContext,
    pub options: AnalysisOptions,
}

pub struct AnalysisOptions {
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub cache_result: bool,
    pub priority: Priority,
}
```

#### 10.4.4 AI Provider Selection Strategy

```rust
pub enum ProviderSelectionStrategy {
    /// Use the configured default provider
    Default,
    /// Use the cheapest available provider
    CostOptimal,
    /// Use the fastest available provider
    SpeedOptimal,
    /// Use the highest quality provider
    QualityOptimal,
    /// Round-robin across enabled providers
    RoundRobin,
    /// Specific provider per analysis type
    PerAnalysisType(HashMap<AnalysisType, AiProviderType>),
}

impl ProviderSelectionStrategy {
    pub fn select_provider(
        &self,
        analysis_type: AnalysisType,
        available_providers: &[&AiProviderConfig],
    ) -> Option<&AiProviderConfig> {
        match self {
            Self::Default => available_providers.first(),
            Self::CostOptimal => available_providers
                .iter()
                .min_by_key(|p| p.estimated_cost),
            Self::SpeedOptimal => available_providers
                .iter()
                .min_by_key(|p| p.estimated_latency),
            Self::QualityOptimal => available_providers
                .iter()
                .max_by_key(|p| p.quality_score),
            Self::RoundRobin => {
                static ROUND_ROBIN: AtomicUsize = AtomicUsize::new(0);
                let idx = ROUND_ROBIN.fetch_add(1, Ordering::SeqCst);
                available_providers.get(idx % available_providers.len())
            }
            Self::PerAnalysisType(map) => {
                map.get(&analysis_type)
                    .and_then(|pt| available_providers.iter()
                        .find(|p| p.provider_type == *pt))
            }
        }
    }
}
```

### 10.5 Configuration Persistence

All runtime configuration changes are immediately applied and persisted:

```rust
pub struct ConfigurationManager {
    config_store: Arc<dyn ConfigStore>,
    notifier: Arc<ConfigChangeNotifier>,
    cache: Arc<RwLock<Config>>,
}

impl ConfigurationManager {
    pub async fn set<T: ConfigValue>(&self, key: &str, value: T) -> Result<(), Error> {
        // Validate the new value
        self.validate(key, &value).await?;

        // Apply the change
        self.apply(key, &value).await?;

        // Persist to database
        self.persist(key, &value).await?;

        // Notify all running components
        self.notifier.notify(key, &value).await?;

        // Audit log the change
        self.audit_log(key, &value).await?;

        Ok(())
    }

    pub async fn get<T: ConfigValue>(&self, key: &str) -> Result<T, Error> {
        // Check cache first
        if let Some(cached) = self.cache.read().get(key) {
            return Ok(cached.clone());
        }

        // Load from store
        let value = self.config_store.get(key).await?;

        // Update cache
        self.cache.write().insert(key.clone(), value.clone());

        Ok(value)
    }
}
```

---

## 11. Docker Deployment

### 11.1 Docker Images

Horizon provides the following Docker images:

| Image                | Description                 | Base Image             |
| -------------------- | --------------------------- | ---------------------- |
| `horizon/server`     | Main API server             | `rust:1.75-slim`       |
| `horizon/worker`     | Background worker processes | `rust:1.75-slim`       |
| `horizon/agent`      | Lightweight agent image     | `alpine:3.19`          |
| `horizon/web`        | Pre-built web UI            | `node:20-alpine`       |
| `horizon/all-in-one` | All services combined       | `debian:bookworm-slim` |

### 11.2 Docker Compose Configuration

```yaml
version: "3.8"

services:
  # PostgreSQL Database
  postgres:
    image: postgres:16-alpine
    container_name: horizon-postgres
    environment:
      POSTGRES_USER: horizon
      POSTGRES_PASSWORD: ${HORIZON_POSTGRES_PASSWORD:-horizon-secret}
      POSTGRES_DB: horizon
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U horizon -d horizon"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - horizon-network

  # Redis Cache
  redis:
    image: redis:7-alpine
    container_name: horizon-redis
    command: redis-server --requirepass ${HORIZON_REDIS_PASSWORD:-redis-secret}
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - horizon-network

  # API Server
  server:
    image: horizon/server:${HORIZON_VERSION:-latest}
    container_name: horizon-server
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    environment:
      # Server Configuration
      HORIZON_SERVER_HOST: "0.0.0.0"
      HORIZON_SERVER_PORT: "8080"

      # Database
      HORIZON_DATABASE_URL: "postgresql://horizon:${HORIZON_POSTGRES_PASSWORD:-horizon-secret}@postgres:5432/horizon"
      HORIZON_DATABASE_POOL_SIZE: "20"

      # Redis
      HORIZON_REDIS_URL: "redis://:${HORIZON_REDIS_PASSWORD:-redis-secret}@redis:6379/0"

      # Security
      HORIZON_ENCRYPTION_KEY: "${HORIZON_ENCRYPTION_KEY}"
      HORIZON_JWT_SECRET: "${HORIZON_JWT_SECRET}"
      HORIZON_JWT_EXPIRY: "3600"
      HORIZON_BCRYPT_COST: "12"

      # AI Providers
      HORIZON_AI_ENABLED: "${HORIZON_AI_ENABLED:-true}"
      HORIZON_AI_DEFAULT_PROVIDER: "${HORIZON_AI_DEFAULT_PROVIDER:-local}"
      HORIZON_AI_OPENAI_API_KEY: "${HORIZON_AI_OPENAI_API_KEY}"
      HORIZON_AI_ANTHROPIC_API_KEY: "${HORIZON_AI_ANTHROPIC_API_KEY}"
      HORIZON_AI_GITHUB_COPILOT_TOKEN: "${HORIZON_AI_GITHUB_COPILOT_TOKEN}"
      HORIZON_AI_LOCAL_CLI_PATH: "/usr/local/bin"

      # Notifications
      HORIZON_SMTP_HOST: "${HORIZON_SMTP_HOST}"
      HORIZON_SMTP_PORT: "${HORIZON_SMTP_PORT:-587}"
      HORIZON_SMTP_USER: "${HORIZON_SMTP_USER}"
      HORIZON_SMTP_PASSWORD: "${HORIZON_SMTP_PASSWORD}"
      HORIZON_WEBHOOK_SECRET: "${HORIZON_WEBHOOK_SECRET}"

      # Logging
      HORIZON_LOG_LEVEL: "${HORIZON_LOG_LEVEL:-info}"
      HORIZON_LOG_FORMAT: "json"

      # Metrics
      HORIZON_METRICS_ENABLED: "${HORIZON_METRICS_ENABLED:-false}"
      HORIZON_METRICS_PORT: "9090"
    ports:
      - "8080:8080"
      - "9090:9090" # Metrics port
    volumes:
      - certificates:/var/lib/horizon/certs
      - logs:/var/log/horizon
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/api/v1/system/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - horizon-network
    restart: unless-stopped

  # Background Workers
  worker:
    image: horizon/server:${HORIZON_VERSION:-latest}
    container_name: horizon-worker
    command: ["worker"]
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    environment:
      # All server environment variables
      HORIZON_SERVER_HOST: "0.0.0.0"
      HORIZON_SERVER_PORT: "8080"
      HORIZON_DATABASE_URL: "postgresql://horizon:${HORIZON_POSTGRES_PASSWORD:-horizon-secret}@postgres:5432/horizon"
      HORIZON_REDIS_URL: "redis://:${HORIZON_REDIS_PASSWORD:-redis-secret}@redis:6379/0"
      HORIZON_ENCRYPTION_KEY: "${HORIZON_ENCRYPTION_KEY}"
      HORIZON_JWT_SECRET: "${HORIZON_JWT_SECRET}"
      HORIZON_LOG_LEVEL: "${HORIZON_LOG_LEVEL:-info}"
      HORIZON_AI_ENABLED: "${HORIZON_AI_ENABLED:-true}"
    volumes:
      - logs:/var/log/horizon
    networks:
      - horizon-network
    restart: unless-stopped

  # Web UI
  web:
    image: horizon/web:${HORIZON_VERSION:-latest}
    container_name: horizon-web
    depends_on:
      - server
    environment:
      VITE_API_URL: "http://localhost:8080"
      VITE_WS_URL: "ws://localhost:8080"
    ports:
      - "3000:80"
    networks:
      - horizon-network
    restart: unless-stopped

volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local
  certificates:
    driver: local
  logs:
    driver: local

networks:
  horizon-network:
    driver: bridge
```

### 11.3 Dockerfile References

#### 11.3.1 Server Dockerfile

```dockerfile
# horizon/Dockerfile.server
FROM rust:1.75-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy cargo files
COPY Cargo.toml Cargo.lock ./

# Create dummy source to download dependencies
RUN mkdir -p src && echo "fn main() {}" > src/main.rs

# Download dependencies
RUN cargo fetch --locked && cargo build --release --frozen

# Copy source code
COPY src ./src

# Build application
RUN cargo build --release --frozen

# Production image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create non-root user
RUN useradd -m -s /bin/bash horizon && \
    mkdir -p /var/lib/horizon /var/log/horizon && \
    chown -R horizon:horizon /var/lib/horizon /var/log/horizon

# Copy binary
COPY --from=builder /app/target/release/horizon-server /usr/local/bin/

# Copy entrypoint
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER horizon

EXPOSE 8080 9090

ENTRYPOINT ["/entrypoint.sh"]
CMD ["server"]
```

#### 11.3.2 Agent Dockerfile

```dockerfile
# agent/Dockerfile.agent
FROM alpine:3.19 AS builder

WORKDIR /app

# Install Rust
RUN apk add --no-cache rust cargo

# Copy cargo files
COPY Cargo.toml Cargo.lock ./
COPY agent ./agent

# Build agent
RUN cd agent && cargo build --release --frozen --target x86_64-unknown-linux-musl

# Production image
FROM alpine:3.19

RUN apk add --no-cache \
    ca-certificates \
    sqlite \
    ethtool \
    iproute2 \
    procps \
    && adduser -D -s /bin/sh horizon

WORKDIR /app

# Copy binary
COPY --from=builder /app/agent/target/x86_64-unknown-linux-musl/release/horizon-agent /usr/local/bin/

# Copy configuration
COPY agent/config/ /etc/horizon/

USER horizon

ENTRYPOINT ["/usr/local/bin/horizon-agent"]
```

#### 11.3.3 Web Dockerfile

```dockerfile
# web/Dockerfile.web
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# Production image
FROM nginx:alpine

COPY --from=builder /app/dist /usr/share/nginx/html
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

### 11.4 Kubernetes Deployment

```yaml
# kubernetes/horizon.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: horizon-config
  namespace: horizon
data:
  HORIZON_SERVER_HOST: "0.0.0.0"
  HORIZON_SERVER_PORT: "8080"
  HORIZON_DATABASE_URL: "postgresql://horizon:@postgres:5432/horizon"
  HORIZON_REDIS_URL: "redis://redis:6379"
  HORIZON_LOG_LEVEL: "info"
  HORIZON_AI_ENABLED: "true"
  HORIZON_AI_DEFAULT_PROVIDER: "local"

---
apiVersion: v1
kind: Secret
metadata:
  name: horizon-secrets
  namespace: horizon
type: Opaque
stringData:
  HORIZON_ENCRYPTION_KEY: "your-256-bit-encryption-key-base64"
  HORIZON_JWT_SECRET: "your-jwt-secret"
  HORIZON_POSTGRES_PASSWORD: "postgres-password"
  HORIZON_REDIS_PASSWORD: "redis-password"
  HORIZON_AI_OPENAI_API_KEY: "sk-..."

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: horizon-server
  namespace: horizon
spec:
  replicas: 3
  selector:
    matchLabels:
      app: horizon-server
  template:
    metadata:
      labels:
        app: horizon-server
    spec:
      containers:
        - name: server
          image: horizon/server:latest
          ports:
            - containerPort: 8080
            - containerPort: 9090
          envFrom:
            - configMapRef:
                name: horizon-config
            - secretRef:
                name: horizon-secrets
          resources:
            requests:
              memory: "512Mi"
              cpu: "500m"
            limits:
              memory: "2Gi"
              cpu: "2000m"
          livenessProbe:
            httpGet:
              path: /api/v1/system/health
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /api/v1/system/ready
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5

---
apiVersion: v1
kind: Service
metadata:
  name: horizon-service
  namespace: horizon
spec:
  selector:
    app: horizon-server
  ports:
    - port: 80
      targetPort: 8080
  type: LoadBalancer
```

### 11.5 Helm Chart

```yaml
# helm/horizon/Chart.yaml
apiVersion: v2
name: horizon
description: Cyberpath Horizon - CMDB and Asset Inventory System
version: 1.0.0
appVersion: "1.0.0"

# helm/horizon/values.yaml
replicaCount: 1

image:
  repository: horizon
  tag: latest
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 8080
  metricsPort: 9090

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: horizon.example.com
      paths:
        - path: /
          pathType: Prefix

postgresql:
  enabled: true
  postgresqlPassword: horizon-secret
  persistence:
    enabled: true
    size: 10Gi

redis:
  enabled: true
  password: redis-secret
  persistence:
    enabled: true
    size: 1Gi

resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "1Gi"
    cpu: "1000m"

ai:
  enabled: true
  defaultProvider: "local"
  openai:
    enabled: false
    apiKey: ""
  anthropic:
    enabled: false
    apiKey: ""
  githubCopilot:
    enabled: false
    token: ""
```

---

## 12. Implementation Phases

### 12.1 Phase 1: Foundation (Weeks 1-12)

**Goal:** Establish core infrastructure with API, database, and basic asset management.

**Deliverables:**

1. **Project Infrastructure** (Week 1-2)
   - Git repository with branch protection
   - CI/CD pipeline (GitHub Actions)
   - Development environment (Docker Compose)
   - Code formatting (cargo fmt) and linting (clippy)
   - Logging and monitoring setup
   - Docker images for server, agent, web

2. **Database Foundation** (Week 2-4)
   - Sea-ORM entity definitions for core tables
   - Migrations for users, teams, assets, asset_types, asset_relationships, asset_history
   - Database indexes for common queries
   - Seed data for asset types, enums

3. **API Foundation** (Week 4-8)
   - Axum server setup with routing
   - Authentication module (JWT, bcrypt, totp)
   - User management endpoints
   - Team and role management
   - Asset CRUD endpoints
   - Asset relationship endpoints
   - Asset history endpoints

4. **Web Interface Foundation** (Week 8-12)
   - React application with Vite
   - Authentication pages
   - Asset list with filtering and pagination
   - Asset detail view
   - Asset creation/editing forms
   - User and team management UI

**Crates:**

- Web: axum, tokio, tower
- Database: sea-orm, sqlx, postgres-types
- Auth: jsonwebtoken, bcrypt, totp
- Serialization: serde, serde_json, chrono
- Error: thiserror, anyhow
- Logging: tracing, tracing-subscriber
- Docker: docker-compose.yml, Dockerfiles

**Testing Requirements:**

- Unit tests (>80% coverage)
- Integration tests for API endpoints
- Authentication flow tests
- Database transaction tests
- Docker build and deployment tests

**Success Criteria:**

- Users can authenticate and manage assets via API
- Web interface provides basic asset management
- API responds within 200ms
- All data changes are audit-logged
- Docker images build successfully
- Docker Compose deployment works

### 12.2 Phase 2: Agent and Discovery (Weeks 13-24)

**Goal:** Deliver lightweight agent with automated discovery and secure communication using RustCrypto.

**Deliverables:**

1. **Agent Core** (Week 13-16)
   - Agent architecture and component structure
   - Platform abstraction layer
   - Configuration management
   - Logging and error handling
   - Installation packages (.deb, .rpm, .msi, .pkg)
   - Agent updater mechanism
   - Agent Docker image

2. **Data Collection** (Week 16-20)
   - Hardware collection (CPU, memory, storage, network)
   - Operating system collection
   - Software package collection
   - Network interface and connection collection
   - Process and service collection
   - Security configuration collection
   - Cross-platform support

3. **Secure Communication (RustCrypto)** (Week 20-22)
   - Certificate authority implementation (**rcgen**)
   - Agent registration with mTLS certificate issuance
   - Message signing with **ed25519** (RustCrypto, constant-time)
   - Protocol Buffer message serialization (**prost**)
   - Encrypted message transmission with **chacha20poly1305** or **aes-gcm**
   - X25519 key exchange for forward secrecy
   - Offline queue with encryption using **zeroize** for memory clearing
   - Certificate renewal with **x509-parser** for validation

4. **Server Integration** (Week 22-24)
   - Agent registration endpoints
   - Certificate management endpoints
   - Report submission and processing
   - Agent status dashboard
   - Agent configuration push

**Encryption Crates (RustCrypto):**

- **aes-gcm** - AES-256-GCM encryption (constant-time)
- **chacha20poly1305** - ChaCha20-Poly1305 encryption (constant-time)
- **sha2** - SHA-256/512 hashing (constant-time)
- **hmac** - HMAC-SHA256/512 (constant-time)
- **ed25519** - Ed25519 signatures (constant-time)
- **x25519** - X25519 key exchange (constant-time)
- **pbkdf2** - PBKDF2 key derivation (constant-time)
- **scrypt** - Scrypt key derivation (constant-time)
- **rand** / **getrandom** - Cryptographic random (CSPRNG)
- **zeroize** - Secure memory clearing

**Testing Requirements:**

- Agent unit tests for collection modules
- Cross-platform compatibility testing
- Communication security testing (mTLS, message signing)
- Performance benchmarking
- Offline queue testing
- Docker agent deployment testing

**Success Criteria:**

- Agents deploy on all supported platforms
- Agent resource usage meets targets (<50MB memory)
- Automated discovery populates inventory
- mTLS communication is established
- Message signing prevents tampering (Ed25519)
- All encryption uses constant-time implementations
- Docker agent image available

### 12.3 Phase 3: Software, Configuration, and BIA (Weeks 25-36)

**Goal:** Deliver software management, configuration management, and BIA capabilities.

**Deliverables:**

1. **Software Management** (Week 25-28)
   - Software product CRUD endpoints
   - Version management with normalized parsing
   - Installation tracking correlation
   - License management
   - Software lifecycle tracking (EOL, support status)
   - Software search and filtering

2. **Configuration Management** (Week 28-32)
   - Environment management
   - Configuration profile versioning
   - Configuration item tracking
   - Configuration deployment
   - Drift detection
   - Configuration history

3. **Security Baselines** (Week 32-34)
   - Security baseline definitions (CIS, custom)
   - Baseline rule management
   - Configuration assessment
   - Violation tracking
   - Compliance reporting

4. **Business Impact Analysis** (Week 34-36)
   - Business function management
   - Critical system registry
   - Dependency mapping
   - Recovery objectives (RTO, RPO)
   - Recovery contact tracking
   - BIA status monitoring
   - BIA reporting

**Crates:**

- ORM: sea-orm, sqlx
- Config: serde_yaml, toml-rs, ini, figment
- Data Processing: regex, csv, chrono
- Graph: petgraph (for BIA dependencies)

**Testing Requirements:**

- Software lifecycle workflow tests
- Configuration deployment tests
- Drift detection tests
- BIA dependency chain tests
- Compliance report generation tests

**Success Criteria:**

- Complete software inventory with version tracking
- Configuration management with baselines
- Security compliance assessment
- BIA data collection and dependency mapping
- Compliance and BIA reporting

### 12.4 Phase 4: Vulnerability and Notification Systems (Weeks 37-48)

**Goal:** Deliver comprehensive vulnerability management and notification system.

**Deliverables:**

1. **Vulnerability Framework** (Week 37-40)
   - CVE synchronization with NVD
   - Custom vulnerability source management
   - Vulnerability-asset correlation
   - Risk assessment with asset context
   - Remediation workflow

2. **Penetration Test Integration** (Week 40-42)
   - Penetration test finding management
   - Engagement tracking
   - Retesting workflow
   - Evidence management (screenshots, logs)
   - Report generation

3. **Red Team Integration** (Week 42-44)
   - Red team finding management
   - MITRE ATT&CK technique mapping
   - IOC tracking
   - Chain analysis
   - Dwell time metrics

4. **Notification System** (Week 44-48)
   - Notification template management
   - Trigger configuration system
   - Email delivery (lettre)
   - Webhook delivery (reqwest, hmac for signatures)
   - Slack/Teams integration
   - Notification history and audit
   - Rate limiting and throttling

**Crates:**

- HTTP: reqwest, hyper
- Email: lettre, mailparse
- Webhooks: reqwest, hmac (RustCrypto)
- XML: quick-xml, serde_xml

**Testing Requirements:**

- CVE sync functionality tests
- Penetration test workflow tests
- Red team finding tests
- Notification delivery tests
- Webhook signature verification tests

**Success Criteria:**

- Automated CVE synchronization
- Vulnerability correlation with assets
- Penetration test tracking and retesting
- Red team finding integration with MITRE ATT&CK
- Multi-channel notification delivery

### 12.5 Phase 5: AI, Import/Export, and Desktop App (Weeks 49-60)

**Goal:** Deliver AI-powered insights, comprehensive data interoperability, and desktop application.

**Deliverables:**

1. **AI Inference Service** (Week 49-52)
   - AI service architecture with multi-provider support
   - **Remote Providers:**
     - OpenAI integration (**async-openai**)
     - Anthropic integration (**anthropic** crate)
     - GitHub Copilot integration
   - **Local CLI Tools:**
     - OpenCode CLI integration (**tokio::process**)
     - GitHub Copilot CLI integration
   - Security configuration analysis model
   - Anomaly detection model
   - Recommendation generation
   - API endpoints for AI analysis
   - Model versioning and updates
   - Provider selection strategies

2. **Import/Export System** (Week 52-55)
   - CSV import/export (csv crate)
   - Excel import/export (calamine)
   - JSON import/export
   - XML support
   - Field mapping interface
   - Bulk import with validation
   - Complete system export

3. **Desktop Application** (Week 55-60)
   - Tauri application setup
   - Multi-server profile management
   - Offline data access
   - Native agent management
   - Desktop notifications
   - Import/export UI
   - Quick actions and shortcuts
   - System tray integration

**AI Provider Crates:**

- **candle** - Rust-native ML framework
- **candle-nn** - Neural network building blocks
- **tokenizers** - Hugging Face tokenizers
- **onnxruntime** - ONNX model execution
- **ndarray** - Numerical array operations
- **reqwest** - HTTP client for remote APIs
- **async-openai** - OpenAI API client
- **anthropic** - Anthropic API client
- **tokio::process** - Subprocess execution for CLI tools

**Desktop Crates:**

- **tauri** - Desktop runtime
- **tauri-plugin-tray** - System tray
- **tauri-plugin-notification** - Desktop notifications
- **window-vibrancy** - Native window appearance

**Testing Requirements:**

- AI provider integration tests (OpenAI, Anthropic, Copilot)
- Local CLI tool tests (opencode, copilot CLI)
- Import validation tests
- Export format tests
- Desktop app integration tests
- Multi-profile functionality tests
- Offline mode tests

**Success Criteria:**

- AI-powered security analysis with multiple providers
- Remote AI (OpenAI, Anthropic, Copilot) works
- Local CLI AI (opencode, copilot CLI) works
- Comprehensive import/export for all data types
- Desktop application with multi-server support
- Offline capability in desktop app
- Native desktop notifications
- AI provider selection strategies functional

### 12.6 Phase 6: Configuration Management, Docker, and Production Readiness (Weeks 61-72)

**Goal:** Comprehensive configuration management, Docker deployment, and production readiness.

**Deliverables:**

1. **Configuration Management System** (Week 61-64)
   - Environment variable configuration loading
   - Configuration file parsing (YAML, TOML, JSON)
   - Runtime configuration API implementation
   - Immediate configuration application
   - Configuration persistence to database
   - Configuration validation and schema enforcement
   - Configuration change audit logging
   - Configuration rollback capabilities

2. **Docker Deployment** (Week 64-68)
   - Complete Docker Compose setup
   - Multi-stage Dockerfiles for server, agent, web
   - Kubernetes manifests
   - Helm chart
   - Private registry configuration
   - Volume management for persistence
   - Network configuration
   - Health checks and readiness probes

3. **Production Hardening** (Week 68-72)
   - Performance optimization
   - Scalability testing and tuning
   - Load testing
   - Security audit and penetration testing
   - Compliance documentation (SOC 2, ISO 27001)
   - Backup and disaster recovery procedures
   - Monitoring setup (Prometheus, Grafana)
   - Alert configuration
   - Runbook creation

**Configuration Management Crates:**

- **figment** - Configuration management with multiple backends
- **serde_yaml** - YAML parsing
- **toml** - TOML parsing
- **config** - Hierarchical configuration
- **directories** - Platform-specific config directories

**Docker and Deployment:**

- **docker-compose.yml** - Full stack deployment
- **Dockerfile.server** - Multi-stage server build
- **Dockerfile.agent** - Alpine-based agent
- **Dockerfile.web** - Nginx-based static files
- **kubernetes/** - K8s manifests
- **helm/** - Helm charts

**Testing Requirements:**

- Configuration loading tests (env vars, files, API)
- Configuration persistence tests
- Docker build tests
- Docker Compose deployment tests
- Kubernetes deployment tests
- Performance benchmark tests
- Load tests
- Security penetration tests
- Backup/restore tests

**Success Criteria:**

- Configuration works via env vars, files, and API
- All configuration changes are immediately applied
- Configuration persists across restarts
- Docker images build and deploy successfully
- Docker Compose deployment works out-of-box
- Kubernetes manifests are functional
- Helm chart is publishable
- Production performance meets SLAs
- Security audit passes
- Backup and recovery procedures tested

---

## 13. Technical Decisions and Justifications

### 13.1 Encryption: RustCrypto with Constant-Time Operations

**Decision:** Use RustCrypto exclusively for all cryptographic operations, with constant-time implementations where
available.

**Justification:** RustCrypto provides high-quality, audit-friendly cryptographic implementations with a focus on
security and correctness. The constant-time operations are essential for preventing timing side-channel attacks,
especially when comparing hashes, verifying signatures, or performing cryptographic operations on sensitive data.

**Specific Choices:**

| Operation            | Crate                               | Justification                                                                                                                             |
| -------------------- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Symmetric Encryption | **aes-gcm** or **chacha20poly1305** | Both provide authenticated encryption. AES-GCM uses AES-NI when available (fast), ChaCha20 is constant-time without hardware acceleration |
| Hashing              | **sha2**                            | Industry-standard, constant-time comparison supported                                                                                     |
| MAC                  | **hmac**                            | Standard HMAC with constant-time verification                                                                                             |
| Signatures           | **ed25519**                         | EdDSA with constant-time scalar multiplication                                                                                            |
| Key Exchange         | **x25519**                          | ECDH with constant-time operations                                                                                                        |
| Key Derivation       | **pbkdf2** or **scrypt**            | Both constant-time, scrypt provides better memory-hard properties                                                                         |
| Random               | **rand** with **getrandom**         | Uses OS CSPRNG (getrandom)                                                                                                                |
| Memory Clearing      | **zeroize**                         | Explicit zeroing of sensitive memory                                                                                                      |

**Alternative Rejected:** libsodium (NaCl) was rejected because RustCrypto provides equivalent or better security
guarantees with more granular control over constant-time operations and better integration with the broader Rust
ecosystem.

### 13.2 AI Provider Support

**Decision:** Support multiple AI providers including remote APIs and local CLI tools, configurable at all levels.

**Justification:** Different organizations have different AI preferences and requirements. Some prefer cloud APIs
(OpenAI, Anthropic) for their capabilities, others require local tools (opencode, copilot CLI) for data sovereignty, and
some need GitHub Copilot integration for development workflows. Configurable providers at global, per-analysis, and
per-request levels provide maximum flexibility.

**Provider Selection Strategy:**

The system supports multiple provider selection strategies:

- Default provider (configured globally)
- Cost-optimal (cheapest available)
- Speed-optimal (fastest response)
- Quality-optimal (highest quality score)
- Per-analysis-type (different providers for different tasks)
- Round-robin (distribute load)

### 13.3 Configuration Management

**Decision:** Implement hierarchical configuration with environment variables, configuration files, and runtime API,
with immediate application and persistence.

**Justification:** Different deployment scenarios require different configuration methods:

- Container deployments use environment variables
- Traditional deployments use configuration files
- Runtime adjustments use the API

Immediate application ensures operational responsiveness, while persistence ensures configuration survives restarts.

### 13.4 Docker Deployment

**Decision:** Provide complete Docker deployment with multi-stage builds, Docker Compose, Kubernetes manifests, and Helm
chart.

**Justification:** Modern deployments require container support. Multi-stage builds minimize image sizes. Docker Compose
enables local development and simple deployments. Kubernetes and Helm support enterprise-scale deployments.

---

## 14. Action Items and Roadmap

### 14.1 Immediate Action Items

1. **Repository Setup:** Initialize Git repository with branch protection rules, Docker support, and CI/CD.

2. **Development Environment:** Configure Docker Compose for PostgreSQL, Redis, and development services.

3. **CI/CD Pipeline:** Configure GitHub Actions for Rust testing, linting, Docker builds, and deployments.

4. **API Specification:** Finalize OpenAPI specification for v1 API.

5. **Database Schema:** Create initial migration scripts for core entities.

6. **Security Review:** Conduct security architecture review focusing on RustCrypto implementation.

7. **Docker Setup:** Create initial Dockerfiles and docker-compose.yml.

### 14.2 Phase Completion Criteria

| Phase   | Key Success Criteria                                              |
| ------- | ----------------------------------------------------------------- |
| Phase 1 | Functional API, web UI, Docker images build                       |
| Phase 2 | Agent with RustCrypto encryption (constant-time), mTLS            |
| Phase 3 | Software, configuration, BIA tracking                             |
| Phase 4 | Vulnerability management, notifications                           |
| Phase 5 | AI providers (OpenAI, Anthropic, Copilot, CLI tools), desktop app |
| Phase 6 | Configuration management, Docker/K8s deployment, production ready |

---

## Appendix A: Glossary

| Term      | Definition                                         |
| --------- | -------------------------------------------------- |
| **Agent** | Lightweight software component for data collection |
| **Asset** | Any discrete IT infrastructure component           |
| **BIA**   | Business Impact Analysis                           |
| **CVE**   | Common Vulnerabilities and Exposures               |
| **CVSS**  | Common Vulnerability Scoring System                |
| **mTLS**  | Mutual TLS authentication                          |
| **CMDB**  | Configuration Management Database                  |

---

## Appendix B: Technology Stack Reference

**Backend Stack:**

- Language: Rust 1.75+
- Web Framework: Axum 0.7
- ORM: Sea-ORM 0.12
- Async Runtime: Tokio 1.35
- Database: PostgreSQL 16
- Cache: Redis 7
- Serialization: Protocol Buffers, JSON

**Encryption (RustCrypto):**

- aes-gcm, chacha20poly1305, sha2, hmac
- ed25519, x25519, pbkdf2, scrypt
- rand, getrandom, zeroize, subtle

**AI Providers:**

- Remote: OpenAI, Anthropic, GitHub Copilot
- Local: opencode CLI, copilot CLI
- Framework: candle, onnxruntime, tokenizers

**Frontend Stack:**

- React 18, TypeScript 5, Vite 5
- Tailwind CSS 4, shadcn/ui
- TanStack Query 5

**Desktop Stack:**

- Tauri 2.0, React

**Deployment:**

- Docker, Docker Compose
- Kubernetes, Helm

---

_This implementation plan represents the current understanding of Horizon requirements and architecture. The plan will
be updated as implementation progresses and new requirements emerge._
