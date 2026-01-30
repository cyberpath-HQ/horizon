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

**External AI Provider Support (Inference-First):**

| Provider           | Type             | Integration Method |
| ------------------ | ---------------- | ------------------ |
| **OpenAI**         | Remote Inference | REST API           |
| **Anthropic**      | Remote Inference | REST API           |
| **GitHub Copilot** | Remote Inference | REST API           |
| **opencode**       | CLI Inference    | Subprocess         |
| **copilot-cli**    | CLI Inference    | Subprocess         |

**Local ML Models (Only If Strictly Needed):**

| Crate       | Purpose                          |
| ----------- | -------------------------------- |
| **candle**  | Pre-trained ONNX model execution |
| **ndarray** | Tensor operations                |

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

PostgreSQL (latest) with Redis (latest) for caching.

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
| Runtime                 | **tokio**, **async-trait**                                                                             |
| Database                | **sqlx**, **rusqlite**                                                                                 |
| Communication           | **reqwest**, **rustls**, **prost**, **flate2**                                                         |
| Encryption (RustCrypto) | **chacha20poly1305**, **blake3**, **hmac**, **ed25519**, **x25519**, **argon2**, **zeroize**, **rand** |
| System Info             | **sysinfo**, **heim**, **pnet**                                                                        |
| Files                   | **notify**, **walkdir**                                                                                |

### 7.3 Communication Protocol Security

- mTLS with server-issued certificates using rcgen
- Message signing with Ed25519 (constant-time)
- Encryption with XChaCha20-Poly1305
- Forward secrecy with X25519 key exchange
- Password hashing with Argon2id

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

- Argon2id for password hashing
- XChaCha20-Poly1305 for symmetric encryption
- BLAKE3 for general hashing
- SHA3 for backup hashing
- Ed25519 for digital signatures
- X25519 for key exchange
- Zeroize for secure memory clearing

### 9.2 Authentication Methods

Password with Argon2id, SSO, OpenID Connect, API keys, JWT tokens, TOTP MFA, WebAuthn/FIDO2.

### 9.3 Data Protection

Encryption at rest, in transit, and for sensitive fields.

### 9.4 Agent Security

mTLS, Ed25519 signing, XChaCha20-Poly1305 encryption.

---

## 10. Configuration Management

### 10.1 Configuration Architecture

Three-level hierarchy: Runtime API, Environment Variables, Configuration Files.

### 10.2 Environment Variables

All configuration exposed via HORIZON\_\* environment variables.

### 10.3 Runtime Configuration API

Endpoints for config get/set, validate, export/import, history, rollback.

---

## 11. Docker Deployment

### 11.1 Docker Images

| Image          | Base Image             |
| -------------- | ---------------------- |
| horizon/server | rust:1.94-nightly-slim |
| horizon/worker | rust:1.94-nightly-slim |
| horizon/agent  | alpine:3.21            |
| horizon/web    | node:22-alpine         |

### 11.2 Docker Compose

Multi-service deployment with PostgreSQL, Redis, server, worker, web.

### 11.3 Kubernetes

ConfigMap, Secret, Deployment, Service, Ingress, HPA, PDB, PVC.

### 11.4 Helm Chart

Complete Helm chart structure with templates and values.yaml.

---

## 12. Implementation Phases

### Phase 1: Project Foundation and Core Infrastructure

**Scope:** Establish project infrastructure, core database schema, basic API, and web frontend foundation.

**Deliverables:**

- Initialize Rust workspace with Cargo.toml defining all dependencies
- Configure Git repository with branch protection rules and commit conventions
- Set up CI/CD pipeline using GitHub Actions for automated testing, linting, and Docker builds
- Define Docker Compose configuration for PostgreSQL, Redis, and development services
- Create development environment documentation in README.md
- Implement tracing and logging infrastructure with structured JSON output
- Define Sea-ORM entities for users, teams, roles, and permissions
- Create database migrations for authentication schema
- Implement JWT authentication middleware using jsonwebtoken crate
- Implement Argon2id password hashing using argon2 crate
- Implement TOTP MFA functionality using totp crate
- Create user registration, login, logout, and session management endpoints
- Define API response types and error handling with thiserror
- Implement rate limiting middleware using Redis
- Create web application project with React, TypeScript, and Vite
- Set up Tailwind CSS and shadcn/ui component library
- Implement authentication pages (login, register, MFA)
- Create base layout and navigation components
- Implement session storage and JWT token management
- Build user profile and settings pages
- Create Dockerfiles for server, worker, and web services
- Configure multi-stage Docker builds for minimal image sizes
- Define environment variable configurations for all services

**Database Tables:**

- users (id, email, username, password_hash, totp_secret, status, created_at, updated_at)
- teams (id, name, slug, description, parent_team_id, manager_id, created_at)
- team_members (id, team_id, user_id, role, joined_at)
- roles (id, name, slug, description, permissions, is_system, created_at)
- user_roles (id, user_id, role_id, scope_type, scope_id, expires_at, assigned_at)
- api_keys (id, user_id, name, key_hash, key_prefix, permissions, expires_at, last_used_at)
- sessions (id, user_id, token, expires_at, ip_address, user_agent)

**API Endpoints:**

- POST /api/v1/auth/register
- POST /api/v1/auth/login
- POST /api/v1/auth/logout
- POST /api/v1/auth/refresh
- POST /api/v1/auth/mfa/verify
- GET /api/v1/users/me
- PUT /api/v1/users/me
- GET /api/v1/users
- GET /api/v1/teams
- POST /api/v1/teams
- GET /api/v1/teams/{id}
- POST /api/v1/teams/{id}/members

---

### Phase 2: Asset Inventory Core

**Scope:** Implement asset management, relationships, history tracking, and agent foundation.

**Deliverables:**

- Define Sea-ORM entities for asset_types, assets, and asset_relationships
- Create database migrations for asset schema with hierarchical classification support
- Implement asset CRUD endpoints with UUID primary keys
- Implement asset type hierarchy with recursive parent_id references
- Define custom_attributes JSONB column for extensible asset properties
- Implement asset relationship types (dependency, connectivity, containment, ownership)
- Create relationship strength enum (strong, medium, weak, unknown)
- Implement asset history tracking with full change provenance
- Define actor_type enum (user, agent, system, import, api)
- Implement asset list endpoint with filtering, pagination, and sorting
- Implement asset search with PostgreSQL full-text search
- Create asset detail endpoint with embedded relationships
- Implement bulk asset operations (create, update, delete)
- Define asset status enum (planned, acquired, active, maintenance, retiring, decommissioned)
- Implement asset import functionality with validation
- Create agent project with Rust workspace member
- Implement agent configuration loading from environment and files
- Define agent command-line interface with clap
- Implement platform detection (Linux, Windows, macOS)
- Create system information collection using sysinfo and heim crates
- Implement hardware inventory (CPU, memory, storage, network interfaces)
- Implement operating system inventory (kernel, distribution, hostname, uptime)
- Implement software package inventory (dpkg, rpm, brew, chocolatey)
- Create agent communication module with Protocol Buffers serialization
- Define agent report message format with prost
- Implement server-side agent registration endpoints
- Create agent status dashboard in web UI
- Implement real-time agent status updates using WebSocket

**Database Tables:**

- asset_types (id, parent_id, name, slug, description, icon, color, metadata_schema, is_active)
- assets (id, inventory_number, asset_type_id, name, description, serial_number, manufacturer, model, owner_id,
  custodian_id, status, tags, custom_attributes, agent_id, bia_criticality, last_seen_at, created_by, created_at,
  updated_at)
- asset_relationships (id, source_asset_id, target_asset_id, relationship_type, metadata, strength, is_active)
- asset_history (id, asset_id, action, field_name, old_value, new_value, actor_type, actor_id, actor_name,
  change_reason, created_at)
- agents (id, asset_id, name, version, platform, last_seen_at, status, cert_expires_at)

**API Endpoints:**

- GET /api/v1/assets
- POST /api/v1/assets
- GET /api/v1/assets/{id}
- PUT /api/v1/assets/{id}
- DELETE /api/v1/assets/{id}
- GET /api/v1/assets/{id}/relationships
- POST /api/v1/assets/{id}/relationships
- DELETE /api/v1/assets/{id}/relationships
- GET /api/v1/assets/{id}/history
- POST /api/v1/assets/import
- GET /api/v1/assets/export
- GET /api/v1/asset-types
- POST /api/v1/asset-types
- GET /api/v1/agents
- GET /api/v1/agents/{id}
- GET /api/v1/agents/{id}/reports

---

### Phase 3: Software Management and Version Tracking

**Scope:** Implement software product catalog, version management, installation tracking, and license management.

**Deliverables:**

- Define Sea-ORM entities for software_products, software_versions, and software_installations
- Create database migrations for software schema
- Implement software product CRUD endpoints
- Define software_category enum (operating_system, database, middleware, application, utility, firmware, driver,
  container_image, library)
- Implement version string normalization with semantic versioning parsing
- Create version comparison functions for sorting and range queries
- Implement software vendor linking with vendor_id foreign key
- Define support_status enum (active, limited, deprecated, end_of_life, unsupported, unknown)
- Implement EOL date tracking and alerting
- Create software installation tracking linked to assets
- Define installation_path, installation_date, and license_key fields
- Implement license management with license_key, license_expiry, and usage tracking
- Define usage_status enum (active, inactive, deprecated, removed)
- Create software inventory search and filtering
- Implement software lifecycle reports
- Create dependency detection between installed software
- Implement software version comparison API
- Define startup_type enum for services (automatic, manual, disabled, on_demand)
- Create service and process inventory linked to software installations
- Implement web UI for software management with version history
- Create software dashboard with installation statistics

**Database Tables:**

- software_vendors (id, name, slug, website, support_email, metadata)
- software_products (id, vendor_id, name, category, description, website, support_status, eol_date, icon_url)
- software_versions (id, product_id, version_string, version_major, version_minor, version_patch, version_build,
  release_date, eol_date, download_url, checksum, is_latest, is_security_release)
- software_installations (id, asset_id, version_id, installation_path, installation_date, installation_source,
  license_key, license_expiry, usage_status, instance_count, configuration_path, startup_type, service_name,
  last_used_at, detected_at)
- software_licenses (id, installation_id, license_key, license_type, seats, expiry_date, purchase_date, cost)

**API Endpoints:**

- GET /api/v1/software/products
- POST /api/v1/software/products
- GET /api/v1/software/products/{id}
- PUT /api/v1/software/products/{id}
- DELETE /api/v1/software/products/{id}
- GET /api/v1/software/products/{id}/versions
- POST /api/v1/software/products/{id}/versions
- GET /api/v1/software/versions/{id}
- GET /api/v1/software/installations
- GET /api/v1/software/installations/{id}
- POST /api/v1/software/installations
- GET /api/v1/software/licenses
- POST /api/v1/software/licenses
- GET /api/v1/software/search
- GET /api/v1/software/categories

---

### Phase 4: Security Configuration and Baselines

**Scope:** Implement security configuration assessment, benchmark management, violation tracking, and AI-powered
analysis.

**Deliverables:**

- Define Sea-ORM entities for security_baselines, baseline_rules, and configuration_violations
- Create database migrations for configuration schema
- Define baseline_source enum (cis, disa_stig, nist_csf, custom, vendor_recommendation)
- Implement CIS Benchmark support with rule identifiers and descriptions
- Implement DISA STIG support with STIG identifiers
- Implement NIST CSF alignment with framework categories
- Define value_type enum (string, integer, boolean, json, enum, version, path)
- Create baseline rule management with validation queries
- Implement rule severity classification (critical, high, medium, low, info)
- Define deviation_type enum (missing, incorrect, warning, informational)
- Implement automated configuration assessment against baselines
- Create configuration item tracking linked to assets
- Implement configuration drift detection with historical comparison
- Define configuration_source enum (agent, manual, import, deployment, discovery)
- Create violation tracking with severity and remediation status
- Implement AI-powered configuration analysis using inference providers
- Create remediation guidance generation
- Implement compliance scoring and reporting
- Define remediation_status enum (not_started, in_progress, waiting_on_vendor, blocked, completed, no_action_required)
- Create audit trail for configuration changes
- Implement auto-fixable rule detection and script generation
- Create web UI for baseline management and violation tracking
- Build compliance dashboard with score visualization

**Database Tables:**

- security_baselines (id, name, description, source_type, source_reference, benchmark_version, applies_to_asset_types,
  severity, is_active, created_by, created_at)
- baseline_rules (id, baseline_id, rule_id, title, description, category, remediation, expected_value, value_type,
  validation_query, severity, is_auto_fixable, fix_command, references, is_active)
- configuration_items (id, asset_id, environment_id, config_key, config_value, value_type, source, is_sensitive,
  last_observed_at)
- configuration_assessments (id, asset_id, baseline_id, assessed_at, assessed_by, total_rules, passed_rules,
  failed_rules, compliance_score, overall_status, report_path)
- configuration_violations (id, assessment_id, asset_id, rule_id, current_value, expected_value, deviation_type,
  severity, is_acknowledged, acknowledged_by, acknowledged_at, remediation_status, remediation_deadline,
  remediation_owner, ai_analysis, created_at)
- configuration_history (id, asset_id, config_key, old_value, new_value, change_type, source, actor_type, actor_id,
  change_reason, created_at)
- environments (id, name, description, environment_type, is_active)

**API Endpoints:**

- GET /api/v1/configuration/baselines
- POST /api/v1/configuration/baselines
- GET /api/v1/configuration/baselines/{id}
- PUT /api/v1/configuration/baselines/{id}
- DELETE /api/v1/configuration/baselines/{id}
- GET /api/v1/configuration/baselines/{id}/rules
- POST /api/v1/configuration/baselines/{id}/rules
- GET /api/v1/configuration/rules/{id}
- POST /api/v1/configuration/assess
- GET /api/v1/configuration/assessments
- GET /api/v1/configuration/violations
- GET /api/v1/configuration/compliance
- POST /api/v1/configuration/items
- GET /api/v1/configuration/items
- GET /api/v1/configuration/environments
- POST /api/v1/configuration/environments
- POST /api/v1/ai/analyze/configuration

---

### Phase 5: Vulnerability Management

**Scope:** Implement CVE synchronization, vulnerability tracking, penetration test integration, and red team findings
management.

**Deliverables:**

- Define Sea-ORM entities for vulnerabilities, vulnerability_sources, and vulnerability_assessments
- Create database migrations for vulnerability schema
- Define vulnerability_source enum (cve, pentest, vulnerability_scan, red_team, threat_intel, manual, vendor_advisory)
- Implement NVD API integration for CVE synchronization
- Create custom vulnerability source management with configurable sync intervals
- Implement CVE parsing and normalization with CVSS scoring
- Define severity_level enum (critical, high, medium, low, info, none)
- Implement vulnerability-asset correlation through software mapping
- Create risk assessment with asset context and compensating controls
- Define vulnerability_status enum (open, in_progress, resolved, risk_accepted, false_positive, duplicate, out_of_scope)
- Implement penetration test finding management
- Define pentest_type enum (internal, external, web_application, mobile, network, social_engineering, physical)
- Create engagement tracking with finding numbers and retesting workflow
- Implement evidence management (screenshots, logs, files)
- Define retest_status enum (pending, passed, failed, not_applicable)
- Implement red team finding management
- Map MITRE ATT&CK techniques and tactics to findings
- Implement IOC (Indicators of Compromise) tracking
- Create chain analysis for attack paths
- Define exploitation_status enum (not_exploited, exploited, exploitable, proof_of_concept, unclear)
- Implement dwell time and detection time metrics
- Create vulnerability reports with asset lists and remediation guidance
- Implement false positive detection with ML inference
- Create web UI for vulnerability management and tracking
- Build security dashboard with vulnerability metrics

**Database Tables:**

- vulnerability_sources (id, source_type, name, description, import_config, last_sync_at, sync_interval_minutes,
  is_active, credentials)
- vulnerabilities (id, source_type, external_id, source_id, title, description, severity, cvss_score, cvss_vector,
  cvss3_score, cvss3_vector, status, remediation_guidance, exploit_available, patch_available, affected_cpes,
  affected_products, published_date, discovered_at)
- vulnerability_assessments (id, vulnerability_id, asset_id, assessment_type, applicability, false_positive,
  risk_rating, affected_component, exploitation_status, compensating_controls, risk_acceptance, risk_accepted_by,
  remediation_owner, remediation_deadline, remediation_status, verified, verified_by, assessed_by, assessed_at)
- penetration_test_engagements (id, name, type, scope, start_date, end_date, team, status)
- penetration_test_findings (id, vulnerability_id, engagement_id, test_type, finding_number, title, description,
  methodology, impact, likelihood, evidence, affected_assets, remediation, retest_date, retest_status, retested_by,
  retested_at)
- red_team_engagements (id, name, campaign, start_date, end_date, objectives, status)
- red_team_findings (id, vulnerability_id, engagement_id, technique_id, tactic_id, objectives_achieved,
  dwell_time_minutes, detection_time_minutes, lateral_movement, privilege_escalation, data_exfiltration,
  chain_description, affected_assets, ttps, iocs, remediation_priority)
- cve_references (id, vulnerability_id, url, source, description)

**API Endpoints:**

- GET /api/v1/vulnerabilities
- POST /api/v1/vulnerabilities
- GET /api/v1/vulnerabilities/{id}
- PUT /api/v1/vulnerabilities/{id}
- POST /api/v1/vulnerabilities/sync
- GET /api/v1/vulnerabilities/sources
- POST /api/v1/vulnerabilities/sources
- GET /api/v1/vulnerabilities/assessments
- POST /api/v1/vulnerabilities/assessments
- GET /api/v1/pentests
- POST /api/v1/pentests
- GET /api/v1/pentests/{id}/findings
- POST /api/v1/pentests/{id}/findings
- POST /api/v1/pentests/{id}/retest
- GET /api/v1/red-team
- POST /api/v1/red-team/engagements
- GET /api/v1/red-team/findings
- POST /api/v1/red-team/findings
- GET /api/v1/vulnerabilities/export
- GET /api/v1/vulnerabilities/reports

---

### Phase 6: Network Flow Mapping

**Scope:** Implement network topology discovery, flow collection, aggregation, and behavioral analysis.

**Deliverables:**

- Define Sea-ORM entities for network_interfaces, ip_addresses, network_flows, and flow_sessions
- Create database migrations for network schema
- Implement network interface discovery using platform-specific APIs
- Define interface_type enum (ethernet, wifi, loopback, tunnel, vlan, bridge, bond, tap, virtio, vmxnet, e1000, hyperv)
- Capture MAC addresses, interface speeds, and MTU values
- Implement IP address allocation tracking with IPv4 and IPv6 support
- Define ip_address_type enum (ipv4, ipv6, both)
- Implement subnet tracking and CIDR notation support
- Create network flow collection from agents and external sources
- Define transport_layer_protocol enum (tcp, udp, icmp, icmpv6, gre, esp, ah, sctp, other)
- Implement flow aggregation into sessions with statistical summaries
- Define flow_direction enum (inbound, outbound, internal, external)
- Create behavioral baselining for normal traffic patterns
- Implement anomaly detection using inference providers
- Define flow_status enum (observed, permitted, blocked, expected, unexpected, anomalous)
- Implement topology mapping from interface connections
- Create network visualization with graph representation
- Define behavioral_status enum (normal, suspicious, anomalous, critical)
- Implement traffic analysis and bandwidth reporting
- Create unexpected traffic alerts with severity classification
- Implement flow comparison with configured vs observed discrepancies
- Create web UI for network topology visualization
- Build flow analysis dashboard with filtering and search

**Database Tables:**

- subnets (id, cidr, name, vlan_id, environment_id, gateway, dns_servers)
- network_interfaces (id, asset_id, interface_name, mac_address, interface_type, link_speed_mbps, mtu, is_virtual,
  vlan_id, parent_interface_id, operational_status, admin_status, last_seen_at)
- ip_addresses (id, interface_id, ip_address, prefix_length, address_type, subnet_id, allocation_reason, is_primary,
  dns_name, last_seen_at)
- network_flows (id, source_asset_id, source_ip, source_port, dest_asset_id, dest_ip, dest_port, protocol,
  application_protocol, service_name, flow_direction, first_observed_at, last_observed_at, byte_count, packet_count,
  connection_count, flow_status, is_encrypted, observation_source, raw_data)
- flow_sessions (id, source_asset_id, dest_asset_id, source_port, dest_port, protocol, service_name, flow_direction,
  session_start, session_end, total_bytes, total_packets, connection_count, avg_duration_seconds, peak_bandwidth_bps,
  observations, behavioral_status, ai_analysis)
- network_topology (id, asset_id, connected_asset_id, connection_type, cable_id, port, is_trunk, allowed_vlans)

**API Endpoints:**

- GET /api/v1/network/interfaces
- GET /api/v1/network/interfaces/{id}
- GET /api/v1/network/ip-addresses
- GET /api/v1/network/subnets
- POST /api/v1/network/subnets
- GET /api/v1/network/flows
- POST /api/v1/network/flows
- GET /api/v1/network/flows/sessions
- GET /api/v1/network/flows/summary
- GET /api/v1/network/flows/compare
- GET /api/v1/network/topology
- GET /api/v1/network/topology/visualize
- GET /api/v1/network/anomalies
- GET /api/v1/network/bandwidth
- POST /api/v1/ai/analyze/network

---

### Phase 7: Business Impact Analysis (BIA)

**Scope:** Implement business function mapping, critical system registry, dependency tracking, and recovery management.

**Deliverables:**

- Define Sea-ORM entities for business_functions, critical_systems, system_dependencies, and recovery_contacts
- Create database migrations for BIA schema
- Implement business function management with hierarchical structure
- Define bia_criticality enum (critical, high, medium, low, non_critical)
- Implement RTO (Recovery Time Objective) tracking in minutes
- Implement RPO (Recovery Point Objective) tracking in minutes
- Define maximum tolerable outage in minutes
- Implement financial impact per hour tracking
- Create critical system registry linked to assets and software
- Define bia_status enum (operational, degraded, unavailable, in_maintenance, pending_review)
- Implement dependency mapping between critical systems
- Define dependency_type enum (infrastructure, software, data, network, service, vendor)
- Create dependency graph with impact cascade analysis
- Define failover_mechanism enum (automatic, manual, none, third_party, cloud_failover)
- Implement recovery procedures documentation
- Create work-around tracking for critical systems
- Implement BIA review scheduling with last and next review dates
- Define contact_type enum (technical, management, vendor, security, executive, external_support)
- Create recovery contact management with escalation order
- Implement automated BIA status monitoring from asset status
- Create impact assessment reports with recovery recommendations
- Define recovery objectives calculation based on business criticality
- Implement critical system verification workflow
- Create web UI for BIA management and visualization
- Build BIA dashboard with impact metrics and dependency graphs

**Database Tables:**

- business_functions (id, code, name, description, owner_id, parent_function_id, criticality, rto_minutes, rpo_minutes,
  max_downtime_minutes, financial_impact_per_hour, regulatory_requirements, is_active)
- critical_systems (id, asset_id, software_id, system_name, business_function_id, criticality, impact_description,
  recovery_procedures, failover_mechanism, maximum_tolerable_outage, work_around_exists, work_around_description,
  last_bia_review, next_bia_review, bia_reviewer_id, is_verified, verified_by, verified_at)
- system_dependencies (id, dependent_system_id, dependency_system_id, dependency_type, is_critical, failover_possible,
  failover_details, max_dependency_outage)
- recovery_contacts (id, critical_system_id, contact_type, name, role, phone, email, is_primary, escalation_order)
- bia_status_history (id, critical_system_id, status, previous_status, change_reason, triggered_by, created_at)
- recovery_plans (id, critical_system_id, name, description, steps, test_frequency, last_test_date, next_test_date,
  owner)
- recovery_tests (id, plan_id, test_date, status, results, participants, issues, next_test_date)

**API Endpoints:**

- GET /api/v1/bia/business-functions
- POST /api/v1/bia/business-functions
- GET /api/v1/bia/business-functions/{id}
- PUT /api/v1/bia/business-functions/{id}
- GET /api/v1/bia/critical-systems
- POST /api/v1/bia/critical-systems
- GET /api/v1/bia/critical-systems/{id}
- PUT /api/v1/bia/critical-systems/{id}
- GET /api/v1/bia/dependencies
- POST /api/v1/bia/dependencies
- GET /api/v1/bia/recovery-contacts
- POST /api/v1/bia/recovery-contacts
- GET /api/v1/bia/recovery-plans
- POST /api/v1/bia/recovery-plans
- POST /api/v1/bia/recovery-plans/{id}/test
- GET /api/v1/bia/reports/impact
- GET /api/v1/bia/reports/recovery
- GET /api/v1/bia/dashboard

---

### Phase 8: Vendor Management

**Scope:** Implement vendor profiles, contact management, contract tracking, and asset association.

**Deliverables:**

- Define Sea-ORM entities for vendors, vendor_contacts, vendor_contracts, and vendor_contract_assets
- Create database migrations for vendor schema
- Implement vendor profile CRUD endpoints
- Define vendor_type enum (software_publisher, hardware_manufacturer, cloud_provider, service_provider, distributor,
  consultant, integrator, telecom)
- Implement vendor contact management with multiple contacts per vendor
- Define contact_type array (technical, sales, management, support, executive)
- Implement contract management with lifecycle tracking
- Define contract_type enum (support, maintenance, license, subscription, service_level, professional_services,
  cloud_usage, hosting)
- Implement payment_term tracking with frequency
- Define payment_frequency enum (one_time, monthly, quarterly, annually, multi_year)
- Create contract status tracking with automatic expiration detection
- Define contract_status enum (draft, pending, active, expiring, expired, terminated, renewed)
- Implement asset-contract association with coverage tracking
- Define coverage_type enum (hardware, software, support, updates, security_patches, all)
- Create support SLA tracking with response time metrics
- Implement vendor performance evaluation
- Create renewal alerts and notification triggers
- Define auto-renewal with notice period tracking
- Implement vendor metadata and document storage
- Create web UI for vendor management and contract tracking
- Build vendor dashboard with contract summaries and renewal alerts

**Database Tables:**

- vendors (id, name, slug, description, website, vendor_type, primary_contact_id, support_portal, support_email,
  support_phone, tax_id, payment_terms, logo_url, is_active)
- vendor_contacts (id, vendor_id, name, role, title, department, email, phone, mobile, contact_type, is_primary)
- vendor_contracts (id, vendor_id, contract_number, contract_type, title, description, start_date, end_date, auto_renew,
  renewal_notice_days, value, currency, payment_frequency, status, documents)
- vendor_contract_assets (id, contract_id, asset_id, software_id, coverage_type, coverage_details,
  service_level_agreement, response_time_hours)
- vendor_performance (id, vendor_id, period_start, period_end, sla_compliance, incident_count, response_time_avg,
  quality_score, notes)
- vendor_documents (id, vendor_id, contract_id, name, file_path, file_type, uploaded_at, uploaded_by)

**API Endpoints:**

- GET /api/v1/vendors
- POST /api/v1/vendors
- GET /api/v1/vendors/{id}
- PUT /api/v1/vendors/{id}
- DELETE /api/v1/vendors/{id}
- GET /api/v1/vendors/{id}/contacts
- POST /api/v1/vendors/{id}/contacts
- GET /api/v1/vendors/{id}/contracts
- POST /api/v1/vendors/{id}/contracts
- GET /api/v1/vendors/{id}/assets
- GET /api/v1/vendors/{id}/performance
- GET /api/v1/contracts
- GET /api/v1/contracts/{id}
- PUT /api/v1/contracts/{id}
- GET /api/v1/contracts/expiring
- POST /api/v1/contracts/{id}/renew
- GET /api/v1/vendors/dashboard

---

### Phase 9: Notification System

**Scope:** Implement multi-channel notification delivery, trigger configuration, webhook management, and notification
logging.

**Deliverables:**

- Define Sea-ORM entities for notification_triggers, notification_subscriptions, notification_templates, and
  webhook_endpoints
- Create database migrations for notification schema
- Implement notification template management
- Define notification_channel enum (email, webhook, slack, teams, push, sms, desktop)
- Define body_format enum (text, html, markdown, json)
- Implement trigger configuration with event-based rules
- Define event_type enum (asset_created, asset_updated, asset_deleted, asset_offline, vulnerability_detected,
  vulnerability_resolved, configuration_changed, configuration_failed, compliance_status_changed, certificate_expiring,
  bia_status_changed, custom)
- Create condition-based trigger filtering with JSON conditions
- Define notification_priority enum (low, normal, high, critical)
- Implement multi-channel delivery with channel-specific configuration
- Create email delivery using lettre crate with SMTP
- Implement webhook delivery with HMAC-BLAKE3 signature verification
- Define webhook_auth_type enum (none, basic, bearer, hmac, oauth2)
- Implement Slack integration with webhook URLs
- Implement Microsoft Teams integration with webhook URLs
- Create SMS delivery through configurable gateway
- Implement push notification support
- Define cooldown and rate limiting per trigger
- Create notification history with delivery status tracking
- Define notification_status enum (pending, sent, delivered, failed, bounced)
- Implement retry logic with exponential backoff
- Create escalation workflows with time-based rules
- Define custom event support with API triggers
- Implement notification aggregation to prevent fatigue
- Create web UI for notification configuration and history
- Build notification dashboard with delivery metrics

**Database Tables:**

- notification_templates (id, name, description, channel, subject_template, body_template, body_format, variables,
  is_default, is_active)
- notification_triggers (id, name, description, event_type, conditions, actions, priority, is_enabled, cooldown_seconds,
  schedule, created_by)
- notification_subscriptions (id, user_id, team_id, trigger_id, channel, destination, is_verified, last_delivered_at,
  delivery_count, failure_count, is_active)
- webhook_endpoints (id, name, description, url, secret, headers, auth_type, auth_credentials, events, is_active,
  last_response_status, failure_count)
- notification_log (id, trigger_id, subscription_id, channel, status, subject, body, attempt_count, error_message,
  delivered_at, metadata)
- notification_aggregates (id, trigger_id, user_id, channel, events, last_notified_at, next_allowed_at)

**API Endpoints:**

- GET /api/v1/notifications/triggers
- POST /api/v1/notifications/triggers
- GET /api/v1/notifications/triggers/{id}
- PUT /api/v1/notifications/triggers/{id}
- DELETE /api/v1/notifications/triggers/{id}
- POST /api/v1/notifications/triggers/{id}/test
- GET /api/v1/notifications/subscriptions
- POST /api/v1/notifications/subscriptions
- GET /api/v1/notifications/templates
- POST /api/v1/notifications/templates
- GET /api/v1/notifications/webhooks
- POST /api/v1/notifications/webhooks
- GET /api/v1/notifications/webhooks/{id}/test
- GET /api/v1/notifications/history
- GET /api/v1/notifications/history/{id}
- POST /api/v1/notifications/send
- GET /api/v1/notifications/dashboard

---

### Phase 10: Agent Communication Security and Configuration Management

**Scope:** Implement mTLS certificate management, message signing, configuration persistence, and environment-based
configuration.

**Deliverables:**

- Implement Certificate Authority using rcgen crate
- Create agent certificate issuance and management endpoints
- Define certificate expiry and renewal workflows with configurable renewal days
- Implement X.509 certificate parsing using x509-parser crate
- Create certificate revocation list (CRL) management
- Implement mTLS mutual authentication for agent-server communication
- Define agent registration flow with initial token authentication
- Implement certificate renewal endpoint with CSR submission
- Create message signing using ed25519 crate with constant-time operations
- Implement XChaCha20-Poly1305 encryption for all agent-server communication
- Define X25519 key exchange for forward secrecy
- Implement secure offline queue with encryption and local storage
- Create agent configuration push with versioned configurations
- Define configuration loading from environment variables
- Implement configuration file parsing (YAML, TOML, JSON)
- Create runtime configuration API with immediate application
- Implement configuration persistence to database for restart consistency
- Define configuration schema with validation rules
- Create configuration versioning with rollback support
- Implement configuration change auditing with full history
- Define configuration export and import functionality
- Create configuration templates for common deployments
- Implement environment-specific configuration profiles
- Define all configuration with environment variable overrides (HORIZON\_\* prefix)
- Create secure credential storage with encryption at rest
- Implement configuration diff and comparison tools
- Create web UI for configuration management and monitoring

**Database Tables:**

- certificate_authorities (id, name, private_key, public_key, not_before, not_after, is_active)
- agent_certificates (id, agent_id, serial_number, certificate, private_key, not_before, not_after, status, renewed_at)
- configuration_versions (id, key, version, value, created_at, created_by, change_reason)
- configuration_history (id, key, old_value, new_value, actor_type, actor_id, change_reason, created_at)
- configuration_templates (id, name, description, environment, config_data, is_default)
- credentials (id, name, encrypted_value, algorithm, key_version, created_at, updated_at)

**API Endpoints:**

- POST /api/v1/agents/register
- POST /api/v1/agents/{id}/certificates
- POST /api/v1/agents/{id}/certificates/renew
- GET /api/v1/agents/{id}/config
- POST /api/v1/agents/{id}/config
- GET /api/v1/system/config
- PUT /api/v1/system/config/{key}
- PATCH /api/v1/system/config
- POST /api/v1/system/config/validate
- POST /api/v1/system/config/export
- POST /api/v1/system/config/import
- GET /api/v1/system/config/history
- POST /api/v1/system/config/rollback
- GET /api/v1/credentials
- POST /api/v1/credentials
- GET /api/v1/configuration/templates
- POST /api/v1/configuration/templates

---

### Phase 11: AI Inference Providers and Local Model Integration

**Scope:** Implement multi-provider AI inference, CLI tool integration, and local model support only when strictly
needed.

**Deliverables:**

- Define AI provider abstraction layer with trait-based design
- Implement OpenAI API integration using async-openai crate
- Implement Anthropic API integration using anthropic crate
- Implement GitHub Copilot API integration
- Define provider selection strategies (default, cost_optimal, speed_optimal, quality_optimal, round_robin,
  per_analysis_type)
- Create CLI provider integration using tokio::process for opencode CLI
- Create CLI provider integration for github-copilot CLI
- Define LocalModelConfig for local inference when strictly needed
- Implement candle and onnxruntime for local model execution
- Create pre-trained ONNX model embedding at build time
- Define model cache with TTL for inference results
- Implement AI inference API with provider selection
- Define analysis_type enum (security_configuration, vulnerability_assessment, anomaly_detection,
  recommendation_generation, data_quality)
- Create prompt template management with variable substitution
- Implement inference timeout and retry logic
- Define usage tracking and cost estimation per provider
- Create response caching for repeated queries
- Implement fallback chain for provider failures
- Define model versioning for local models
- Create local model registry with metadata
- Implement batch inference for large datasets
- Define streaming response support for compatible providers
- Create AI configuration API with provider settings
- Implement API key management with encryption at rest
- Define usage quotas and rate limits per provider
- Create web UI for AI provider management and monitoring
- Build AI inference dashboard with usage metrics

**Database Tables:**

- ai_providers (id, name, provider_type, config, is_enabled, is_default, priority, rate_limit, cost_per_1k_tokens)
- ai_provider_credentials (id, provider_id, encrypted_key, key_version, created_at, updated_at)
- ai_prompt_templates (id, name, analysis_type, template, variables, description)
- ai_inference_logs (id, request_id, provider_id, analysis_type, prompt, response, tokens_used, latency_ms, cost,
  status)
- ai_model_registry (id, name, model_type, file_path, version, parameters, is_embedded, embedding_size)
- ai_cache (id, key, response, analysis_type, ttl_seconds, created_at)

**API Endpoints:**

- GET /api/v1/ai/providers
- POST /api/v1/ai/providers
- GET /api/v1/ai/providers/{id}
- PUT /api/v1/ai/providers/{id}
- POST /api/v1/ai/providers/{id}/test
- GET /api/v1/ai/providers/{id}/credentials
- POST /api/v1/ai/providers/{id}/credentials
- POST /api/v1/ai/analyze
- POST /api/v1/ai/analyze/{analysis_type}
- GET /api/v1/ai/prompts
- POST /api/v1/ai/prompts
- GET /api/v1/ai/prompts/{id}
- GET /api/v1/ai/models
- GET /api/v1/ai/usage
- GET /api/v1/ai/costs
- POST /api/v1/ai/cache/clear
- GET /api/v1/ai/dashboard

---

### Phase 12: Import/Export and Data Interoperability

**Scope:** Implement CSV, Excel, JSON, XML import/export for all data types with validation and field mapping.

**Deliverables:**

- Implement CSV parsing and generation using csv crate
- Implement Excel file reading and writing using calamine crate
- Create JSON import/export with nested structure support
- Implement XML import/export for legacy system compatibility
- Define field mapping system for different column names
- Create import validation with error reporting and line numbers
- Implement duplicate detection and conflict resolution strategies
- Define ConflictResolution enum (skip, overwrite, merge, error)
- Create batch import with transaction safety and rollback
- Implement progress tracking for large imports
- Define import templates for common data types
- Create export filters with query parameter support
- Implement selective column export with field selection
- Define export formats enum (csv, xlsx, json, xml, zip)
- Create complete system export as ZIP archive
- Implement password-protected export files
- Define import preview mode with dry-run capability
- Create validation rules engine for imports
- Implement bulk operations with bulk_update and bulk_delete
- Define data transformation pipeline for imports
- Create web UI for import/export with drag-and-drop
- Build import wizard with field mapping interface
- Implement export scheduling and notification

**Database Tables:**

- import_templates (id, name, data_type, field_mapping, validation_rules, created_by, created_at)
- import_jobs (id, template_id, file_name, file_path, status, total_records, processed_records, failed_records,
  started_at, completed_at, error_log)
- export_templates (id, name, data_type, filters, field_selection, format, created_by, created_at)
- export_jobs (id, template_id, file_name, file_path, status, record_count, started_at, completed_at)

**API Endpoints:**

- POST /api/v1/import/preview
- POST /api/v1/import/execute
- POST /api/v1/import/templates
- GET /api/v1/import/templates
- GET /api/v1/import/jobs
- GET /api/v1/import/jobs/{id}
- GET /api/v1/export
- POST /api/v1/export
- GET /api/v1/export/{id}
- GET /api/v1/export/download/{id}
- POST /api/v1/export/templates
- GET /api/v1/export/templates
- POST /api/v1/data/validate
- POST /api/v1/data/transform

---

### Phase 13: Desktop Application

**Scope:** Implement Tauri-based desktop application with multi-server profiles, offline mode, and system integration.

**Deliverables:**

- Create Tauri project with Rust backend and React frontend
- Implement multi-server profile management with profile switching
- Define ServerProfile struct with url, name, credentials
- Implement local SQLite cache using rusqlite for offline data
- Create offline data synchronization with conflict resolution
- Implement system tray integration with tauri-plugin-tray
- Define tray menu with quick actions and status
- Create native notification delivery using tauri-plugin-notification
- Implement window vibrancy and native appearance
- Create agent management UI for local agent installation and monitoring
- Implement import/export UI with file picker integration
- Define keyboard shortcuts for common actions
- Create dark/light theme switching
- Implement global search across all data
- Define connection status indicator with automatic reconnection
- Implement background task execution for synchronization
- Create clipboard integration for quick data copy
- Define deep linking support for opening specific records
- Implement credential storage with system keyring integration
- Create startup at login option
- Define window state persistence (position, size, maximized)
- Implement update checking and notification
- Create about and help pages
- Build desktop-specific settings page
- Implement analytics and crash reporting opt-in
- Create installer packages (.msi, .dmg, .deb, .rpm)

**Database Tables (Local Cache):**

- cache_profiles (id, name, server_url, last_sync_at, sync_status)
- cache_sync_history (id, profile_id, entity_type, last_sync_id, synced_at, status)
- cache_offline_queue (id, profile_id, operation, entity_type, entity_id, data, created_at)

**Desktop API (Tauri Commands):**

- profile.list
- profile.add
- profile.remove
- profile.switch
- sync.now
- sync.status
- agent.install
- agent.status
- agent.uninstall
- import.file
- export.file
- notification.show
- shortcut.register
- window.setAlwaysOnTop
- credentials.store
- credentials.get

---

### Phase 14: Docker and Production Deployment

**Scope:** Implement complete Docker deployment with Kubernetes manifests, Helm chart, and production infrastructure.

**Deliverables:**

- Create multi-stage Dockerfile for server with rust:1.94-nightly-slim base
- Create multi-stage Dockerfile for agent with alpine:3.21 base
- Create Dockerfile for web application with node:22-alpine
- Define Docker Compose file with all services (postgres, redis, server, worker, web)
- Configure health checks for all services
- Define environment variable configurations for all services
- Implement volume mounts for persistence (postgres, redis, uploads, logs)
- Create network configuration with internal service network
- Define secrets management with environment files
- Create Kubernetes Deployment manifests for server
- Create Kubernetes Service manifest with type LoadBalancer
- Create Kubernetes ConfigMap for configuration
- Create Kubernetes Secret for sensitive data
- Create Kubernetes Ingress with TLS termination
- Define resource limits and requests for all containers
- Create HorizontalPodAutoscaler for server scaling
- Define PodDisruptionBudget for zero-downtime updates
- Create PersistentVolumeClaims for database and cache
- Define StorageClass for dynamic provisioning
- Create Helm chart structure with values.yaml
- Implement Helm templates for all Kubernetes resources
- Define Helm hooks for database migrations
- Create Helm test manifests for validation
- Implement readiness and liveness probes
- Define pod anti-affinity for high availability
- Create network policies for namespace isolation
- Define service mesh integration (Istio/Linkerd optional)
- Implement backup and restore procedures
- Create monitoring dashboards with Prometheus metrics
- Define alerting rules for critical conditions
- Create log aggregation configuration (Fluentd/Loki)
- Implement tracing with Jaeger/Zipkin optional
- Define disaster recovery runbooks
- Create deployment documentation with runbooks
- Implement blue/green and canary deployment strategies
- Define secret rotation procedures
- Create certificate management with cert-manager optional

**Docker Images:**

- horizon/server:latest (rust:1.94-nightly-slim)
- horizon/worker:latest (rust:1.94-nightly-slim)
- horizon/agent:latest (alpine:3.21)
- horizon/web:latest (node:22-alpine)
- horizon/migrate:latest (for database migrations)

**Kubernetes Resources:**

- ConfigMap (horizon-config)
- Secret (horizon-secrets)
- Deployment (horizon-server, horizon-worker)
- Service (horizon-service)
- Ingress (horizon-ingress)
- HPA (horizon-server-hpa)
- PDB (horizon-server-pdb)
- PVC (horizon-postgres-pvc, horizon-redis-pvc)

**Helm Chart Structure:**

- Chart.yaml
- values.yaml
- templates/
  - configmap.yaml
  - secrets.yaml
  - deployment-server.yaml
  - deployment-worker.yaml
  - service.yaml
  - ingress.yaml
  - hpa.yaml
  - pdb.yaml
  - pvc.yaml
  - tests/
    - connectivity.yaml

---

### Phase 15: Testing, Security Hardening, and Documentation

**Scope:** Implement comprehensive testing, security audit, and complete documentation.

**Deliverables:**

- Implement unit tests for all core business logic with coverage >80%
- Create integration tests for all API endpoints
- Implement end-to-end tests for critical user workflows
- Create load testing scenarios with k6 or similar
- Define performance benchmarks for API responses
- Create fuzzing tests for input validation
- Implement security testing with OWASP ZAP
- Conduct third-party penetration testing
- Create security audit report with findings and remediation
- Define compliance mapping for SOC 2 and ISO 27001
- Implement audit logging for all security-relevant events
- Create security hardening guide
- Define incident response procedures
- Implement rate limiting and DDoS protection
- Create API documentation with OpenAPI 3.0 specification
- Generate Swagger UI for API documentation
- Create architecture documentation with diagrams
- Write user documentation for all features
- Create API client libraries for common languages
- Define migration guides for version upgrades
- Create troubleshooting guides for common issues
- Implement health check endpoints (/health, /ready, /metrics)
- Define SLA and performance targets
- Create runbooks for operational tasks
- Implement feature flags for controlled rollouts
- Define deprecation policy and migration paths
- Create contribution guidelines for external developers
- Implement code review checklist
- Define coding standards and style guides
- Create security vulnerability disclosure procedure
- Implement bug bounty program documentation

---

## 13. Technical Decisions and Justifications

### 13.1 Encryption: Best Security Standards with RustCrypto

| Operation            | Algorithm         | Crate                | Justification                       |
| -------------------- | ----------------- | -------------------- | ----------------------------------- |
| Password Hashing     | Argon2id          | **argon2**           | Gold standard, GPU/ASIC resistant   |
| Symmetric Encryption | XChaCha20-Poly1305 | **chacha20poly1305** | Constant-time, no timing attacks    |
| Hashing              | BLAKE3            | **blake3**           | Faster than SHA-2/3, SIMD-optimized |
| Backup Hashing       | SHA3              | **sha3**             | NIST standard alternative           |
| MAC                  | HMAC-BLAKE3       | **hmac**             | Message authentication              |
| Signatures           | Ed25519           | **ed25519**          | Modern high-security signatures     |
| Key Exchange         | X25519            | **x25519**           | Modern ECDH                         |

### 13.2 AI: Inference-First Strategy

AI is provided through inference providers (remote APIs and CLI tools). Local ML models are only used when strictly
necessary and are pre-trained at build time.

### 13.3 Version Policy

Always use the latest available versions with Rust minimum 1.94.0-nightly.

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

- React, TypeScript, Vite
- Tailwind CSS, shadcn/ui

**Desktop Stack:**

- Tauri, React

**Deployment:**

- Docker, Docker Compose
- Kubernetes, Helm

---

_This implementation plan uses the highest security standards and latest technology versions. All cryptographic
operations use RustCrypto with Argon2id, XChaCha20-Poly1305, BLAKE3, Ed25519, and X25519. AI is provided through
inference providers with local models only when strictly necessary._
