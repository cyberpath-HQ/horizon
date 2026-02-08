# Horizon Implementation Plan

## Cyberpath Horizon - CMDB and Asset Inventory System

**Version:** 5.0.0  
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

---

## 2. Introduction and Vision

### 2.1 Purpose and Scope

Horizon provides organizations with complete control over their IT asset data through a self-hostable solution with no
licensing costs and complete data ownership.

### 2.2 Strategic Goals

- **Comprehensiveness**: Capture all information relevant to IT asset management
- **Automation**: Lightweight agent collection with minimal configuration
- **Flexibility**: Support both automated and manual data entry
- **Integrity**: Complete audit trails and data quality assessment
- **Intelligence**: AI-powered pattern recognition via inference providers
- **Accessibility**: Multiple interfaces including web and desktop applications

---

## 3. Architecture Overview

### 3.1 High-Level Architecture

Three-tier architecture with presentation layer (web/desktop), business logic layer (API server with AI inference), and
data persistence layer (PostgreSQL and Redis).

### 3.2 Technology Stack Selection

**Version Policy:** All components use the latest stable or nightly versions available. Rust version requirement:
**minimum 1.94.0-nightly**.

**Core Crates:**

| Category        | Primary Crates                         | Purpose                            |
| --------------- | -------------------------------------- | ---------------------------------- |
| Web Framework   | **axum**, **tokio**, **tower**         | REST API server with async support |
| Database ORM    | **sea-orm**, **sqlx**                  | Entity management with migrations  |
| Database Driver | **tokio-postgres**, **postgres-types** | PostgreSQL driver                  |
| Redis           | **redis-rs**                           | Caching and session management     |
| Serialization   | **serde**, **serde_json**, **prost**   | JSON and Protocol Buffer handling  |
| Error Handling  | **thiserror**, **anyhow**              | Error types and propagation        |
| Logging         | **tracing**, **tracing-subscriber**    | Structured logging                 |

**Encryption Stack (RustCrypto - Best Security Standards):**

| Operation            | Crate                    | Algorithm          |
| -------------------- | ------------------------ | ------------------ |
| Password Hashing     | **argon2**               | Argon2id           |
| Symmetric Encryption | **chacha20poly1305**     | XChaCha20-Poly1305 |
| Hashing              | **blake3**               | BLAKE3             |
| Backup Hashing       | **sha3**                 | SHA3-256/512       |
| MAC                  | **hmac**                 | HMAC-BLAKE3        |
| Digital Signatures   | **ed25519**              | Ed25519            |
| Key Exchange         | **x25519**               | X25519             |
| Random               | **rand** + **getrandom** | CSPRNG             |
| Memory Clearing      | **zeroize**              | N/A                |

**AI Providers (Inference-First):**

| Provider           | Type             | Integration Method |
| ------------------ | ---------------- | ------------------ |
| **OpenAI**         | Remote Inference | REST API           |
| **Anthropic**      | Remote Inference | REST API           |
| **GitHub Copilot** | Remote Inference | REST API           |
| **opencode**       | CLI Inference    | Subprocess         |
| **copilot-cli**    | CLI Inference    | Subprocess         |

---

## 4. Core Components

### 4.1 API Server

| Module         | Primary Crates                                                         | Purpose                  |
| -------------- | ---------------------------------------------------------------------- | ------------------------ |
| Authentication | **axum**, **jsonwebtoken**, **argon2**, **totp**                       | User login, token, MFA   |
| Assets         | **sea-orm**, **sqlx**, **serde**                                       | CRUD operations          |
| AI Providers   | **reqwest**, **async-openai**, **anthropic**, **tokio::process**       | Remote and CLI AI        |
| Encryption     | **chacha20poly1305**, **blake3**, **ed25519**, **argon2**, **zeroize** | Cryptographic operations |
| Notifications  | **lettre**, **reqwest**, **hmac**                                      | Email, webhooks          |

### 4.2 Database Layer

PostgreSQL (latest) with Redis (latest) for caching.

### 4.3 Agent Communication Service

mTLS with server-issued certificates and bidirectional Ed25519 message signing.

---

## 5. Database Schema Design

Core entity models for assets, software, vulnerabilities, BIA, vendors, notifications, and configuration.

---

## 6. API Design Specification

RESTful API with hierarchical resource organization, JWT-based authentication, and comprehensive endpoints.

---

## 7. Agent Architecture and Design

Lightweight agent (<50MB memory) with RustCrypto encryption (ChaCha20-Poly1305, Ed25519, X25519, Argon2id).

---

## 8. Feature Specifications

Asset inventory, network flow mapping, vulnerability management, security configuration, BIA, vendor management, and
notification systems.

---

## 9. Security Framework

- Argon2id for password hashing
- ChaCha20-Poly1305 for symmetric encryption
- BLAKE3 for general hashing
- Ed25519 for digital signatures
- X25519 for key exchange
- Zeroize for secure memory clearing

---

## 10. Configuration Management

Three-level hierarchy: Runtime API, Environment Variables (HORIZON\_\*), Configuration Files.

---

## 11. Docker Deployment

Docker Compose with PostgreSQL, Redis, server, worker, web. Kubernetes manifests and Helm chart.

---

## 12. Implementation Phases

### Group A: Foundation

#### A-01: Project Infrastructure Setup

- Initialize Rust workspace with Cargo.toml defining core dependencies
- Configure Git repository with branch protection rules
- Set up GitHub Actions CI/CD pipeline for testing and linting
- Create development environment documentation in README.md

#### A-02: Docker Development Environment

- Define Docker Compose configuration for PostgreSQL
- Define Docker Compose configuration for Redis
- Configure internal network for service communication
- Create environment file template for all services

#### A-03: Logging and Error Handling Infrastructure

- Implement tracing and logging infrastructure with structured JSON output
- Define API response types using thiserror
- Implement error handling middleware with anyhow propagation
- Configure log levels and output formats for all environments

#### A-04: Database Migrations Infrastructure

- Set up Sea-ORM connection to PostgreSQL
- Create migration runner with up/down functionality
- Implement migration version tracking table
- Create seeds for enum values and default data

---

### Group B: Authentication

#### B-01: User and Team Database Schema

- Define users table (id, email, username, password_hash, totp_secret, status, created_at, updated_at)
- Define teams table (id, name, slug, description, parent_team_id, manager_id, created_at)
- Define team_members table (id, team_id, user_id, role, joined_at)
- Create Sea-ORM entities for users, teams, and team_members.
- Write migrations for authentication schema
- create an entity generation and reconciliation script to create new entities as needed, and update existing ones. this
  will be used instead of the default sea-orm codegen tool to ensure consistency across the project. default tool
  overwrites everything. this script will be idempotent and can be run as part of the build process or CI/CD pipeline.
  It will use the command line interface to generate entities based on the current database schema, and will compare the
  generated entities with the existing ones in the codebase. it will overwrite everything but keep any customization
  made within a set of designated regions (e.g., between special comments). the called cli uses the `migration` crate
  and provides at least the following options (check command line options for sea-orm-cli for more ideas and additional
  cli flags):
  - `--with-serde`
  - `--impl-active-model-behavior`
  - `--entity-format dense`
  - `--serde-skip-hidden-column`

#### B-02: Role-Based Access Control Schema

- Define roles table (id, name, slug, description, permissions, is_system, created_at)
- Define user_roles table (id, user_id, role_id, scope_type, scope_id, expires_at, assigned_at)
- Define api_keys table (id, user_id, name, key_hash, key_prefix, permissions, expires_at, last_used_at)
- Create Sea-ORM entities for roles, user_roles, and api_keys
- Write migrations for RBAC schema

#### B-03: Password Authentication Implementation

- Implement Argon2id password hashing using argon2 crate
- Create password hashing and verification functions
- Implement initial setup endpoint for first-user creation (POST /api/v1/auth/setup), this must be disabled after first
  user creation
- Implement login endpoint (POST /api/v1/auth/login)
- Implement logout endpoint (POST /api/v1/auth/logout)

#### B-04: JWT Token Management

- Implement JWT authentication middleware using jsonwebtoken crate
- Create access token generation and validation
- Create refresh token generation and storage
- Implement token refresh endpoint (POST /api/v1/auth/refresh)
- Implement session storage in Redis with token blacklisting

#### B-05: Multi-Factor Authentication

- Implement TOTP MFA using totp crate
- Create TOTP secret generation and QR code display
- Implement MFA verification endpoint (POST /api/v1/auth/mfa/verify)
- Create MFA enable/disable functionality
- Implement backup codes generation and storage

#### B-06: User and Team API Endpoints

- Implement user profile endpoints (GET/PUT /api/v1/users/me)
- Implement user list endpoint (GET /api/v1/users)
- Implement team CRUD endpoints (GET/POST /api/v1/teams)
- Implement team member management (POST /api/v1/teams/{id}/members)
- Implement API key management endpoints

#### B-07: Rate Limiting and Security Middleware

- Implement rate limiting middleware using Redis sorted sets
- Configure per-endpoint rate limits based on sensitivity
- Implement IP-based rate limiting rules
- Add security headers (CSP, X-Frame-Options, etc.) to all responses
- Add MFA enforcement middleware for sensitive endpoints
- Implement account lockout after multiple failed login attempts
- Implement password complexity validation
- Add MFA verification requirement on login if enabled

#### B-08: API Access

- Implement API key authentication middleware
- Create API key generation endpoint (POST /api/v1/auth/api-keys)
- Implement API key revocation endpoint (DELETE /api/v1/auth/api-keys/{id})
- Implement API key usage tracking and last used timestamp update
- Create API key permission scope enforcement
- Implement API key expiration handling
- Create API key listing endpoint (GET /api/v1/auth/api-keys)
- Implement API key rotation functionality
- Create API key usage audit logging
- Implement API key prefix matching for authentication
- Create API key search and filtering functionality
- Implement API key rate limiting based on key permissions (configurable)
- Create API key detailed view endpoint (GET /api/v1/auth/api-keys/{id})
- Implement API key usage statistics endpoint (GET /api/v1/auth/api-keys/{id}/usage)
- Implement API key permission modification endpoint (PUT /api/v1/auth/api-keys/{id}/permissions)
- ensure that api keys cannot be used to access user management endpoints unless explicitly granted the necessary
  permissions. This includes restricting access to user creation, deletion, and role assignment endpoints.
- ensure all permissions of the user associated with the api key are checked before allowing any action. if the user has
  been deactivated or had their roles changed, the api key should reflect those changes immediately.
- ensure all api keys are logged with their usage, including timestamp, endpoint accessed, and action performed for
  auditing purposes.
- ensure all api keys are linked to their creator user for accountability.

---

### Group C: Web Frontend Foundation

#### C-01: React Application Setup

- Create React application with Vite and TypeScript
- Configure Tailwind CSS and shadcn/ui component library
- Set up React Router for client-side routing
- Configure environment variables for API URL
- Set up build optimization and code splitting

#### C-02: Authentication Pages

- Implement login page with email/password form
- Implement setup page with validation
- Implement MFA verification page
- Create password reset request and reset pages
- Implement session timeout and refresh handling

#### C-03: Layout and Navigation Components

- Create main application layout with sidebar
- Implement navigation menu with role-based visibility
- Create header with user menu and notifications
- Implement breadcrumb navigation
- Create page wrapper with loading states

#### C-04: Session and Token Management

- Implement JWT token storage (localStorage/secure storage)
- Create authentication context and provider
- Implement automatic token refresh on expiration
- Handle authentication state changes across the app
- Implement logout on all tabs/sessions

---

### Group D: Asset Inventory Core

#### D-01: Asset Type Schema and API

- Define asset_types table (id, parent_id, name, slug, description, icon, color, metadata_schema, is_active)
- Define assets table (id, inventory_number, asset_type_id, name, description, serial_number, manufacturer, model,
  owner_id, custodian_id, status, tags, custom_attributes, agent_id, bia_criticality, last_seen_at, created_by,
  created_at, updated_at)
- Create Sea-ORM entities for asset_types and assets
- Write migrations for asset schema
- Implement asset type CRUD endpoints

#### D-02: Asset CRUD API Endpoints

- Implement asset list endpoint with filtering, pagination, and sorting
- Implement asset create endpoint (POST /api/v1/assets)
- Implement asset detail endpoint (GET /api/v1/assets/{id})
- Implement asset update endpoint (PUT /api/v1/assets/{id})
- Implement asset delete endpoint (DELETE /api/v1/assets/{id})

#### D-03: Asset Relationships Schema and API

- Define asset_relationships table (id, source_asset_id, target_asset_id, relationship_type, metadata, strength,
  is_active)
- Define relationship strength enum (strong, medium, weak, unknown)
- Create Sea-ORM entity for asset_relationships
- Implement relationship CRUD endpoints
- Implement relationship query by asset

#### D-04: Asset History Tracking

- Define asset_history table (id, asset_id, action, field_name, old_value, new_value, actor_type, actor_id, actor_name,
  change_reason, created_at)
- Define actor_type enum (user, agent, system, import, api)
- Create Sea-ORM entity for asset_history
- Implement history recording on all asset changes
- Implement history query endpoint (GET /api/v1/assets/{id}/history)

#### D-05: Asset Search and Full-Text Search

- Implement PostgreSQL full-text search for assets
- Create search index on name, description, serial_number, manufacturer, model
- Implement search endpoint with query parameters
- Add search suggestions/autocomplete functionality
- Implement search result highlighting

#### D-06: Asset Import Functionality

- Implement CSV import for assets
- Implement field mapping for different column names
- Create validation rules for required fields
- Implement conflict detection and resolution
- Create import preview with dry-run capability

#### D-07: Web UI for Asset Management

- Create asset list page with filtering and pagination
- Create asset detail page with tabs (info, relationships, history, software, vulnerabilities)
- Create asset create/edit forms with validation
- Create asset type management page
- Implement bulk operations UI

---

### Group E: Agent Foundation

#### E-01: Agent Project Setup

- Create agent Rust project as workspace member
- Implement agent command-line interface with clap
- Define agent configuration loading from environment and files
- Create logging infrastructure for agent
- Set up agent update mechanism

#### E-02: Agent Platform Detection

- Implement platform detection (Linux, Windows, macOS)
- Create platform abstraction layer
- Implement OS-specific information collection
- Create unified system info struct
- Handle platform-specific edge cases

#### E-03: Agent Hardware Inventory Collection

- Implement CPU information collection (model, cores, frequency)
- Implement memory information collection (total, available, slots)
- Implement storage information collection (disks, SMART status)
- Implement network interface collection (MAC, speeds, addresses)
- Implement peripheral device enumeration

#### E-04: Agent OS and Software Inventory

- Implement OS information collection (kernel, distribution, hostname, uptime)
- Implement installed package collection (dpkg, rpm, brew, chocolatey, winget)
- Implement running service enumeration (systemctl, service, launchctl)
- Implement startup item detection
- Create normalized software inventory format

#### E-05: Agent Communication Protocol

- Define Protocol Buffers message format with prost
- Implement agent report message structure
- Create compression for report transmission
- Implement retry logic with exponential backoff
- Create offline queue with local SQLite storage

#### E-06: Server-Side Agent Registration

- Define agents table (id, asset_id, name, version, platform, last_seen_at, status, cert_expires_at)
- Create agent registration endpoint (POST /api/v1/agents/register)
- Implement agent status tracking
- Create agent dashboard in web UI
- Implement real-time status updates via WebSocket

---

### Group F: Software Management

#### F-01: Software Schema and API

- Define software_vendors, software_products, software_versions tables
- Define software_installations, software_licenses tables
- Create Sea-ORM entities for all software tables
- Write migrations for software schema
- Implement software product CRUD endpoints

#### F-02: Version Management

- Implement version string normalization with semantic versioning parsing
- Create version comparison functions
- Implement version parsing (major, minor, patch, build)
- Create version comparison API
- Implement version sorting and range queries

#### F-03: Software Installation Tracking

- Implement software installation tracking linked to assets
- Create installation discovery from agent reports
- Implement manual installation entry
- Create installation update and deletion
- Implement installation search and filtering

#### F-04: License Management

- Implement license tracking with license_key, license_type, seats
- Track license expiry dates and alerts
- Create license association with installations
- Implement license usage monitoring
- Create license compliance reports

#### F-05: Software Web UI

- Create software product list page
- Create product detail page with version history
- Create installation tracking page
- Create license management page
- Create software dashboard with statistics

---

### Group G: Security Configuration

#### G-01: Configuration Schema and Baselines

- Define security_baselines, baseline_rules, environments tables
- Define configuration_items, configuration_assessments, configuration_violations tables
- Create Sea-ORM entities for configuration tables
- Write migrations for configuration schema
- Implement baseline and rule CRUD endpoints

#### G-02: CIS Benchmark Support

- Define CIS benchmark data structure
- Implement CIS rule import functionality
- Create CIS rule validation queries
- Implement baseline assessment against CIS rules
- Create CIS compliance reporting

#### G-03: Configuration Assessment Engine

- Implement automated configuration assessment
- Create rule severity classification
- Implement deviation type detection
- Create compliance scoring algorithm
- Implement assessment scheduling

#### G-04: Configuration Drift Detection

- Implement configuration history tracking
- Create drift detection by comparison
- Implement drift alerts
- Create drift reporting
- Implement baseline versioning

#### G-05: AI Configuration Analysis

- Implement AI-powered configuration analysis
- Create configuration analysis prompt templates
- Implement remediation guidance generation
- Create violation severity assessment
- Implement AI analysis caching

#### G-06: Configuration Web UI

- Create baseline management page
- Create rule management page
- Create compliance dashboard
- Create violation tracking page
- Create configuration item explorer

---

### Group H: Vulnerability Management

#### H-01: Vulnerability Schema and CVE Sync

- Define vulnerability_sources, vulnerabilities, vulnerability_assessments tables
- Define penetration_test_engagements, penetration_test_findings tables
- Define red_team_engagements, red_team_findings tables
- Create Sea-ORM entities for vulnerability tables
- Write migrations for vulnerability schema
- Implement NVD API integration for CVE synchronization

#### H-02: Vulnerability-Asset Correlation

- Implement vulnerability-asset correlation through software mapping
- Create automatic vulnerability detection based on installed software
- Implement manual vulnerability assignment
- Create vulnerability search by asset
- Implement bulk vulnerability operations

#### H-03: Penetration Test Integration

- Implement penetration test engagement tracking
- Create finding management with evidence upload
- Implement retesting workflow
- Create finding-remediation tracking
- Implement pentest reporting

#### H-04: Red Team Integration

- Implement red team engagement tracking
- Create MITRE ATT&CK technique mapping
- Implement IOC tracking
- Create attack chain analysis
- Implement dwell time and detection metrics

#### H-05: Vulnerability Web UI

- Create vulnerability list page with filtering
- Create vulnerability detail page with affected assets
- Create pentest management page
- Create red team findings page
- Create security dashboard

---

### Group I: Network Flow Mapping

#### I-01: Network Schema and Interface Discovery

- Define subnets, network_interfaces, ip_addresses tables
- Define network_flows, flow_sessions, network_topology tables
- Create Sea-ORM entities for network tables
- Write migrations for network schema
- Implement interface discovery API

#### I-02: IP Address and Subnet Tracking

- Implement IPv4/IPv6 address tracking
- Create subnet management with CIDR notation
- Implement address allocation tracking
- Create DNS name resolution tracking
- Implement IP history and change tracking

#### I-03: Flow Collection and Aggregation

- Implement flow collection from agents
- Create flow parsing and normalization
- Implement session aggregation
- Create flow direction classification
- Implement flow statistics calculation

#### I-04: Network Topology and Visualization

- Implement topology discovery from interface connections
- Create topology visualization data structure
- Implement topology change detection
- Create topology export for graphing tools
- Implement link status tracking

#### I-05: Flow Analysis and Anomaly Detection

- Implement behavioral baselining
- Create anomaly detection using inference providers
- Implement unexpected traffic alerts
- Create flow comparison reports
- Implement bandwidth analysis

#### I-06: Network Web UI

- Create network topology visualization
- Create interface list page
- Create flow explorer page
- Create anomaly dashboard
- Create bandwidth reports

---

### Group J: Business Impact Analysis

#### J-01: BIA Schema and Business Functions

- Define business_functions, critical_systems tables
- Define system_dependencies, recovery_contacts tables
- Define bia_status_history, recovery_plans, recovery_tests tables
- Create Sea-ORM entities for BIA tables
- Write migrations for BIA schema
- Implement business function CRUD endpoints

#### J-02: Critical System Registry

- Implement critical system registration linked to assets/software
- Create criticality classification (critical, high, medium, low, non_critical)
- Implement RTO/RPO tracking
- Create financial impact tracking
- Implement maximum tolerable outage tracking

#### J-03: Dependency Mapping

- Implement system dependency registration
- Create dependency graph structure
- Implement impact cascade analysis
- Create dependency visualization data
- Implement dependency criticality scoring

#### J-04: Recovery Management

- Implement recovery procedures documentation
- Create recovery contact management
- Implement recovery plan creation
- Create recovery test tracking
- Implement BIA review scheduling

#### J-05: BIA Web UI

- Create business function management page
- Create critical system registry page
- Create dependency graph visualization
- Create recovery management page
- Create BIA dashboard

---

### Group K: Vendor Management

#### K-01: Vendor Schema and API

- Define vendors, vendor_contacts tables
- Define vendor_contracts, vendor_contract_assets tables
- Define vendor_performance, vendor_documents tables
- Create Sea-ORM entities for vendor tables
- Write migrations for vendor schema
- Implement vendor CRUD endpoints

#### K-02: Contract Management

- Implement contract lifecycle tracking
- Create contract status management (draft, pending, active, expiring, expired)
- Implement automatic expiration detection
- Create renewal alerts
- Implement auto-renewal with notice period

#### K-03: Asset-Vendor Association

- Implement asset-contract association
- Create coverage tracking by asset/software
- Implement SLA tracking
- Create vendor performance evaluation
- Implement contract asset reports

#### K-04: Vendor Web UI

- Create vendor management page
- Create contact management page
- Create contract management page
- Create vendor performance page
- Create vendor dashboard

---

### Group L: Notification System

#### L-01: Notification Schema and Templates

- Define notification_templates, notification_triggers tables
- Define notification_subscriptions, webhook_endpoints tables
- Define notification_log, notification_aggregates tables
- Create Sea-ORM entities for notification tables
- Write migrations for notification schema
- Implement template CRUD endpoints

#### L-02: Trigger Configuration

- Implement event-based trigger system
- Create condition-based filtering
- Define event types (asset_created, vulnerability_detected, etc.)
- Implement trigger CRUD endpoints
- Create trigger testing functionality

#### L-03: Multi-Channel Delivery

- Implement email delivery using lettre
- Implement webhook delivery with HMAC-BLAKE3 signatures
- Implement Slack integration
- Implement Microsoft Teams integration
- Implement push notification support

#### L-04: Notification Delivery Engine

- Implement notification queue processing
- Create retry logic with exponential backoff
- Implement delivery status tracking
- Create escalation workflows
- Implement notification aggregation

#### L-05: Notification Web UI

- Create trigger management page
- Create subscription management page
- Create webhook management page
- Create notification history page
- Create notification dashboard

---

### Group M: Agent Security and Configuration

#### M-01: Certificate Authority

- Implement Certificate Authority using rcgen crate
- Create agent certificate issuance workflow
- Implement certificate renewal endpoint
- Create certificate revocation list management
- Implement certificate validation

#### M-02: Agent mTLS Communication

- Implement mTLS mutual authentication
- Create agent registration with certificate issuance
- Implement certificate renewal with CSR
- Create agent configuration push
- Implement secure offline queue

#### M-03: Message Signing and Encryption

- Implement message signing using ed25519 crate with constant-time operations
- Implement ChaCha20-Poly1305 encryption for agent-server communication
- Implement X25519 key exchange for forward secrecy
- Create message validation and verification
- Implement secure message format

#### M-04: Runtime Configuration API

- Implement configuration loading from environment variables
- Implement configuration file parsing (YAML, TOML, JSON)
- Create runtime configuration API with immediate application
- Implement configuration persistence to database
- Create configuration versioning and rollback

#### M-05: Credential Storage

- Implement secure credential storage with encryption at rest
- Create credential CRUD API
- Implement credential encryption using ChaCha20-Poly1305
- Create credential access auditing
- Implement credential rotation support

---

### Group N: AI Inference Providers

#### N-01: AI Provider Abstraction Layer

- Define AI provider trait-based abstraction
- Create provider configuration structure
- Implement provider registry
- Create provider selection strategies
- Implement provider health checking

#### N-02: OpenAI Integration

- Implement OpenAI API integration using async-openai crate
- Create API key management for OpenAI
- Implement model selection and configuration
- Create prompt template management
- Implement OpenAI inference endpoint

#### N-03: Anthropic Integration

- Implement Anthropic API integration
- Create API key management for Anthropic
- Implement model selection and configuration
- Create Anthropic-specific prompt handling
- Implement Anthropic inference endpoint

#### N-04: GitHub Copilot Integration

- Implement GitHub Copilot API integration
- Create token management for Copilot
- Implement Copilot-specific prompts
- Create Copilot inference endpoint
- Implement token usage tracking

#### N-05: CLI Tool Integration

- Implement opencode CLI integration using tokio::process
- Implement copilot-cli integration
- Create CLI timeout and error handling
- Implement CLI output parsing
- Create CLI provider configuration

#### N-06: AI Inference API and Caching

- Implement unified AI inference API
- Create analysis type enumeration
- Implement response caching with TTL
- Create usage tracking and cost estimation
- Implement fallback chain for failures

#### N-07: AI Web UI

- Create AI provider management page
- Create prompt template editor
- Create AI usage dashboard
- Create cost tracking page
- Create inference log viewer

---

### Group O: Import/Export

#### O-01: CSV Import/Export

- Implement CSV parsing using csv crate
- Create CSV generation for all data types
- Implement field mapping for different column names
- Create validation rules engine
- Implement conflict resolution strategies

#### O-02: Excel Import/Export

- Implement Excel file reading using calamine crate
- Implement Excel file writing
- Create multi-sheet export support
- Implement cell formatting
- Create Excel template management

#### O-03: JSON/XML Import/Export

- Implement JSON import/export with nested structure support
- Implement XML import/export for legacy systems
- Create schema validation for imports
- Implement transformation pipeline
- Create data validation engine

#### O-04: Import/Export API

- Implement import preview endpoint
- Create import execution endpoint
- Implement export job creation
- Create export download endpoint
- Implement import/export job status tracking

#### O-05: Import/Export Web UI

- Create import wizard with file upload
- Create field mapping interface
- Create validation error display
- Create export configuration page
- Create job status dashboard

---

### Group P: Desktop Application

#### P-01: Tauri Project Setup

- Create Tauri project with Rust backend
- Configure React frontend for Tauri
- Set up build configuration for all platforms
- Create installer configuration
- Implement auto-update mechanism

#### P-02: Multi-Server Profile Management

- Implement server profile struct (url, name, credentials)
- Create profile CRUD operations
- Implement profile switching
- Create profile encryption for storage
- Implement profile import/export

#### P-03: Offline Mode and Caching

- Implement local SQLite cache using rusqlite
- Create offline data synchronization
- Implement conflict resolution
- Create sync status tracking
- Implement background sync jobs

#### P-04: System Tray and Notifications

- Implement system tray integration
- Create tray menu with quick actions
- Implement native notifications
- Create notification preferences
- Implement notification badge handling

#### P-05: Desktop UI Components

- Implement dark/light theme switching
- Create keyboard shortcuts
- Implement global search
- Create settings page
- Implement window state persistence

#### P-06: Desktop Agent Integration

- Create agent management UI
- Implement local agent installation
- Create agent status monitoring
- Implement agent configuration
- Create agent update handling

---

### Group Q: Docker and Kubernetes

#### Q-01: Server Docker Image

- Create multi-stage Dockerfile for server with rust:1.94-nightly-slim
- Optimize build for minimal image size
- Configure non-root user
- Create entrypoint script
- Set up health checks

#### Q-02: Agent Docker Image

- Create multi-stage Dockerfile for agent with alpine:3.21
- Include all agent dependencies
- Configure for containerized environments
- Create minimal agent variant
- Set up agent auto-update

#### Q-03: Web Docker Image

- Create Dockerfile for web application with node:22-alpine
- Build static files with Vite
- Configure nginx for serving
- Set up health checks
- Implement multi-stage build

#### Q-04: Docker Compose Configuration

- Define Docker Compose with all services
- Configure PostgreSQL with volume persistence
- Configure Redis with volume persistence
- Define environment variables
- Create network configuration

#### Q-05: Kubernetes Manifests

- Create ConfigMap for configuration
- Create Secret for sensitive data
- Create Deployment for server
- Create Service with LoadBalancer
- Create Ingress with TLS

#### Q-06: Kubernetes Scaling and Storage

- Create HorizontalPodAutoscaler
- Create PodDisruptionBudget
- Create PersistentVolumeClaims
- Define resource limits
- Implement readiness probes

#### Q-07: Helm Chart

- Create Helm chart structure
- Implement values.yaml with all configurations
- Create templates for all resources
- Define hooks for migrations
- Create test manifests

---

### Group R: Testing and Hardening

#### R-01: Unit Testing Infrastructure

- Set up test framework (rstest or standard lib tests)
- Create test utilities and fixtures
- Implement tests for core business logic
- Target 80% code coverage
- Create test data generators

#### R-02: API Integration Testing

- Create API integration tests
- Implement authentication testing
- Test all CRUD endpoints
- Test error handling
- Create test database fixtures

#### R-03: End-to-End Testing

- Set up Playwright for E2E tests
- Create critical workflow tests
- Test authentication flows
- Test major feature paths
- Create test reporting

#### R-04: Security Testing

- Implement security testing with OWASP ZAP
- Conduct third-party penetration testing
- Create security audit report
- Implement rate limiting tests
- Test authentication security05: API Documentation

#### R-

- Create OpenAPI 3.0 specification
- Generate Swagger UI
- Document all endpoints
- Create API examples
- Implement API versioning

#### R-06: Health Checks and Monitoring

- Implement /health endpoint
- Implement /ready endpoint
- Implement /metrics endpoint (Prometheus)
- Create health check documentation
- Define SLA targets

---

## 13. Technical Decisions and Justifications

### 13.1 Encryption: Best Security Standards with RustCrypto

- Argon2id for password hashing (GPU/ASIC resistant)
- ChaCha20-Poly1305 for encryption (constant-time)
- BLAKE3 for hashing (faster than SHA-2/3)
- Ed25519 for signatures (modern high-security)
- X25519 for key exchange (modern ECDH)

### 13.2 AI: Inference-First Strategy

AI provided through inference providers (remote APIs and CLI tools). Local models only when strictly necessary,
pre-trained at build time.

### 13.3 Version Policy

Always use latest available versions with Rust minimum 1.94.0-nightly.

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

_This implementation plan uses granular, PR-sized sub-phases. Each sub-phase contains 3-5 focused deliverables for
focused development and review._
