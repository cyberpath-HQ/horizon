# Horizon Implementation Plan

## Cyberpath Horizon - CMDB and Asset Inventory System

**Version:** 1.0.0  
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
10. [Implementation Phases](#implementation-phases)
11. [Technical Decisions and Justifications](#technical-decisions-and-justifications)
12. [Action Items and Roadmap](#action-items-and-roadmap)

---

## 1. Executive Summary

Horizon is a self-hostable Configuration Management Database (CMDB) system designed to provide comprehensive visibility
into an organization's IT infrastructure. The system combines a powerful backend with a lightweight, cross-platform
agent to automatically discover and inventory hardware assets, software installations, network configurations, and
security-relevant information. Horizon addresses the critical need for organizations to maintain accurate, real-time
records of their technology assets while providing the flexibility for manual data entry and modification.

The platform encompasses eight core functional areas: asset inventory management, network flow mapping, vendor
relationship tracking, vulnerability monitoring, security configuration assessment, configuration management, software
version tracking, and patch management. Each module has been designed to operate independently while contributing to a
unified, interconnected view of the IT environment. The system prioritizes data integrity through comprehensive audit
trails, supports both automated and manual data entry workflows, and provides extensible mechanisms for future
enhancements.

This implementation plan provides a detailed roadmap for building Horizon, including architectural decisions, technology
selections justified by specific requirements, database schema designs that support complex relationships and queries,
API specifications that enable both frontend consumption and third-party integrations, and agent designs that minimize
resource consumption while maximizing data collection capabilities. The plan is organized into actionable phases that
allow for incremental development and deployment, with each phase delivering tangible value while building toward the
complete vision.

---

## 2. Introduction and Vision

### 2.1 Purpose and Scope

The modern IT environment presents significant challenges for organizations attempting to maintain accurate inventories
of their technology assets. Traditional spreadsheet-based approaches quickly become unmanageable as infrastructure
grows, while enterprise-grade CMDB solutions often introduce prohibitive costs, excessive complexity, or vendor lock-in.
Horizon exists to fill the gap between these extremes, providing a capable, self-hostable solution that gives
organizations complete control over their data while eliminating ongoing licensing costs and dependency on external
service providers.

The scope of Horizon encompasses the complete lifecycle of IT asset management, from initial discovery through ongoing
monitoring, vulnerability tracking, and eventual decommissioning. The system is designed to support organizations
ranging from small businesses with dozens of assets to enterprises managing thousands of distributed systems. This
scalability requirement influences architectural decisions throughout the implementation, particularly regarding
database design, API efficiency, and agent resource utilization.

### 2.2 Problem Statement

Organizations face several interconnected challenges when attempting to maintain accurate IT asset inventories. First,
the dynamic nature of modern infrastructure means that assets are constantly being added, modified, or removed, making
static inventories obsolete within weeks of creation. Second, the proliferation of virtualization, containerization, and
cloud services has expanded the definition of what constitutes an "asset," requiring CMDBs to track not only physical
hardware but also virtual machines, containers, cloud instances, and network devices. Third, security and compliance
requirements increasingly demand detailed knowledge of software versions, configurations, and vulnerabilities across the
entire asset base, information that is difficult to maintain manually at scale.

Current solutions address these challenges incompletely or at excessive cost. Open-source alternatives often lack the
polish, documentation, or community support needed for production deployment in enterprise environments. Commercial
solutions, while feature-rich, typically involve significant per-asset licensing fees that scale prohibitively for large
infrastructures. Cloud-based solutions introduce data sovereignty concerns and ongoing operational costs that conflict
with the self-hosting preferences of security-conscious organizations. Horizon addresses these gaps by providing a
capable, self-hosted solution with no licensing costs and complete data ownership.

### 2.3 Strategic Goals

Horizon pursues four strategic goals that guide all implementation decisions. The first goal is comprehensiveness: the
system must capture all information relevant to IT asset management, from basic inventory data through security
configurations, vulnerabilities, and relationships between assets. The second goal is automation: the lightweight agent
must collect and report information with minimal configuration, enabling organizations to achieve comprehensive
visibility with reasonable operational overhead. The third goal is flexibility: the system must support both automated
and manual data entry, accommodate diverse asset types and configurations, and provide extension points for
organization-specific requirements. The fourth goal is integrity: all data must be auditable, changes must be traceable,
and the system must support data quality assessment and improvement workflows.

---

## 3. Architecture Overview

### 3.1 High-Level Architecture

Horizon employs a classic three-tier architecture consisting of a presentation layer, business logic layer, and data
persistence layer. This architectural pattern has been selected for its proven scalability, clear separation of
concerns, and widespread familiarity among software developers. The presentation layer encompasses the web-based
frontend application that provides the primary user interface for administrators and read-only access for other users.
The business logic layer consists of the API server that handles all requests, enforces business rules, coordinates with
the agent communication service, and manages background processing tasks. The data persistence layer includes the
primary PostgreSQL database for relational data, Redis for caching and session management, and optional object storage
for agent reports and supporting files.

The agent layer represents a critical component deployed on managed assets. Each agent operates independently,
periodically collecting system information and transmitting reports to the central server. Agent communication uses a
secure, authenticated protocol with message signing to prevent tampering and ensure data integrity. Agents are designed
for minimal resource consumption, typically requiring less than 50MB of memory and less than 1% CPU during normal
operation. The agent supports graceful degradation, continuing to collect and queue data when communication with the
server is temporarily unavailable.

### 3.2 Technology Stack Selection

The technology stack has been selected based on specific criteria aligned with Horizon's goals. Rust has been chosen for
the core server and agent implementations, providing memory safety guarantees, excellent performance characteristics,
and cross-platform compilation capabilities. The choice of Rust specifically addresses the security-focused nature of
the system, eliminating entire classes of memory-safety vulnerabilities that could compromise asset data. Additionally,
Rust's zero-cost abstractions enable high-performance data processing without sacrificing developer productivity.

For the database layer, PostgreSQL has been selected as the primary relational database. PostgreSQL's robust support for
complex queries, advanced data types, and extensibility makes it ideal for the complex relationships inherent in CMDB
data models. The decision against MySQL stems from PostgreSQL's superior support for JSON columns, full-text search
capabilities, and more sophisticated constraint mechanisms that will prove valuable for the vulnerability tracking and
configuration management features.

The web framework selected is Axum, a modular and ergonomic web framework for Rust that integrates seamlessly with Tokio
for asynchronous operations. Axum's design emphasizes type safety and composability, reducing the likelihood of runtime
errors while maintaining excellent performance. For the frontend, a modern JavaScript framework (React) will be selected
during the implementation phase.

### 3.3 Design Principles

The architecture adheres to several guiding principles that influence implementation decisions. The principle of least
privilege ensures that each component operates with the minimum permissions required for its function, limiting the
impact of potential security breaches. The principle of defense in depth implements multiple layers of security
controls, ensuring that the compromise of any single component does not expose the entire system. The principle of
observable behavior ensures that all significant operations produce logs, metrics, or audit records, enabling
troubleshooting, compliance reporting, and security analysis.

The architecture also embraces the concept of eventual consistency where appropriate. Agent reports may arrive out of
order or with slight delays, and the system must handle these scenarios gracefully without compromising data integrity.
Conflict resolution strategies are implemented for scenarios where concurrent modifications to the same asset data might
occur, typically favoring the most recent authoritative update while preserving history.

---

## 4. Core Components

### 4.1 API Server

The API server serves as the central hub of the Horizon system, handling all client requests, coordinating background
tasks, and serving as the authoritative source for asset information. The server is implemented as a stateless REST API,
enabling horizontal scaling through the addition of server instances behind a load balancer. Statelessness is achieved
through token-based authentication, with session state stored in Redis rather than in-memory on individual server
instances.

The API server is organized into several logical modules based on functionality.

- The authentication module handles user login, token issuance, and permission verification.
- The asset module manages CRUD operations for assets, including the complex relationships between assets, software
  installations, and configurations.
- The agent module handles agent registration, report submission, and configuration updates.
- The vulnerability module processes CVE data, associates vulnerabilities with assets and software, and manages
  remediation tracking.
- The configuration module handles environment definitions, configuration profiles, and version management.
- The reporting module generates inventory reports, compliance assessments, and custom queries based on stored data.

Request processing follows a consistent pipeline pattern. Each request passes through authentication verification,
permission authorization, input validation, business logic processing, and response formatting stages. Errors are
handled uniformly, with meaningful error messages returned to clients while detailed error information is logged
server-side for troubleshooting. Rate limiting protects the system from abuse, with different limits applied based on
endpoint sensitivity and client authentication level.

### 4.2 Database Layer

The database layer provides persistent storage for all Horizon data, with PostgreSQL serving as the primary data store.
The database schema will be designed to support the complex relationships between entities while maintaining query
performance as data volumes grow. Key design considerations include proper normalization to eliminate data redundancy,
appropriate indexing to support common query patterns, and strategic denormalization for performance-critical paths.

The database schema includes approximately forty tables organized into logical groups.

- The core group contains tables for:
  - assets,
  - asset types,
  - asset relationships,
  - and asset history.
- The software group encompasses:
  - software products,
  - versions,
  - installations,
  - and licenses.
- The network group includes:
  - network interfaces,
  - IP addresses,
  - subnets,
  - and network flows.
- The vulnerability group covers:
  - CVEs,
  - affected software,
  - vulnerability assessments,
  - and remediation records.
- The configuration group manages:
  - environments,
  - configuration profiles,
  - configuration items,
  - and version history.
- The vendor group stores:
  - vendor information,
  - contracts,
  - and asset associations.

Redis serves as a complementary data store for performance-critical operations. Session storage in Redis enables
stateless API server scaling while maintaining fast session access. Request caching reduces database load for frequently
accessed reference data such as asset type lists and software vendors. The rate limiter uses Redis sorted sets to
implement sliding window rate limiting across distributed server instances.

### 4.3 Agent Communication Service

The agent communication service manages all interactions with deployed agents, handling registration, authentication,
report submission, and configuration distribution. This service operates as a separate process from the main API server,
enabling independent scaling and deployment. The communication protocol has been designed for efficiency over unreliable
network connections, with support for compression, batching, and offline operation.

Agent registration follows a secure bootstrapping process. New agents receive a unique identifier and authentication
token during initial installation, typically through a provisioning system or manual configuration. Upon first
connection, agents authenticate using these credentials and receive a rotated authentication token for future use. The
server maintains agent registration records including last connection time, agent version, and operational status.

Report submission uses a pull-based model where the server periodically requests reports from registered agents. This
approach reduces network traffic compared to continuous polling while ensuring timely data collection. Agents can also
push critical alerts immediately, ensuring that significant events such as security configuration changes or critical
vulnerability detections reach administrators without delay.

### 4.4 Background Processing System

Background processing enables Horizon to perform operations that would be inappropriate for synchronous request
handling. The background system is implemented using a work queue architecture, with jobs processed by worker processes
operating independently of the API server. This separation ensures that long-running operations such as vulnerability
database synchronization, report generation, and bulk asset updates do not impact API responsiveness.

Several categories of background jobs are anticipated. Vulnerability synchronization jobs fetch CVE data from
authoritative sources, parse updates, and associate new vulnerabilities with affected software in the database. Report
generation jobs compile complex reports that aggregate data across many assets, potentially requiring significant
processing time. Cleanup jobs remove stale data, archive old records, and perform database maintenance tasks.
Notification jobs evaluate system state and generate alerts for conditions requiring administrative attention.

The background system implements retry logic with exponential backoff for failed jobs, ensuring eventual completion
despite transient failures. Job status is persisted in the database, enabling administrators to monitor job progress and
troubleshoot failures. Dead letter queues capture jobs that repeatedly fail, preventing blocking while preserving failed
work for investigation.

---

## 5. Database Schema Design

### 5.1 Core Entity Model

The core entity model establishes the foundational data structures for Horizon's CMDB capabilities. The central entity
is the asset, representing any discrete component of the IT infrastructure that requires tracking. Assets are classified
using a hierarchical taxonomy that supports arbitrary classification depth while maintaining query efficiency. Each
asset belongs to an asset type, which defines the characteristics applicable to assets of that category.

The asset table stores the following primary attributes:

- a CUID2 primary key that remains stable across asset modifications,
- a human-readable inventory number suitable for external references,
- the asset type identifier linking to the classification system,
- ownership information linking to organizational units or individuals,
- acquisition and decommissioning dates,
- current operational status,
- and a JSONB column for extensible attributes that vary by asset type.

The schema uses CUIDs rather than sequential identifiers to support distributed asset creation, prevent enumeration
attacks, and enable asset migration between database instances without collision concerns.

Asset relationships form a graph structure that captures connections between assets. The relationship table supports
arbitrary relationship types defined in a separate relationship types configuration. Common relationships include
network connectivity, dependency (where one asset requires another to function), containment (where one asset physically
or logically contains another), and ownership (where one asset is owned by an organizational unit associated with
another asset). The graph structure enables powerful queries such as dependency chain analysis, impact assessment for
planned changes, and network topology visualization.

The history table implements audit logging for all asset modifications. Every create, update, or delete operation on
asset data creates a history record capturing the timestamp, actor (user or agent), change type, previous values, and
new values. The history system preserves complete provenance for all data, supporting compliance requirements and
troubleshooting workflows. History records are write-once, preventing modification or deletion after creation.

### 5.2 Software Entity Model

The software entity model captures information about software products, their versions, and installations on managed
assets. The design distinguishes between abstract software products (such as "Apache HTTP Server") and specific versions
(such as "2.4.52"), enabling queries at both levels of granularity. This distinction proves essential for vulnerability
management, where vulnerabilities often affect specific versions while remediation typically requires product-level
coordination.

The software products table stores canonical information about software products regardless of version. Fields include:

- the product name,
- vendor association,
- product category (operating system, application, middleware, firmware, etc.),
- support status,
- end-of-life information where applicable,
- and a JSONB column for product-specific metadata.

Products may be linked to multiple vendors in cases of acquisition, rebranding, or distribution relationships.

The software versions table captures specific version information for each product. Each version record:

- links to a product,
- specifies the version string using a normalized parsing structure that supports semantic versioning and arbitrary
  versioning schemes,
- indicates the release date,
- provides download URLs and checksums where available,
- and includes a JSONB column for version-specific attributes.

The version parsing system extracts major, minor, patch, and build components from version strings, enabling range
queries and comparison operations.

Software installations represent the many-to-many relationship between assets and software versions, enriched with
installation-specific details. Each installation record links an asset to a software version, records the installation
path, installation date, installation source, current usage status, and installation-specific configuration locations.
The same software version may appear on multiple assets, and an asset may have multiple software installations of
different products.

### 5.3 Network Flow Model

The network flow model captures information about network traffic patterns between assets, enabling security analysis,
capacity planning, and change impact assessment. The design supports both agent-reported flows (observed network
connections) and configured flows (intended or permitted connections), enabling comparison between expected and observed
behavior.

The network flows table stores flow records with the following key attributes:

- source asset,
- destination asset,
- source port and protocol,
- destination port and protocol,
- service name where identifiable,
- flow direction (inbound, outbound, internal),
- observed timestamp,
- and flow metadata including byte counts and connection duration.

Flow records are immutable once created, with new records created for subsequent observations.

Flow grouping enables analysis at appropriate granularity. Flows between the same source-destination pair with
consistent characteristics are grouped into flow sessions, simplifying the view of network activity while preserving
detail when needed. Flow sessions support temporal analysis, revealing patterns such as peak usage times, unusual
connection timing, or changes in flow volume.

Network interface records provide additional context for flow analysis. Each network interface links to an asset and
records the interface name, MAC address, IP addresses (both IPv4 and IPv6), subnet association, interface type, link
speed, and operational status. Interface records enable correlation between flows and physical or virtual network
adapters, supporting scenarios such as identifying assets with unexpected network interfaces.

### 5.4 Vendor Management Model

The vendor management model supports comprehensive tracking of vendor relationships, contracts, and vendor-provided
software and hardware. The design recognizes that vendors play multiple roles in IT environments, serving as sources of
software products, manufacturers of hardware assets, providers of managed services, and parties to contractual
relationships.

The vendors table stores core vendor information:

- vendor name,
- unique identifier,
- primary contact information,
- support contact information,
- vendor type (software vendor, hardware manufacturer, service provider, etc.),
- financial identifiers such as tax IDs where relevant,
- and a JSONB column for flexible vendor attributes.

The system supports vendor hierarchy, enabling representation of vendor relationships such as parent companies,
subsidiaries, and acquisition targets.

Vendor contacts represent individual people associated with vendors. Each contact record links to a vendor and includes
name, role, email, phone, and responsibility areas. Multiple contacts per vendor support scenarios such as separate
support, sales, and technical contacts. Contact records enable direct communication tracking and relationship
management.

Vendor contracts link vendors to assets and services, tracking contractual terms relevant to asset management. Contract
records include contract type (support, maintenance, licensing, service level agreement), start and end dates, contract
value, renewal terms, and associated assets. The system supports linking multiple assets to a single contract,
simplifying bulk operations such as contract renewals or compliance assessments.

Vendor software and hardware associations link vendor records to software products and asset types, enabling
vendor-centric views of the IT environment. These associations support queries such as "show all assets manufactured by
Vendor X" or "list all software products from Vendor Y with known vulnerabilities."

### 5.5 Vulnerability Management Model

The vulnerability management model provides the foundation for tracking security vulnerabilities, assessing asset
exposure, and managing remediation efforts. The design integrates with external vulnerability data sources while
maintaining internal tracking and workflow capabilities.

The cve_records table stores vulnerability information from authoritative sources, primarily the National Vulnerability
Database (NVD) and related feeds. Each record includes:

- the CVE identifier,
- publication date,
- description,
- severity metrics (CVSS scores and vectors),
- affected products and versions,
- remediation guidance,
- and references.

The system maintains the complete history of CVE records, updating existing records when authoritative sources are
revised while preserving historical states.

The vulnerability_ASSETS table tracks the intersection of vulnerabilities and affected assets. For each known
vulnerability and each asset with affected software, the system creates an association record indicating:

- the detection method (agent scan, imported report, manual entry),
- detection date,
- current status (vulnerable, mitigated, remediated, accepted risk),
- remediation priority,
- and assigned owner.

This table enables asset-centric vulnerability views and reporting.

Vulnerability assessments enable systematic evaluation of vulnerability relevance and impact. Each assessment links a
vulnerability to an asset and includes an analyst's evaluation of applicability, impact assessment, remediation
planning, and risk acceptance documentation. The assessment workflow supports organizational security processes while
maintaining clear audit trails.

### 5.6 Configuration Management Model

The configuration management model supports tracking of configuration items, environments, and configuration versions.
The design enables organizations to define configuration baselines, track deviations, and manage configuration change
processes.

The environments table defines distinct deployment environments such as production, staging, development, and test.
Environment records include:

- name,
- description,
- environment type,
- criticality level,
- and associated access policies.

The environment model supports arbitrary environment hierarchies, enabling representation of complex organizational
structures such as multi-region deployments or partitioned environments.

Configuration profiles define collections of configuration items that together constitute a complete configuration for a
given context. Each profile links to an environment and includes:

- profile version,
- creation date,
- author,
- and approval status.

Profiles are immutable once approved, with new versions created for subsequent changes. This immutability ensures
configuration reproducibility and supports audit requirements.

Configuration items represent individual configurable elements within the system. Item records include:

- key (identifying the configuration element),
- value (the configured setting),
- item type (string, integer, boolean, JSON, etc.),
- and validation rules.

Configuration items link to profiles and may optionally link to assets, enabling both environment-level and asset-level
configurations.

The configuration history table tracks all configuration changes, maintaining provenance similar to asset history. Each
configuration modification creates a history record capturing the change details, enabling rollback, comparison, and
audit workflows.

---

## 6. API Design Specification

### 6.1 RESTful API Architecture

The Horizon API follows REST architectural principles, providing a predictable, self-documenting interface for all
system operations. Resources are organized hierarchically with logical groupings, and standard HTTP methods convey
operations. The API version is included in the URL path, enabling controlled evolution while maintaining backward
compatibility for existing clients.

All API endpoints require authentication except for the login endpoint and health check endpoint. Authentication uses
bearer tokens issued during the login process, with tokens expiring after a configurable duration. Refresh tokens enable
session extension without re-authentication. Token validation is performed at the API gateway level before requests
reach the application layer, ensuring consistent security enforcement.

Request and response payloads use JSON format exclusively. The API employs consistent envelope structure for responses,
wrapping all successful responses in a standardized object containing status, data, and metadata fields. Error responses
include error codes, messages, and detailed validation information where applicable. Date and time values use ISO 8601
format with UTC timezone, ensuring unambiguous interpretation across distributed systems.

### 6.2 Authentication and Authorization

The authentication system implements role-based access control (RBAC) with support for custom roles and fine-grained
permissions. The system distinguishes between authentication (verifying identity) and authorization (verifying
permissions), with separate middleware components handling each concern. This separation enables flexible deployment
scenarios such as integration with external identity providers.

User roles define collections of permissions that determine allowed operations. The system includes predefined roles for
common scenarios: administrators with full system access, operators with asset management capabilities, viewers with
read-only access, and auditors with access to history and audit data. Custom roles enable organizations to define role
structures aligned with their operational models.

Permission checks occur at multiple levels. Endpoint-level permissions restrict access to entire API paths based on role
membership. Object-level permissions control access to specific resources based on ownership, organizational assignment,
or other attributes. Field-level permissions enable partial data hiding, allowing users to view asset metadata without
exposing sensitive fields. The permission system is extensible, supporting custom permission types for
organization-specific requirements.

### 6.3 Asset Endpoints

The asset endpoints provide comprehensive access to asset data and related operations. The primary asset list endpoint
(`GET /api/v1/assets`) supports filtering, pagination, and sorting with all parameters passed as query strings. Filter
criteria may include asset type, ownership, status, location, and custom attributes. The response includes pagination
metadata and optional embedded relationships such as recent software installations or current vulnerabilities.

Asset detail endpoints provide access to specific asset records and their related data. The endpoint
`GET /api/v1/assets/{id}` returns complete asset information including relationships, while related endpoints provide
views of specific aspects: `/api/v1/assets/{id}/software` for installed software, `/api/v1/assets/{id}/configurations`
for configuration items, `/api/v1/assets/{id}/vulnerabilities` for vulnerability associations,
`/api/v1/assets/{id}/network` for network interfaces and flows, and `/api/v1/assets/{id}/history` for change history.

Asset modification endpoints use standard HTTP methods with validation appropriate to each operation. Create operations
(`POST /api/v1/assets`) validate required fields and return the created resource with assigned identifiers. Update
operations (`PATCH /api/v1/assets/{id}`) support partial updates, applying only provided changes while preserving
existing values. Delete operations (`DELETE /api/v1/assets/{id}`) support both soft deletion (preserving history) and
hard deletion based on system configuration.

### 6.4 Software Management Endpoints

Software management endpoints enable tracking of software products, versions, and installations. The product endpoints
(`/api/v1/software/products`) support CRUD operations on software product definitions. Product create operations require
vendor association, product name, and category, while optional fields support additional metadata. Product list
endpoints support filtering by vendor, category, and support status.

Version endpoints (`/api/v1/software/products/{product_id}/versions`) manage version lifecycle for specific products.
Version create operations parse and validate version strings, extract version components, and detect duplicate versions.
Version update operations support changes to metadata while preserving version identity. Version comparison endpoints
enable programmatic comparison of version strings, supporting vulnerability matching and upgrade planning workflows.

Installation endpoints (`/api/v1/software/installations`) track software installations on assets. Installation create
operations link an asset to a software version with installation-specific details. Installation list endpoints support
filtering by asset, software product, version, and installation status. Installation update operations enable tracking
of configuration changes and status updates.

### 6.5 Network Flow Endpoints

Network flow endpoints provide access to observed and configured network traffic data. Flow list endpoints
(`GET /api/v1/network/flows`) support filtering by source asset, destination asset, port, protocol, and time range.
Responses include aggregated flow summaries by default, with optional detailed listing for investigative queries.

Flow report endpoints accept network flow data from agents and external sources. The endpoint
`POST /api/v1/network/flows/batch` accepts arrays of flow records for bulk ingestion. The ingestion process validates
records, detects duplicates, and stores flows with appropriate metadata. Bulk operations support efficiency for
high-volume environments.

Flow analysis endpoints provide derived insights from flow data. The endpoint `GET /api/v1/network/flows/summary`
returns aggregated statistics including flow counts by asset, port, and protocol. Flow comparison endpoints
(`GET /api/v1/network/flows/compare`) identify discrepancies between configured and observed flows, highlighting
unexpected network activity.

### 6.6 Vulnerability Endpoints

Vulnerability endpoints manage CVE data, vulnerability assessments, and remediation tracking. CVE sync endpoints
(`POST /api/v1/vulnerabilities/sync`) trigger synchronization with external vulnerability databases. The sync process
supports incremental updates, fetching only records modified since the last synchronization. Sync status endpoints
return synchronization progress and recent sync results.

Asset vulnerability endpoints (`GET /api/v1/assets/{id}/vulnerabilities`) list vulnerabilities affecting specific
assets, with filtering by severity, status, and remediation priority. Bulk vulnerability update endpoints
(`PATCH /api/v1/vulnerabilities/batch`) support mass status updates for remediation workflows.

Vulnerability assessment endpoints (`/api/v1/vulnerabilities/{cve_id}/assessments`) manage the evaluation process for
specific vulnerabilities. Assessment create operations record analyst evaluations, risk acceptances, and remediation
plans. Assessment history endpoints preserve the complete evaluation lifecycle for audit purposes.

### 6.7 Configuration Management Endpoints

Configuration management endpoints support environments, profiles, and configuration items. Environment endpoints
(`GET/POST/PUT/DELETE /api/v1/config/environments`) manage environment definitions with validation for name uniqueness
and required fields.

Profile endpoints (`/api/v1/config/profiles`) manage configuration profile lifecycle. Profile create operations require
environment association and initial version. Profile approval endpoints transition profiles from draft to approved
status, with optional approval workflows requiring multiple approvers. Profile version endpoints enable navigation
through profile history and comparison between versions.

Configuration item endpoints (`/api/v1/config/items`) manage individual configuration values. Items link to profiles and
optionally to assets. Bulk item operations support efficient configuration deployment. Configuration validation
endpoints test proposed configurations against defined rules before application.

---

## 7. Agent Architecture and Design

### 7.1 Agent Overview and Design Goals

The Horizon agent is a lightweight software component deployed on managed assets to collect and report system
information. The agent design prioritizes minimal resource consumption, reliable operation across diverse environments,
and secure communication with the central server. These priorities reflect the agent's role as a pervasive,
always-running component that must coexist with primary system workloads.

The agent operates as a system service or daemon, automatically starting at system boot and running with appropriate
privileges for system information access. Installation packages are provided for major operating systems: Debian/Ubuntu
packages (.deb), Red Hat/CentOS packages (.rpm), Windows installers (.msi), and macOS packages (.pkg). Additionally, a
static binary distribution supports container environments and embedded systems where package installation is
impractical.

Agent resource consumption targets are deliberately conservative. Memory usage typically remains below 50MB even during
intensive collection phases, with idle consumption under 10MB. CPU consumption averages below 1% of a single core during
normal operation, with brief spikes during collection cycles. Network usage averages approximately 100KB per report
submission, with compression reducing transfer size for typical reports. These targets ensure the agent is suitable for
deployment on production systems without performance impact.

### 7.2 Agent Components

The agent consists of four primary components operating in concert. The collector component gathers system information
from various sources appropriate to the host operating system. On Linux systems, collectors read from `/proc`, `/sys`,
and system sockets; on Windows, collectors use WMI and registry queries; on macOS, collectors use system frameworks and
command-line tools. Each collector runs independently, enabling parallel execution and failure isolation.

The cache component maintains local storage for collected data between report submissions. The cache uses a SQLite
database providing reliable storage, efficient queries, and transactional semantics. The cache maintains collected data
for the reporting period, enabling resubmission if transmission fails, and historical data for comparison-based change
detection.

The scheduler component manages collection and reporting cycles. The scheduler implements a flexible configuration
defining collection intervals for different data types, with shorter intervals for critical information and longer
intervals for stable data. The scheduler also handles reporting cycles, coordinating with the communication component to
submit reports according to server-configured schedules.

The communication component manages all interaction with the Horizon server. This component handles authentication,
report submission, configuration synchronization, and alert pushing. The communication component implements exponential
backoff for retry handling, ensuring resilience while avoiding server overload during outages.

### 7.3 Collection Modules

Hardware collection modules gather information about system hardware components. The CPU module extracts processor
model, frequency, core count, and capabilities. The memory module reports installed memory by type, speed, and capacity.
The storage module identifies physical disks and their characteristics including model, serial number, size, and SMART
status where available. The network module enumerates network interfaces with MAC addresses, current IP addresses, and
interface statistics.

Operating system collection modules capture system identification and configuration information. The system module
reports operating system name, version, kernel details, and system uptime. The user module enumerates local users and
groups with membership information. The timezone module reports configured timezone and NTP status. The security module
captures information such as secure boot status, selinux/AppArmor status, and enabled firewalls.

Software collection modules identify installed software across different installation mechanisms. The package module
queries system package managers: dpkg/apt for Debian derivatives, rpm/yum/dnf for Red Hat derivatives, Chocolatey for
Windows, and Homebrew for macOS. The process module identifies running software by examining process listings and
correlating with installation records. The listening module identifies services by examining network socket states.

Configuration collection modules capture security-relevant configuration settings. The disk encryption module reports
encryption status for attached storage volumes. The authentication module reports password policies, failed login
tracking, and account lockout configuration. The update module reports system update status and pending updates. The
audit module captures recent security-relevant events from system audit logs.

### 7.4 Communication Protocol

The agent-server communication protocol has been designed for security, efficiency, and reliability. All communication
uses HTTPS with TLS 1.3 for transport encryption. Certificate validation ensures agents connect to legitimate Horizon
servers, preventing man-in-the-middle attacks. The protocol supports certificate pinning for environments requiring
additional assurance.

Message format uses Protocol Buffers for efficient binary serialization, reducing bandwidth compared to JSON while
providing built-in schema evolution support. Messages include authentication tokens, sequence numbers, and message
digests enabling the server to verify message integrity and detect replay attacks. Compression reduces transfer size for
typical reports by 70-90%.

The registration flow establishes initial trust between agent and server. During installation, agents receive a unique
agent ID and initial authentication token from a provisioning system. On first connection, agents authenticate using
these credentials and receive a rotated authentication token for future use. The server records agent metadata including
reported hostname, operating system, and agent version, enabling inventory enrichment during registration.

Report submission follows a pull-based model where the server requests reports from agents. The server sends a request
containing a nonce and desired data types; agents respond with collected data signed using their authentication token.
This approach prevents blind submission attacks and enables server-driven rate limiting. Critical alerts may be pushed
by agents using a separate endpoint, bypassing the pull cycle for timely notification.

### 7.5 Agent Configuration

Agent behavior is controlled through a hierarchical configuration system. Built-in defaults provide reasonable behavior
for most environments, while configuration files enable customization for specific requirements. Server-provided
configuration overrides local settings, enabling centralized management of agent behavior without individual host
access.

Collection intervals represent the primary configuration aspect. Different data types support independent intervals:
hardware information collected hourly, software inventory daily, network flows continuously buffered with periodic
submission. Intervals balance data freshness against resource consumption, with defaults reflecting typical operational
requirements. Shorter intervals increase data resolution for dynamic environments while longer intervals reduce resource
usage for stable systems.

Feature flags enable selective enablement of collection modules. Organizations may disable collection of sensitive
information such as process listings or user enumerations based on privacy requirements. Feature flags also enable
experimental features for testing before general availability. Server-side feature flag management enables coordinated
configuration changes across the agent fleet.

---

## 8. Feature Specifications

### 8.1 Asset Inventory Management

The asset inventory management feature provides comprehensive tracking of all IT assets within the organization. Assets
encompass physical hardware (servers, workstations, network devices, peripherals), virtual resources (virtual machines,
containers), cloud resources (instances, managed services), and logical constructs (software products, certificates,
configurations). The inventory system maintains complete asset lifecycle tracking from procurement through deployment,
operation, and eventual decommissioning.

Asset classification uses a hierarchical taxonomy supporting arbitrary depth. The root level defines major categories
such as Server, Workstation, Network Device, Storage Device, and Cloud Resource. Each category contains subcategories;
for example, Server might contain Rack Server, Blade Server, and Tower Server. Organizations extend the taxonomy with
additional categories appropriate to their environment. Classification determines available attributes, default
relationships, and applicable security policies.

Ownership tracking associates assets with organizational responsibility. Each asset links to an owner, which may be an
individual user, a team, a department, or a cost center. Additional relationships specify asset custodian (typically the
technical administrator), financial owner (budget responsible), and risk owner (accountable for security posture).
Multiple ownership relationships enable accurate responsibility assignment for different aspects of asset management.

Asset attributes vary by type while maintaining common core fields. Core fields include inventory number, serial number,
manufacturer, model, acquisition date, cost, warranty status, and location. Type-specific fields capture relevant
details: for servers, rack position and power consumption; for workstations, primary user and form factor; for network
devices, throughput capacity and management interface. Custom attributes enable organization-specific tracking without
schema modification.

The inventory interface provides multiple views into asset data. The list view supports filtering, sorting, and bulk
operations for managing large asset populations. The detail view presents complete asset information including
relationships, history, and derived insights. The comparison view enables side-by-side comparison of selected assets.
The timeline view visualizes asset lifecycle events and changes over time.

### 8.2 Network Flow Mapping

Network flow mapping provides visibility into network traffic patterns within the managed environment. Flow data enables
security analysis (identifying unexpected connections), capacity planning (understanding traffic demands), and change
impact assessment (predicting downstream effects). The feature combines agent-reported observations with configured
network topologies to build comprehensive network visibility.

Flow detection occurs through multiple mechanisms. The agent monitors network socket activity, identifying established
connections and their endpoints. For environments where agent deployment is impractical, flow data may be imported from
network monitoring systems such as NetFlow collectors, packet analyzers, or firewall logs. Multiple sources contribute
to a unified flow model, with source attribution enabling assessment of observation confidence.

Flow analysis transforms raw observations into actionable insights. Flow aggregation combines related connections into
sessions representing sustained communication between endpoints. Flow classification identifies known protocols by port
and payload analysis, enabling recognition of standard services and detection of unusual protocol usage. Flow baselining
establishes normal patterns, enabling detection of anomalies indicating compromise or misconfiguration.

Network topology integration connects flows to asset relationships. Assets are linked through network interfaces, which
connect to subnets, which connect through routers and switches. This relationship model enables visualization of network
paths, identification of critical network segments, and assessment of redundancy. Topology views support both logical
connectivity (IP addresses and routes) and physical topology (cables, switches, and ports).

Discrepancy detection highlights differences between observed and expected network behavior. Configured relationships
define permitted connections between assets and services; observed flows are compared against these expectations,
generating alerts for unexpected traffic. Conversely, expected flows that are not observed may indicate connectivity
issues or configuration drift. This bidirectional comparison provides comprehensive network health visibility.

### 8.3 Vendor Management

Vendor management provides comprehensive tracking of vendor relationships, enabling vendor-centric asset views and
contract management. The feature recognizes vendors as central entities in IT environments, serving as sources of
software, manufacturers of hardware, and parties to support contracts.

Vendor profiles aggregate information about each vendor. Basic information includes vendor name, website, and contact
details. Financial information tracks tax identifiers and payment terms where relevant. Classification identifies vendor
type (software publisher, hardware manufacturer, cloud provider, service integrator, etc.). Classification enables
vendor filtering and analysis appropriate to vendor role.

Vendor contacts represent individuals within vendor organizations. Each contact links to a vendor and includes role,
contact information, and responsibility areas. Multiple contacts per vendor support scenarios such as separate sales,
technical support, and executive relationships. Contact tracking enables direct communication and relationship
management within the vendor management workflow.

Contract management tracks formal agreements between the organization and vendors. Contract records capture contract
type (support agreement, license agreement, service level agreement), term dates, value, and renewal terms. Contracts
link to affected assets, enabling vendor-centric views of contract coverage. Contract expiration tracking generates
alerts before contract renewal dates, ensuring continuous coverage.

Vendor software and hardware catalogs link vendor records to products and asset types. These links enable queries such
as "show all assets running software from Vendor X" or "identify all hardware manufactured by Vendor Y." The catalog
supports acquisition tracking, identifying assets that may be affected by vendor product discontinuations, support
lifecycle changes, or security incidents affecting vendor products.

### 8.4 Vulnerability Monitoring

Vulnerability monitoring integrates external vulnerability intelligence with internal asset inventory to track, assess,
and remediate security vulnerabilities. The feature provides comprehensive vulnerability visibility while supporting
organizational remediation workflows and compliance reporting.

CVE integration pulls vulnerability data from authoritative sources, primarily the National Vulnerability Database
(NVD). The integration supports both full synchronization (periodic complete database refresh) and incremental
synchronization (fetching only recent changes). The system maintains complete CVE history, enabling historical
vulnerability analysis and supporting compliance requirements for evidence preservation.

Vulnerability correlation matches CVEs against the asset inventory. For each CVE, the system identifies affected
software products and versions, then queries the installation database to identify affected assets. This correlation
enables asset-centric vulnerability views showing all vulnerabilities affecting a specific asset, and
vulnerability-centric views showing the affected asset population for each CVE.

Risk assessment enables prioritization of remediation efforts. Base CVSS scores provide initial severity assessment,
while asset context enables refined risk calculation. Factors influencing asset-specific risk include asset criticality
(based on data sensitivity and business function), exposure (network accessibility and attack surface), and compensating
controls (segmentation, detection capabilities). Organizations configure risk adjustment factors based on their security
posture and risk tolerance.

Remediation tracking supports vulnerability resolution workflows. Each vulnerability-asset association maintains status
(vulnerable, mitigated, remediated, accepted risk), assigned owner, target remediation date, and resolution notes.
Remediation tasks integrate with change management processes, ensuring appropriate approval and documentation for
vulnerability fixes. Remediation reports support compliance assessments and security metrics.

### 8.5 Security Configuration Assessment

Security configuration assessment evaluates asset security posture against defined benchmarks and organizational
policies. The feature provides continuous visibility into security configuration status, identifying gaps and tracking
remediation.

Configuration benchmarks define expected security settings for different asset types. Benchmarks reference established
standards such as CIS Benchmarks, DISA STIGs, and organizational policies. Each benchmark item specifies the expected
configuration, severity (how important the setting is to overall security), and remediation guidance. The system
supports multiple benchmark versions and enables organizational customization of benchmark content.

Configuration collection occurs through agent-based assessment. The agent evaluates configuration settings against
applicable benchmarks, generating assessment results for each benchmark item. Assessment results indicate whether the
configuration meets expectations, and if not, the specific gap and deviation. Results are cached locally and submitted
with regular reports.

Compliance reporting aggregates assessment results into compliance dashboards. Reports show overall compliance
percentage, compliance trend over time, and detailed breakdowns by benchmark, asset type, and severity. Gap reports
identify specific configuration issues requiring remediation. Compliance evidence exports support audit requirements,
providing documented proof of security configuration status.

Remediation guidance helps address configuration gaps. For each failed benchmark item, the system provides detailed
remediation steps, potential impact assessment, and verification procedures. Integration with configuration management
enables remediation through automated configuration deployment where appropriate.

### 8.6 Configuration Management

Configuration management tracks configuration items across environments, supporting configuration governance and change
control. The feature enables organizations to define configuration baselines, track configuration changes, and ensure
consistency across the environment.

Environment definitions establish the context for configuration management. Environments represent distinct deployment
contexts such as Production, Staging, Development, and Test. Environment records capture environment characteristics
including criticality, access restrictions, and change control requirements. Environment hierarchies support complex
organizational structures with regional deployments, application tiers, and environment promotion workflows.

Configuration profiles define complete configurations for specific contexts. Each profile specifies configuration items
and their expected values for a given environment. Profiles are versioned, with version history preserving the complete
configuration lifecycle. Profile approval workflows ensure configuration changes receive appropriate review before
deployment. Comparison between profile versions shows configuration drift over time.

Configuration deployment enables controlled configuration changes. Deployment workflows specify target assets,
deployment schedule, and rollback procedures. Deployments are staged, with initial deployment to a subset of assets
enabling validation before full rollout. Deployment status tracking shows progress and identifies failures requiring
attention.

Configuration drift detection identifies assets with configurations diverging from baselines. Periodic assessment
compares asset configurations against applicable profiles, generating drift reports for assets with unexpected
configurations. Drift alerts notify administrators of unexpected changes, enabling investigation of both unauthorized
changes and legitimate drift requiring profile updates.

### 8.7 Software Version Management

Software version management provides detailed tracking of software products and their versions across the asset
population. The feature enables organizations to understand their software landscape, plan upgrades, and maintain
software currency.

Product management establishes canonical software definitions. Each product record represents a distinct software
product regardless of version. Products are categorized (operating system, database, application, middleware, utility)
and linked to vendors. Product records capture lifecycle information including release dates, support status, and
end-of-life schedules.

Version management tracks specific product versions. Version records capture version identifiers, release dates, and
metadata such as download URLs and checksums. Version parsing normalizes version strings, enabling programmatic
comparison and range queries. Version relationships track upgrade paths, supporting upgrade planning and identification
of version skips.

Installation tracking correlates software versions with assets. Installation records capture which software versions are
installed on which assets, along with installation date, path, and source. Multiple installations of the same product
version across different assets enable software distribution analysis. Installation deduplication identifies duplicate
installations that may indicate license compliance issues.

Software lifecycle management supports product and version retirement workflows. Products approaching end-of-life
generate notifications, enabling proactive remediation before support expires. Version upgrade tracking identifies
assets running unsupported versions. Software portfolio reports support license optimization and cost management
initiatives.

### 8.8 Patch Management

Patch management extends software version management to encompass patch assessment, approval, and deployment. The
feature enables systematic patch governance, balancing security imperatives against operational stability concerns.

Patch intelligence integrates with vulnerability monitoring to identify patches for known vulnerabilities. When CVEs are
synchronized, the system identifies available patches for affected software. Patch records link to source CVEs, affected
versions, and fixed versions, enabling targeted patch deployment for vulnerability remediation.

Patch assessment evaluates patches before deployment. Assessment includes vendor patch reliability ratings,
compatibility testing with the asset population, and organizational testing workflows. Patches receive approval status
based on assessment results: approved for automatic deployment, approved for manual deployment, or quarantined pending
further evaluation.

Patch deployment orchestrates patch installation across the asset population. Deployment policies specify which patches
apply to which assets based on product, version, environment, and criticality. Deployment scheduling considers
maintenance windows, asset criticality, and deployment capacity. Staged rollout begins with non-production assets,
proceeding to production after validation.

Patch compliance reporting tracks patch status across the environment. Reports show patch currency by asset, product,
and severity. Gap analysis identifies assets missing approved patches. Compliance dashboards support security metrics
and provide evidence for compliance assessments. Remediation tracking integrates with change management for patches
requiring approval workflows.

---

## 9. Security Framework

### 9.1 Authentication and Identity

The security framework implements robust authentication mechanisms protecting system access. User authentication
supports multiple methods including username/password with secure password storage, single sign-on integration via SAML
2.0 and OpenID Connect, and API keys for programmatic access. Password policies enforce complexity requirements,
rotation schedules, and breach detection through integration with compromised credential databases.

Session management issues short-lived tokens with configurable expiration. Session activity tracking enables detection
of concurrent sessions and session hijacking attempts. Session termination options include user-initiated logout,
administrative revocation, and automatic expiration. Secure session storage using encrypted cookies prevents session
theft through client-side attacks.

Multi-factor authentication provides additional assurance for privileged operations. MFA support includes time-based
one-time passwords (TOTP), hardware security keys (WebAuthn/FIDO2), and push notifications to mobile devices. MFA
enforcement policies require MFA for administrative accounts, API access, and access from unusual locations.

### 9.2 Authorization and Access Control

Role-based access control enables granular permission management. Predefined roles provide starting points for common
scenarios: Administrators with full system access, Asset Managers with asset modification permissions, Security Analysts
with vulnerability and configuration access, and Auditors with read access to all data and history. Custom roles enable
organizations to define role structures aligned with operational models.

Permission granularity controls access at multiple levels. Endpoint permissions restrict API access by path and method.
Object permissions control access to specific resources based on ownership, assignment, or organizational membership.
Field permissions enable partial data visibility, hiding sensitive fields from users with general access. Permission
inheritance flows through organizational hierarchies, simplifying management at scale.

Approval workflows extend authorization for sensitive operations. Configurable workflows require multi-level approval
for operations such as asset deletion, configuration deployment, and vulnerability risk acceptance. Workflow definitions
specify required approvers, escalation procedures, and time limits. Audit trails preserve complete approval records for
compliance purposes.

### 9.3 Data Protection

Data protection mechanisms preserve confidentiality and integrity of stored information. Database encryption protects
data at rest using transparent data encryption (TDE) or application-level encryption for sensitive fields. Encryption
keys are managed through dedicated key management systems, supporting key rotation and HSM integration for high-security
environments.

Data classification enables appropriate handling based on sensitivity. Classification labels (Public, Internal,
Confidential, Restricted) attach to data types and individual records. Classification determines encryption
requirements, access controls, and retention policies. Automated classification using pattern matching and machine
learning assists with initial labeling and ongoing monitoring.

Audit logging captures all significant operations for forensic and compliance purposes. Audit records include timestamp,
actor, operation, target, and outcome. Audit data is write-once, preventing modification or deletion. Long-term
retention policies support compliance requirements while balancing storage costs. Integration with external SIEM systems
enables correlation with other security data sources.

### 9.4 Agent Security

Agent security ensures the integrity and confidentiality of agent-server communication. Agent authentication uses mutual
TLS with certificate validation in both directions. Agents verify server certificates against configured certificate
authorities, preventing connection to impersonating servers. Server validates agent certificates during registration and
renewal.

Agent communication uses message signing to prevent tampering. Each message includes a signature generated using the
agent's private key, enabling the server to verify message integrity and authenticity. Message replay prevention using
nonces and timestamps blocks replay attacks. Communication encryption using TLS 1.3 provides confidentiality for
transmitted data.

Agent integrity protection prevents unauthorized agent modification. Agent packages are signed by the Horizon
development team, enabling verification during installation and updates. Runtime integrity monitoring detects
unauthorized agent process modification. Self-update mechanisms ensure agents remain current with security patches.

---

## 10. Implementation Phases

### 10.1 Phase 1: Foundation (Weeks 1-8)

Phase 1 establishes the core infrastructure enabling subsequent feature implementation. The phase delivers a functional
API server with basic CRUD operations, a relational database schema for core entities, and a web-based administrative
interface for fundamental asset management.

The API server foundation implements authentication, authorization, and core asset operations. User authentication with
username/password credentials and JWT token issuance provides secure access. Role-based access control with predefined
roles enables permission management. Asset CRUD operations with validation and error handling establish the primary data
workflow. The API follows the RESTful design specification with consistent error handling and response formats.

The database foundation implements the core entity model including assets, asset types, and asset relationships.
Migration tooling enables schema evolution during development and deployment. Indexes support common query patterns
identified through use case analysis. Database-level constraints ensure data integrity at the storage layer.

The web interface foundation provides basic asset management capabilities. Asset list view with filtering and pagination
supports asset discovery. Asset detail view presents asset information and related data. Asset creation and editing
forms with validation enable asset management. Responsive design ensures usability across device sizes.

### 10.2 Phase 2: Agent and Discovery (Weeks 9-16)

Phase 2 delivers the lightweight agent and automated asset discovery capabilities. The phase enables organizations to
deploy agents across their infrastructure, achieving comprehensive asset visibility with minimal manual effort.

The agent foundation implements core collection capabilities for major platforms. Hardware collection captures CPU,
memory, storage, and network information. Operating system collection reports system identification and configuration.
Basic software collection identifies installed packages. Agent communication with the server enables report submission
and configuration reception.

The discovery enhancement extends agent capabilities with comprehensive data collection. Process and service enumeration
captures running software beyond package installations. User and group enumeration supports security analysis.
Configuration assessment against basic security benchmarks enables initial compliance visibility. Enhanced software
collection with version parsing supports vulnerability correlation.

The server-side processing enables automated asset enrichment. Agent reports automatically create or update asset
records. Change detection identifies modifications since previous reports. Asset relationship inference from network
observation builds connectivity awareness. Duplicate detection prevents asset proliferation from parallel agent
deployments.

### 10.3 Phase 3: Software and Configuration (Weeks 17-24)

Phase 3 delivers software management and configuration management capabilities. The phase enables organizations to track
software versions across the asset population and manage configuration baselines.

Software management implements the complete software entity model. Product management enables definition of software
products with vendor associations. Version management tracks specific versions with normalized parsing. Installation
tracking correlates software with assets. Software lifecycle tracking supports product and version end-of-life
management.

Configuration management implements environment and profile management. Environment definitions establish deployment
contexts. Configuration profiles define complete configurations with version history. Configuration deployment enables
controlled configuration changes. Drift detection identifies assets diverging from baselines.

Integration connects configuration management with asset inventory. Configuration profiles apply to asset types,
automatically associating configurations with new assets. Configuration status appears in asset detail views.
Configuration history integrates with asset history for complete provenance.

### 10.4 Phase 4: Vulnerability and Patch Management (Weeks 25-32)

Phase 4 delivers vulnerability monitoring and patch management capabilities. The phase enables organizations to track,
assess, and remediate security vulnerabilities across the asset population.

Vulnerability monitoring integrates CVE data with asset inventory. CVE synchronization pulls data from authoritative
sources. Vulnerability correlation identifies affected assets through software mapping. Risk assessment incorporates
asset context into severity calculations. Remediation tracking supports vulnerability resolution workflows.

Patch management extends vulnerability capabilities with deployment capabilities. Patch intelligence identifies
available patches for known vulnerabilities. Patch assessment enables evaluation before deployment. Patch deployment
orchestrates installation across asset populations. Patch compliance reporting tracks remediation status.

Security configuration assessment enhances vulnerability visibility. Benchmark management supports multiple security
standards. Configuration assessment evaluates asset configurations against benchmarks. Compliance reporting aggregates
assessment results. Remediation guidance assists gap resolution.

### 10.5 Phase 5: Network Flows and Advanced Features (Weeks 33-40)

Phase 5 delivers network flow mapping and advanced features completing the Horizon vision. The phase enables
organizations to understand network traffic patterns and implements advanced capabilities requested by early adopters.

Network flow mapping implements comprehensive traffic visibility. Flow collection from agents provides endpoint-level
visibility. Flow analysis aggregates observations into meaningful patterns. Topology integration connects flows with
asset relationships. Discrepancy detection identifies unexpected network activity.

Vendor management implements comprehensive vendor tracking. Vendor profiles aggregate vendor information. Vendor
contacts enable relationship management. Contract management tracks agreements and renewals. Vendor-centric views
support vendor analysis and planning.

Advanced features enhance platform capabilities. Reporting generates comprehensive inventory and compliance reports.
Integration APIs enable third-party system connectivity. Custom attributes support organization-specific data
requirements. Workflow automation enables custom operational processes.

---

## 11. Technical Decisions and Justifications

### 11.1 Language and Framework Selection

**Decision:** Implement core components in Rust using the Axum framework.

**Justification:** Rust provides memory safety guarantees eliminating entire classes of vulnerabilities that could
compromise asset data. The language's zero-cost abstractions enable high performance without sacrificing developer
productivity. Cross-platform compilation supports deployment targets including Linux, Windows, and macOS from a single
codebase. The Axum framework provides ergonomic API design with strong type safety, integrating seamlessly with Tokio
for asynchronous operations. This stack balances security, performance, and development velocity.

### 11.2 Database Selection

**Decision:** Use PostgreSQL as the primary relational database with Redis for caching and session management.

**Justification:** PostgreSQL's robust feature set supports the complex data model required for comprehensive CMDB
functionality. Superior support for JSON columns enables flexible attribute storage without sacrificing relational
integrity. Advanced indexing capabilities including GIN indexes for JSONB queries support the varied query patterns
required for asset search and filtering. The extensive ecosystem of extensions enables future capability expansion such
as full-text search and geographic data handling.

**Alternative Considered:** MySQL was evaluated but eliminated due to weaker JSON support and less sophisticated
constraint mechanisms. NoSQL databases such as MongoDB were considered for document storage aspects but rejected due to
the importance of relational integrity for the core data model and the need for complex multi-table queries.

### 11.3 API Architecture

**Decision:** Implement a stateless REST API with JSON payloads and JWT authentication.

**Justification:** REST provides a familiar, well-understood API paradigm supporting extensive tooling and client
libraries. Statelessness enables horizontal scaling through the addition of server instances without session affinity
requirements. JSON provides broad client compatibility and human-readable payloads for debugging. JWT provides compact,
self-contained tokens suitable for distributed authentication.

**Alternative Considered:** GraphQL was evaluated for its flexibility in client data requirements but rejected due to
increased complexity in authorization enforcement and potential performance implications of complex queries. gRPC was
considered for internal service communication but rejected for the external API due to client library availability
concerns.

### 11.4 Agent Communication Model

**Decision:** Implement pull-based report submission with server-initiated requests.

**Justification:** Pull-based communication enables server-driven rate limiting, preventing agent burst traffic from
overwhelming the server. Server-side scheduling optimizes collection timing across the agent fleet. This model
simplifies firewall configuration as agents only need to respond to server requests rather than initiating connections.
Emergency alerts use a separate push mechanism for timely notification of critical events.

**Alternative Considered:** Push-based communication where agents submit reports on their own schedule was rejected due
to potential synchronization storms when many agents report simultaneously. WebSocket-based real-time communication was
considered but rejected due to connection management complexity and firewall traversal challenges.

### 11.5 Data Model Design

**Decision:** Implement a normalized relational model with JSONB columns for extensibility.

**Justification:** Normalization eliminates data redundancy, ensuring single sources of truth for core entities. The
relational model naturally represents the complex relationships between assets, software, configurations. JSONB columns
provide flexibility for type-specific attributes and organization-specific extensions without schema, and
vulnerabilities changes. This hybrid approach balances the integrity benefits of relational storage with the flexibility
of document storage.

**Alternative Considered:** A fully denormalized model was rejected due to update anomalies and data integrity risks. A
pure document model was rejected due to the complexity of relationship queries and the importance of relational
integrity for core entities.

---

## 12. Action Items and Roadmap

### 12.1 Immediate Action Items

The following action items should be completed before proceeding with Phase 1 implementation:

1. **Repository Setup:** Initialize the Git repository with appropriate .gitignore, license file, and contribution
   guidelines. Configure branch protection rules requiring pull request reviews for the main branch.

2. **Development Environment:** Configure development container or VM image with all required dependencies including
   Rust toolchain, PostgreSQL, Redis, and frontend development tools. Document setup procedures in README.md.

3. **CI/CD Pipeline:** Configure continuous integration pipeline for automated testing, linting, and build processes.
   Configure continuous deployment for development environment upon merge to main branch.

4. **API Specification:** Finalize the OpenAPI specification for the v1 API, incorporating decisions from this
   implementation plan. Establish API review process for proposed additions.

5. **Database Schema:** Create initial migration scripts for the core entity model. Establish naming conventions and
   coding standards for database migrations.

### 12.2 Phase 1 Deliverables

The following deliverables complete Phase 1 and enable Phase 2 commencement:

1. **API Server:** Functional API server with authentication, authorization, and asset CRUD operations meeting the
   specifications in Section 6.

2. **Database:** Deployed PostgreSQL database with the core entity model schema and working migrations.

3. **Web Interface:** Administrative interface providing basic asset management capabilities as described in Section
   10.1.

4. **Testing:** Unit test coverage exceeding 80% for core business logic. Integration tests for API endpoints.
   End-to-end tests for critical user workflows.

5. **Documentation:** API documentation generated from OpenAPI specification. Deployment procedures for server
   components. Configuration reference for all server settings.

---

_This implementation plan represents the current understanding of Horizon requirements and architecture. The plan will
be updated as implementation progresses and new requirements emerge._
