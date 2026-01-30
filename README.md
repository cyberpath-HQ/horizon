<div align="center">
  <picture>
    <source srcset="https://raw.githubusercontent.com/cyberpath-HQ/horizon/refs/heads/main/.assets/logo-white.svg" media="(prefers-color-scheme: dark)" />
    <source srcset="https://raw.githubusercontent.com/cyberpath-HQ/horizon/refs/heads/main/.assets/logo.svg" media="(prefers-color-scheme: light)" />
    <img src="https://raw.githubusercontent.com/cyberpath-HQ/horizon/refs/heads/main/.assets/logo.svg" alt="Horizon Logo" height="64"/>
  </picture>

[![Cyberpath](https://img.shields.io/badge/Cyberpath-project-blue)](https://sentinel.cyberpath-hq.com)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE.md)
![Codecov](https://img.shields.io/codecov/c/github/cyberpath-HQ/horizon)

_A self-hostable Configuration Management Database (CMDB) system designed to provide comprehensive visibility into an
organization's IT infrastructure._

</div>

---

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Technology Stack](#technology-stack)
4. [Architecture](#architecture)
5. [Getting Started](#getting-started)
6. [Project Structure](#project-structure)
7. [Documentation](#documentation)
8. [Contributing](#contributing)
9. [Security](#security)
10. [License](#license)

---

## Overview

Horizon is a self-hostable Configuration Management Database (CMDB) system that combines a powerful backend with a
lightweight, cross-platform agent to automatically discover and inventory hardware assets, software installations,
network configurations, and security-relevant information.

### Vision

Horizon provides organizations with complete control over their IT asset data through a self-hostable solution with no
licensing costs and complete data ownership.

### Strategic Goals

- **Comprehensiveness**: Capture all information relevant to IT asset management
- **Automation**: Lightweight agent collection with minimal configuration
- **Flexibility**: Support both automated and manual data entry
- **Integrity**: Complete audit trails and data quality assessment
- **Intelligence**: AI-powered pattern recognition via inference providers
- **Accessibility**: Multiple interfaces including web and desktop applications

---

## Key Features

### Asset Inventory Management

- **Hardware Discovery**: Automated collection of CPU, memory, storage, network interfaces, and peripherals
- **Software Tracking**: Inventory of installed packages, running services, and startup items
- **Asset Relationships**: Map dependencies and connections between assets
- **Full-Text Search**: Powerful search capabilities across all asset metadata
- **Import/Export**: Support for CSV, Excel, JSON, and XML formats

### Network Flow Mapping

- **Interface Discovery**: Track all network interfaces and IP addresses
- **Flow Collection**: Aggregate and analyze network traffic patterns
- **Topology Visualization**: Visual representation of network architecture
- **Anomaly Detection**: AI-powered identification of unusual network behavior

### Security Configuration

- **CIS Benchmark Support**: Validate configurations against industry standards
- **Configuration Drift Detection**: Monitor changes over time
- **Compliance Scoring**: Automated assessment of security posture
- **Remediation Guidance**: AI-powered recommendations for fixing violations

### Vulnerability Management

- **CVE Synchronization**: Automatic sync with National Vulnerability Database
- **Asset Correlation**: Link vulnerabilities to affected assets
- **Penetration Test Integration**: Track findings from security assessments
- **Red Team Tracking**: MITRE ATT&CK technique mapping and IOC tracking

### Business Impact Analysis (BIA)

- **Critical System Registry**: Classify systems by business criticality
- **Dependency Mapping**: Visualize system dependencies and impact cascades
- **Recovery Planning**: Document recovery procedures and contact information
- **Impact Scoring**: Calculate financial and operational impact

### Vendor Management

- **Vendor Profiles**: Track vendor contacts and performance metrics
- **Contract Management**: Monitor contract lifecycle and renewals
- **Asset-Vendor Association**: Link assets to vendor contracts
- **SLA Tracking**: Monitor vendor service level agreements

### Notification System

- **Event-Based Triggers**: Configure alerts for specific events
- **Multi-Channel Delivery**: Email, webhooks, Slack, Microsoft Teams
- **Escalation Workflows**: Automated escalation procedures
- **Notification Aggregation**: Reduce alert fatigue with intelligent grouping

## Getting Started

### Prerequisites

- Rust 1.94.0-nightly or later
- PostgreSQL (latest stable)
- Redis (latest stable)
- Docker and Docker Compose (for containerized deployment)

### Quick Start

1. **Clone the repository**

```bash
git clone https://github.com/cyberpath-HQ/horizon.git
cd horizon
```

2. **Start development environment**

```bash
docker-compose up -d
```

3. **Build the project**

```bash
cargo build --release
```

4. **Start the server**

```bash
cargo run --bin horizon-server
```

5. **Access the web UI**

Open your browser to `http://localhost:8080`

### Development Setup

See [DEVELOPMENT.md](docs/DEVELOPMENT.md) for detailed setup instructions.

---

## Project Structure

```
horizon/
├── Cargo.toml                 # Workspace configuration
├── README.md                  # This file
├── docker-compose.yml         # Docker Compose configuration
├── crates/                    # Workspace members
│   ├── api-server/           # REST API server
│   ├── agent/                # Cross-platform agent
│   ├── common/               # Shared utilities
│   ├── crypto/               # Cryptographic operations
│   ├── database/             # Database layer
│   ├── models/               # Data models
│   └── cli/                  # Command-line tools
├── migrations/               # Database migrations
├── docs/                     # Documentation
└── scripts/                  # Build and deployment scripts
```

---

## Documentation

| Document                                         | Description                            |
| ------------------------------------------------ | -------------------------------------- |
| [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) | Detailed implementation roadmap        |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md)          | System architecture documentation      |
| [API.md](docs/API.md)                            | API reference documentation            |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md)            | Development environment setup          |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md)              | Production deployment guide            |
| [SECURITY.md](docs/SECURITY.md)                  | Security guidelines and best practices |
| [AGENT.md](docs/AGENT.md)                        | Agent installation and configuration   |

---

## Contributing

### Getting Help

- Check the [documentation](docs/)
- Search [existing issues](../../issues)
- Open a [new issue](../../issues/new) for bugs or feature requests
- Join our [Discord community](https://discord.gg/cyberpath)

### Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Security

### Security Model

Horizon implements defense-in-depth security measures:

1. **Encryption at Rest**: XChaCha20-Poly1305 for sensitive data
2. **Encryption in Transit**: mTLS for all communications
3. **Authentication**: JWT tokens with MFA support
4. **Password Security**: Argon2id password hashing
5. **Audit Logging**: Complete audit trail of all actions
6. **Secure Memory**: Zeroize for sensitive data clearing

### Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

1. Do NOT open a public issue
2. Email: support@cyberpath-hq.com
3. Include detailed reproduction steps
4. Allow time for remediation before disclosure

See [SECURITY.md](docs/SECURITY.md) for full security guidelines.

---

## Version Policy

- **Rust Version**: Minimum 1.94.0-nightly, always use latest stable or nightly
- **Dependencies**: Always use latest available versions
- **Breaking Changes**: Major version bumps for breaking changes
- **Support**: Latest version always supported

---

## Roadmap

See [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for the complete implementation roadmap.

### Implementation Phases

| Phase | Description                                                   | Status      |
| ----- | ------------------------------------------------------------- | ----------- |
| A     | Foundation (Infrastructure, Docker, Logging, Migrations)      | In Progress |
| B     | Authentication (Users, Teams, RBAC, JWT, MFA)                 | Planned     |
| C     | Web Frontend (React, Auth Pages, Layout)                      | Planned     |
| D     | Asset Inventory Core (Schema, CRUD, Search, Import)           | Planned     |
| E     | Agent Foundation (Hardware/Software Discovery, Communication) | Planned     |
| F-Z   | Additional features (Software, Security, Network, BIA, etc.)  | Planned     |

---

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with ❤️ by the Cyberpath Team**

</div>
