# Horizon Development Environment Setup

## Overview

This document describes how to set up the Docker development environment for Horizon.

## Prerequisites

- Docker Engine 24.0+
- Docker Compose V2 (or V1 with python wrapper)
- 4GB+ available RAM
- 10GB+ available disk space

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/cyberpath-HQ/horizon.git
cd horizon
```

### 2. Start Docker Environment

```bash
# Option A: Using the convenience script (recommended)
./scripts/docker-dev.sh start

# Option B: Using docker-compose directly
docker-compose up -d
```

### 3. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit with your settings
nano .env
```

### 4. Verify Services

```bash
# Check service status
./scripts/docker-dev.sh status

# Wait for PostgreSQL to be ready
./scripts/docker-dev.sh logs postgres | grep "ready to accept connections"

# Wait for Redis to be ready
./scripts/docker-dev.sh logs redis | grep "Ready to accept connections"
```

### 5. Build and Run Application

```bash
# Build the Rust application
cargo build

# Run database migrations
cargo run --bin horizon migrate

# Start the development server
cargo run --bin horizon serve
```

## Service Endpoints

| Service   | Host              | Credentials            |
|-----------|-------------------|------------------------|
| PostgreSQL| localhost:5432    | horizon/horizon_secret |
| Redis     | localhost:6379    | No authentication      |

## Database Connection

### From Host Machine
```bash
psql -h localhost -p 5432 -U horizon -d horizon
```

### From Docker Network
```bash
# Connect from another container
psql -h postgres -p 5432 -U horizon -d horizon

# Or using docker exec
docker exec -it horizon-postgres psql -U horizon -d horizon
```

## Redis Connection

### From Host Machine
```bash
redis-cli -p 6379
```

### From Docker Network
```bash
# Connect from another container
redis-cli -h redis -p 6379

# Or using docker exec
docker exec -it horizon-redis redis-cli
```

## Troubleshooting

### PostgreSQL Won't Start

1. Check if port 5432 is already in use:
   ```bash
   lsof -i :5432
   ```

2. Check PostgreSQL logs:
   ```bash
   ./scripts/docker-dev.sh logs postgres
   ```

3. Remove and:
   ```bash recreate volumes
   ./scripts/docker-dev.sh destroy
   ./scripts/docker-dev.sh start
   ```

### Redis Connection Refused

1. Check Redis status:
   ```bash
   docker exec horizon-redis redis-cli ping
   ```

2. Check Redis logs:
   ```bash
   ./scripts/docker-dev.sh logs redis
   ```

3. Restart Redis:
   ```bash
   docker restart horizon-redis
   ```

### Permission Issues with Volumes

Ensure the directories have correct permissions:
```bash
sudo chown -R $(id -u):$(id -g) .docker/volumes/
```

### Out of Memory

Reduce container memory limits in `docker-compose.yml`:
```yaml
deploy:
  resources:
    limits:
      memory: 256M  # Reduce from 512M
```

## Development Workflow

### Daily Development

```bash
# Start services (if not running)
./scripts/docker-dev.sh start

# Work on code
cargo build --watch

# Run tests
cargo test

# View logs
./scripts/docker-dev.sh logs -f
```

### Clean Restart

```bash
# Stop and remove everything
./scripts/docker-dev.sh destroy

# Fresh start
./scripts/docker-dev.sh start
```

## Production Considerations

This Docker configuration is **for development only**. For production:

1. Use a managed PostgreSQL service (AWS RDS, Cloud SQL, etc.)
2. Use managed Redis (AWS ElastiCache, etc.)
3. Implement proper secrets management
4. Configure TLS/SSL
5. Set up monitoring and alerting
6. Use Kubernetes or container orchestration

## Additional Resources

- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Redis Documentation](https://redis.io/documentation)
- [pgAdmin Documentation](https://www.pgadmin.org/docs/)
