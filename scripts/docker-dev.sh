#!/bin/bash
# =============================================================================
# Horizon Development Environment Startup Script
# =============================================================================
# This script sets up and starts the Horizon development environment
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Functions
print_step() {
    echo -e "${BLUE}==> ${NC}${GREEN}$1${NC}"
}

print_warning() {
    echo -e "${YELLOW}WARNING:${NC} $1"
}

print_error() {
    echo -e "${RED}ERROR:${NC} $1"
}

print_info() {
    echo -e "${BLUE}INFO:${NC} $1"
}

# Check for required tools
check_requirements() {
    print_step "Checking requirements..."

    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi

    # Check Docker is running
    if ! docker info &> /dev/null; then
        print_error "Docker is not running. Please start Docker first."
        exit 1
    fi

    print_info "All requirements met."
}

# Create necessary directories
setup_directories() {
    print_step "Creating necessary directories..."

    mkdir -p "${SCRIPT_DIR}/.docker/volumes/postgres"
    mkdir -p "${SCRIPT_DIR}/.docker/volumes/redis"
    mkdir -p "${SCRIPT_DIR}/.docker/volumes/pgadmin"
    mkdir -p "${SCRIPT_DIR}/logs"
    mkdir -p "${SCRIPT_DIR}/docker/init-scripts"

    print_info "Directories created."
}

# Setup environment file
setup_env() {
    print_step "Checking environment configuration..."

    if [ ! -f "${SCRIPT_DIR}/.env" ]; then
        if [ -f "${SCRIPT_DIR}/.env.example" ]; then
            print_warning ".env file not found. Creating from .env.example"
            cp "${SCRIPT_DIR}/.env.example" "${SCRIPT_DIR}/.env"
            print_warning "Please review and update .env with your configuration!"
        else
            print_error ".env.example not found. Cannot create .env"
            exit 1
        fi
    else
        print_info "Using existing .env file."
    fi
}

# Start services
start_services() {
    print_step "Starting Horizon services..."

    cd "${SCRIPT_DIR}"

    # Determine docker compose command
    if command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        COMPOSE_CMD="docker compose"
    fi

    # Pull latest images
    print_info "Pulling Docker images..."
    ${COMPOSE_CMD} pull

    # Start services in detached mode
    print_info "Starting containers..."
    ${COMPOSE_CMD} up -d

    print_info "Waiting for services to be healthy..."

    # Wait for PostgreSQL
    print_info "Waiting for PostgreSQL..."
    until docker exec horizon-postgres pg_isready -U horizon &> /dev/null; do
        sleep 2
    done
    print_info "PostgreSQL is ready!"

    # Wait for Redis
    print_info "Waiting for Redis..."
    until docker exec horizon-redis redis-cli ping &> /dev/null; do
        sleep 2
    done
    print_info "Redis is ready!"

    print_info "All services are healthy!"
}

# Show service status
show_status() {
    print_step "Service Status"

    cd "${SCRIPT_DIR}"

    if command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        COMPOSE_CMD="docker compose"
    fi

    ${COMPOSE_CMD} ps
}

# Show helpful information
show_help() {
    echo ""
    echo -e "${GREEN}Horizon Development Environment${NC}"
    echo "================================"
    echo ""
    echo "Services started:"
    echo "  - PostgreSQL: localhost:${POSTGRES_PORT:-5432}"
    echo "  - Redis:      localhost:${REDIS_PORT:-6379}"
    echo ""
    echo "Useful commands:"
    echo "  View logs:     docker-compose logs -f"
    echo "  Stop services: docker-compose down"
    echo "  Restart:       docker-compose restart"
    echo "  Destroy:       docker-compose down -v"
    echo ""
    echo "Database connection:"
    echo "  Host:     postgres"
    echo "  Port:     5432"
    echo "  Database: horizon"
    echo "  User:     horizon"
    echo ""
    echo "Redis connection:"
    echo "  Host: redis"
    echo "  Port: 6379"
    echo ""
}

# Stop services
stop_services() {
    print_step "Stopping Horizon services..."

    cd "${SCRIPT_DIR}"

    if command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        COMPOSE_CMD="docker compose"
    fi

    ${COMPOSE_CMD} down

    print_info "Services stopped."
}

# Main command handling
case "$1" in
    start)
        check_requirements
        setup_directories
        setup_env
        start_services
        show_status
        show_help
        ;;
    stop)
        stop_services
        ;;
    restart)
        stop_services
        start
        ;;
    status)
        show_status
        ;;
    logs)
        cd "${SCRIPT_DIR}"
        if command -v docker-compose &> /dev/null; then
            docker-compose logs -f "${2:-}"
        else
            docker compose logs -f "${2:-}"
        fi
        ;;
    destroy)
        print_warning "This will delete all data!"
        read -p "Are you sure? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            cd "${SCRIPT_DIR}"
            if command -v docker-compose &> /dev/null; then
                docker-compose down -v
            else
                docker compose down -v
            fi
            print_info "Environment destroyed."
        fi
        ;;
    setup)
        check_requirements
        setup_directories
        setup_env
        ;;
    help|--help|-h)
        echo "Horizon Development Environment Management"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  start     Start all services (default)"
        echo "  stop      Stop all services"
        echo "  restart   Restart all services"
        echo "  status    Show service status"
        echo "  logs      Show service logs (optionally: service name)"
        echo "  destroy   Stop and remove all data"
        echo "  setup     Setup directories and environment only"
        echo "  help      Show this help message"
        ;;
    *)
        print_error "Unknown command: $1"
        echo "Run '$0 help' for usage information."
        exit 1
        ;;
esac
