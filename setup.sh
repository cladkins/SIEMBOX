#!/bin/bash

# SIEM BOX - Setup Script
# This script helps set up SIEM BOX for first-time deployment

set -e

echo "🏠 SIEM BOX Setup Script"
echo "========================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
check_docker() {
    print_status "Checking Docker installation..."
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        echo "Visit: https://docs.docker.com/get-docker/"
        exit 1
    fi
    print_success "Docker is installed"
}

# Check if Docker Compose is installed
check_docker_compose() {
    print_status "Checking Docker Compose installation..."
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        echo "Visit: https://docs.docker.com/compose/install/"
        exit 1
    fi
    print_success "Docker Compose is installed"
}

# Create environment file
setup_environment() {
    print_status "Setting up environment configuration..."
    
    if [ ! -f "backend/.env" ]; then
        cp backend/.env.example backend/.env
        print_success "Created backend/.env from example"
        print_warning "Please review and update backend/.env with your specific configuration"
    else
        print_warning "backend/.env already exists, skipping creation"
    fi
}

# Create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    
    # Create log directories if they don't exist
    mkdir -p logs/fluent-bit
    mkdir -p logs/backend
    
    print_success "Directories created"
}

# Set proper permissions
set_permissions() {
    print_status "Setting proper permissions..."
    
    # Make sure Docker can access log directories
    chmod -R 755 logs/ 2>/dev/null || true
    
    # Make sure Fluent Bit config is readable
    chmod 644 ingestion_agents/*.conf 2>/dev/null || true
    
    print_success "Permissions set"
}

# Pull Docker images
pull_images() {
    print_status "Pulling Docker images..."
    
    docker-compose pull
    cd ..
    
    print_success "Docker images pulled"
}

# Build custom images
build_images() {
    print_status "Building SIEM BOX backend image..."
    
    docker-compose build backend
    cd ..
    
    print_success "Backend image built"
}

# Start services
start_services() {
    print_status "Starting SIEM BOX services..."
    
    docker-compose up -d
    cd ..
    
    print_success "Services started"
}

# Wait for services to be ready
wait_for_services() {
    print_status "Waiting for services to be ready..."
    
    # Wait for backend to be healthy
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s http://localhost:8000/api/v1/health/ > /dev/null 2>&1; then
            print_success "Backend service is ready"
            break
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            print_error "Backend service failed to start within expected time"
            print_status "Check logs with: docker logs siembox-backend"
            exit 1
        fi
        
        echo -n "."
        sleep 2
        ((attempt++))
    done
}

# Verify installation
verify_installation() {
    print_status "Verifying installation..."
    
    # Check service health
    local health_response=$(curl -s http://localhost:8000/api/v1/health/ || echo "failed")
    
    if echo "$health_response" | grep -q "healthy\|unhealthy"; then
        print_success "Backend API is responding"
    else
        print_error "Backend API is not responding correctly"
        return 1
    fi
    
    # Check database connection
    if echo "$health_response" | grep -q '"database":"connected"'; then
        print_success "Database connection is working"
    else
        print_warning "Database connection may have issues"
    fi
    
    # Check if Fluent Bit is running
    if docker ps | grep -q siembox-fluent-bit; then
        print_success "Fluent Bit is running"
    else
        print_error "Fluent Bit is not running"
        return 1
    fi
    
    print_success "Installation verification completed"
}

# Show next steps
show_next_steps() {
    echo ""
    echo "🎉 SIEM BOX Setup Complete!"
    echo "=========================="
    echo ""
    echo "Next steps:"
    echo "1. Access the API documentation: http://localhost:8000/docs"
    echo "2. Check service health: http://localhost:8000/api/v1/health/"
    echo "3. Configure your log sources (see ingestion_agents/examples/)"
    echo "4. Monitor logs: docker logs siembox-backend"
    echo ""
    echo "Useful commands:"
    echo "- View all services: docker-compose ps"
    echo "- Stop services: docker-compose down"
    echo "- View logs: docker-compose logs -f"
    echo ""
    echo "For configuration help, see:"
    echo "- Unifi: ingestion_agents/examples/unifi-syslog-config.md"
    echo "- OPNsense/pfSense: ingestion_agents/examples/opnsense-syslog-config.md"
    echo "- Docker: ingestion_agents/examples/docker-logs-config.md"
    echo ""
}

# Main execution
main() {
    echo "Starting SIEM BOX setup..."
    echo ""
    
    check_docker
    check_docker_compose
    setup_environment
    create_directories
    set_permissions
    pull_images
    build_images
    start_services
    wait_for_services
    
    if verify_installation; then
        show_next_steps
    else
        print_error "Installation verification failed. Please check the logs."
        exit 1
    fi
}

# Handle script arguments
case "${1:-}" in
    "help"|"-h"|"--help")
        echo "SIEM BOX Setup Script"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  help     Show this help message"
        echo "  start    Start services (without full setup)"
        echo "  stop     Stop all services"
        echo "  restart  Restart all services"
        echo "  status   Show service status"
        echo "  logs     Show service logs"
        echo ""
        echo "Default: Run full setup"
        ;;
    "start")
        docker-compose up -d
        ;;
    "stop")
        docker-compose down
        ;;
    "restart")
        docker-compose restart
        ;;
    "status")
        docker-compose ps
        ;;
    "logs")
        docker-compose logs -f
        ;;
    *)
        main
        ;;
esac