#!/bin/bash

# SIEM BOX - Volume Reset Script
# This script safely removes Docker volumes for fresh installations
# Use this when you need to start with a clean database or resolve version conflicts

set -e

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

echo "🔄 SIEM BOX Volume Reset Script"
echo "==============================="
echo ""

print_warning "This script will remove ALL data from SIEM BOX volumes!"
print_warning "This includes:"
echo "  - All log data in PostgreSQL database"
echo "  - All alerts and detection history"
echo "  - All user accounts and settings"
echo "  - Fluent Bit processing state"
echo "  - Vulnerability scan results"
echo ""

# Confirmation prompt
read -p "Are you sure you want to continue? (type 'yes' to confirm): " confirmation

if [ "$confirmation" != "yes" ]; then
    print_status "Operation cancelled."
    exit 0
fi

print_status "Stopping SIEM BOX services..."
docker-compose down

print_status "Removing SIEM BOX volumes..."

# Remove specific volumes
volumes_to_remove=(
    "siembox_postgres_data"
    "siembox_fluent_bit_data"
    "siembox_vulnerability_data"
    "siembox_trivy_cache"
)

for volume in "${volumes_to_remove[@]}"; do
    if docker volume ls -q | grep -q "^${volume}$"; then
        print_status "Removing volume: $volume"
        docker volume rm "$volume" 2>/dev/null || print_warning "Volume $volume may not exist or is in use"
    else
        print_status "Volume $volume does not exist, skipping"
    fi
done

# Alternative: Remove all volumes with siembox prefix
print_status "Checking for any remaining SIEM BOX volumes..."
remaining_volumes=$(docker volume ls -q | grep "siembox" || true)

if [ -n "$remaining_volumes" ]; then
    print_status "Found additional volumes:"
    echo "$remaining_volumes"
    read -p "Remove these volumes too? (y/N): " remove_remaining
    
    if [ "$remove_remaining" = "y" ] || [ "$remove_remaining" = "Y" ]; then
        echo "$remaining_volumes" | xargs -r docker volume rm
        print_success "Additional volumes removed"
    fi
fi

print_success "Volume cleanup completed!"
echo ""
print_status "Next steps:"
echo "1. Start SIEM BOX with: docker-compose up -d"
echo "2. Wait for services to initialize (this may take a few minutes)"
echo "3. Access the application at http://localhost:3000"
echo "4. Use default credentials: admin / admin123"
echo ""
print_warning "Remember to change default credentials after first login!"