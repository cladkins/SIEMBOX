#!/bin/bash

# SIEM BOX - Deployment Test Script
# This script tests the end-to-end functionality of SIEM BOX

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

# Test variables
BASE_URL="http://localhost:8000"
SYSLOG_PORT=5140

echo "🧪 SIEM BOX Deployment Test"
echo "==========================="

# Test 1: Health Check
test_health_check() {
    print_status "Testing health check endpoint..."
    
    local response=$(curl -s "$BASE_URL/api/v1/health/" || echo "failed")
    
    if echo "$response" | grep -q '"status"'; then
        print_success "Health check endpoint is responding"
        return 0
    else
        print_error "Health check endpoint failed"
        return 1
    fi
}

# Test 2: Database Connection
test_database_connection() {
    print_status "Testing database connection..."
    
    local response=$(curl -s "$BASE_URL/api/v1/health/database" || echo "failed")
    
    if echo "$response" | grep -q '"status":"healthy"'; then
        print_success "Database connection is working"
        return 0
    else
        print_error "Database connection failed"
        echo "Response: $response"
        return 1
    fi
}

# Test 3: API Documentation
test_api_docs() {
    print_status "Testing API documentation..."
    
    local status_code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/docs" || echo "000")
    
    if [ "$status_code" = "200" ]; then
        print_success "API documentation is accessible"
        return 0
    else
        print_error "API documentation is not accessible (HTTP $status_code)"
        return 1
    fi
}

# Test 4: Log Ingestion
test_log_ingestion() {
    print_status "Testing log ingestion..."
    
    local test_log='{
        "timestamp": "2024-01-01T12:00:00Z",
        "source_ip": "192.168.1.100",
        "source_port": 514,
        "protocol": "UDP",
        "hostname": "test-host",
        "app_name": "test-app",
        "raw_message": "Test log message from deployment test"
    }'
    
    local response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$test_log" \
        "$BASE_URL/api/v1/logs/ingest" || echo "failed")
    
    if echo "$response" | grep -q '"success":true'; then
        print_success "Log ingestion is working"
        
        # Extract log ID for retrieval test
        LOG_ID=$(echo "$response" | grep -o '"log_id":"[^"]*"' | cut -d'"' -f4)
        return 0
    else
        print_error "Log ingestion failed"
        echo "Response: $response"
        return 1
    fi
}

# Test 5: Log Retrieval
test_log_retrieval() {
    print_status "Testing log retrieval..."
    
    local response=$(curl -s "$BASE_URL/api/v1/logs/?limit=5" || echo "failed")
    
    if echo "$response" | grep -q '"id"' && echo "$response" | grep -q '"raw_message"'; then
        print_success "Log retrieval is working"
        return 0
    else
        print_error "Log retrieval failed"
        echo "Response: $response"
        return 1
    fi
}

# Test 6: Specific Log Retrieval
test_specific_log_retrieval() {
    if [ -n "$LOG_ID" ]; then
        print_status "Testing specific log retrieval..."
        
        local response=$(curl -s "$BASE_URL/api/v1/logs/$LOG_ID" || echo "failed")
        
        if echo "$response" | grep -q '"id"' && echo "$response" | grep -q "test-host"; then
            print_success "Specific log retrieval is working"
            return 0
        else
            print_error "Specific log retrieval failed"
            echo "Response: $response"
            return 1
        fi
    else
        print_status "Skipping specific log retrieval (no log ID available)"
        return 0
    fi
}

# Test 7: Log Statistics
test_log_statistics() {
    print_status "Testing log statistics..."
    
    local response=$(curl -s "$BASE_URL/api/v1/logs/stats/summary" || echo "failed")
    
    if echo "$response" | grep -q '"total_logs"' && echo "$response" | grep -q '"recent_logs"'; then
        print_success "Log statistics are working"
        return 0
    else
        print_error "Log statistics failed"
        echo "Response: $response"
        return 1
    fi
}

# Test 8: Syslog Port Accessibility
test_syslog_port() {
    print_status "Testing syslog port accessibility..."
    
    # Test UDP port
    if nc -u -z localhost $SYSLOG_PORT 2>/dev/null; then
        print_success "Syslog UDP port $SYSLOG_PORT is accessible"
        return 0
    else
        print_error "Syslog UDP port $SYSLOG_PORT is not accessible"
        return 1
    fi
}

# Test 9: Fluent Bit Health
test_fluent_bit_health() {
    print_status "Testing Fluent Bit health..."
    
    local status_code=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:2020/api/v1/health" || echo "000")
    
    if [ "$status_code" = "200" ]; then
        print_success "Fluent Bit health endpoint is accessible"
        return 0
    else
        print_error "Fluent Bit health endpoint is not accessible (HTTP $status_code)"
        return 1
    fi
}

# Test 10: Docker Services
test_docker_services() {
    print_status "Testing Docker services..."
    
    local services=("siembox-postgres" "siembox-backend" "siembox-fluent-bit")
    local all_running=true
    
    for service in "${services[@]}"; do
        if docker ps --format "table {{.Names}}" | grep -q "$service"; then
            print_success "Service $service is running"
        else
            print_error "Service $service is not running"
            all_running=false
        fi
    done
    
    if $all_running; then
        return 0
    else
        return 1
    fi
}

# Test 11: Send Test Syslog Message
test_syslog_ingestion() {
    print_status "Testing syslog message ingestion..."
    
    # Send a test syslog message
    local test_message="<14>Jan 01 12:00:00 test-host test-app: Test syslog message from deployment test"
    
    if command -v nc >/dev/null 2>&1; then
        echo "$test_message" | nc -u localhost $SYSLOG_PORT
        
        # Wait a moment for processing
        sleep 2
        
        # Check if the message was ingested
        local response=$(curl -s "$BASE_URL/api/v1/logs/?hostname=test-host&limit=1" || echo "failed")
        
        if echo "$response" | grep -q "test-host"; then
            print_success "Syslog message ingestion is working"
            return 0
        else
            print_error "Syslog message was not ingested properly"
            return 1
        fi
    else
        print_status "Skipping syslog ingestion test (nc not available)"
        return 0
    fi
}

# Run all tests
run_all_tests() {
    local failed_tests=0
    local total_tests=0
    
    echo "Running deployment tests..."
    echo ""
    
    # Array of test functions
    tests=(
        "test_health_check"
        "test_database_connection"
        "test_api_docs"
        "test_log_ingestion"
        "test_log_retrieval"
        "test_specific_log_retrieval"
        "test_log_statistics"
        "test_syslog_port"
        "test_docker_services"
        "test_syslog_ingestion"
    )
    
    for test in "${tests[@]}"; do
        ((total_tests++))
        if ! $test; then
            ((failed_tests++))
        fi
        echo ""
    done
    
    echo "=========================="
    echo "Test Results:"
    echo "Total tests: $total_tests"
    echo "Passed: $((total_tests - failed_tests))"
    echo "Failed: $failed_tests"
    
    if [ $failed_tests -eq 0 ]; then
        echo -e "${GREEN}🎉 All tests passed! SIEM BOX is working correctly.${NC}"
        return 0
    else
        echo -e "${RED}❌ Some tests failed. Please check the output above.${NC}"
        return 1
    fi
}

# Main execution
case "${1:-}" in
    "help"|"-h"|"--help")
        echo "SIEM BOX Deployment Test Script"
        echo ""
        echo "Usage: $0 [test_name]"
        echo ""
        echo "Available tests:"
        echo "  health          - Test health check endpoint"
        echo "  database        - Test database connection"
        echo "  docs            - Test API documentation"
        echo "  ingest          - Test log ingestion"
        echo "  retrieve        - Test log retrieval"
        echo "  stats           - Test log statistics"
        echo "  syslog          - Test syslog port"
        echo "  fluent-bit      - Test Fluent Bit health"
        echo "  services        - Test Docker services"
        echo "  all             - Run all tests (default)"
        ;;
    "health")
        test_health_check
        ;;
    "database")
        test_database_connection
        ;;
    "docs")
        test_api_docs
        ;;
    "ingest")
        test_log_ingestion
        ;;
    "retrieve")
        test_log_retrieval
        ;;
    "stats")
        test_log_statistics
        ;;
    "syslog")
        test_syslog_port
        ;;
    "fluent-bit")
        test_fluent_bit_health
        ;;
    "services")
        test_docker_services
        ;;
    "all"|*)
        run_all_tests
        ;;
esac