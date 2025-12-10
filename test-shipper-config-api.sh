#!/bin/bash

# Test script to check what the shipper configuration API returns
# Run this on your backend server to diagnose the issue

API_KEY="f25d8cc2a7994ab3626e677169b5a53e9c478327373c09302c7aab8cbc5c9031"
API_URL="http://192.168.1.76:3001/api/shippers/config/${API_KEY}"

echo "========================================="
echo "SIEMBox Shipper Configuration API Test"
echo "========================================="
echo "API URL: ${API_URL}"
echo ""

echo "Fetching configuration..."
response=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${API_URL}")

http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
body=$(echo "$response" | sed '/HTTP_CODE:/d')

echo "HTTP Status: ${http_code}"
echo ""

if [ "$http_code" = "200" ]; then
    echo "✓ API call successful"
    echo ""
    echo "Configuration returned:"
    echo "$body" | jq '.' 2>/dev/null || echo "$body"
    echo ""

    # Check for sources
    source_count=$(echo "$body" | jq '.sources | length' 2>/dev/null)
    echo "Number of sources: ${source_count}"

    if [ "$source_count" -gt 0 ]; then
        echo ""
        echo "Sources:"
        echo "$body" | jq '.sources' 2>/dev/null
    else
        echo ""
        echo "⚠ WARNING: No sources configured!"
    fi

    # Check for siem_host and siem_port
    siem_host=$(echo "$body" | jq -r '.siem_host // "not set"' 2>/dev/null)
    siem_port=$(echo "$body" | jq -r '.siem_port // "not set"' 2>/dev/null)
    echo ""
    echo "SIEM Host: ${siem_host}"
    echo "SIEM Port: ${siem_port}"

else
    echo "✗ API call failed"
    echo ""
    echo "Response:"
    echo "$body"
fi

echo ""
echo "========================================="
