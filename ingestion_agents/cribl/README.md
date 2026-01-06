# Cribl Stream Configuration for SIEMBox

This directory contains the Cribl Stream configuration for SIEMBox's Pattern B architecture.

## Overview

SIEMBox uses Cribl Stream as its log processing engine with a dual-destination architecture:
- **Real-time**: HTTP output to backend `/api/v1/logs/cribl`
- **Long-term**: Filesystem output to `/opt/cribl/data/SIEMBOX`

## Configuration Files

### `inputs.yml`
- **syslog_in**: UDP/TCP syslog input on port 5140
- **http_in**: HTTP input on port 8088

### `outputs.yml`
- **siembox_http**: HTTP output to backend for real-time processing
- **siembox_storage**: Filesystem output for long-term storage
- **default**: Fallback filesystem output

### `routes.yml`
- Routes logs from inputs to dual destinations
- Clones logs to both HTTP and filesystem outputs

### `pipelines/main.yml`
- Basic log processing pipeline
- Adds SIEMBox metadata
- Cleans up internal fields

## Getting Started

1. **Start the services**:
   ```bash
   docker-compose up -d
   ```

2. **Access Cribl UI**:
   - URL: http://localhost:9000
   - Default credentials: admin/admin (change in production)

3. **Test the flow**:
   ```bash
   ./test_cribl_flow.sh
   ```

## Sending Logs

### Syslog (UDP/TCP)
```bash
# Send a test syslog message
echo '<14>Jan 01 12:00:00 myhost myapp: Test message' | nc -u localhost 5140
```

### HTTP
```bash
# Send a test HTTP message
curl -X POST -H "Content-Type: application/json" \
  -d '{"timestamp": "2024-01-01T12:00:00Z", "message": "Test HTTP message"}' \
  http://localhost:8088/services/collector/event
```

## Monitoring

### Check Processing
```bash
# Backend logs
docker logs -f siembox-backend

# Cribl logs
docker logs -f siembox-cribl
```

### Verify Outputs
```bash
# Check filesystem output
docker exec siembox-cribl ls -la /opt/cribl/data/SIEMBOX/

# Check HTTP output via backend API
curl http://localhost:8000/api/v1/logs/stats
```

## Configuration Notes

- **Authentication**: Uses bearer token authentication between Cribl and backend
- **Token**: Currently set to `siembox-token-change-in-production` (change in production)
- **Processing**: All logs go through the `main` pipeline for enrichment
- **Storage**: Logs are partitioned by date in filesystem output

## Troubleshooting

### Common Issues

1. **Logs not reaching backend**:
   - Check Cribl logs: `docker logs siembox-cribl`
   - Verify backend is healthy: `curl http://localhost:8000/api/v1/health/`
   - Check authentication token configuration

2. **Syslog not working**:
   - Verify port 5140 is accessible
   - Check firewall settings
   - Test with: `nc -u -z localhost 5140`

3. **HTTP input not working**:
   - Verify port 8088 is accessible
   - Check Content-Type header
   - Test with curl command above

### Log Locations
- **Cribl config**: `/opt/cribl/config/`
- **Cribl data**: `/opt/cribl/data/`
- **SIEMBox logs**: `/opt/cribl/data/SIEMBOX/`

## Customization

### Adding New Inputs
1. Add to `inputs.yml`
2. Update `routes.yml` to route new input
3. Restart Cribl: `docker-compose restart cribl`

### Modifying Processing
1. Edit `pipelines/main.yml`
2. Add custom functions as needed
3. Restart Cribl to apply changes

### Custom Outputs
1. Add to `outputs.yml`
2. Update routing configuration
3. Test with `./test_cribl_flow.sh`

## Security

- Change default authentication credentials
- Update bearer token in production
- Configure firewall rules for input ports
- Enable TLS for production deployments

For more information, see the main SIEMBox documentation or access the Cribl UI at http://localhost:9000.