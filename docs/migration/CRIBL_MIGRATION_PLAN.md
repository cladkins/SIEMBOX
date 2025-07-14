# Cribl Migration Plan

This document outlines the plan to migrate our log ingestion pipeline from Fluent Bit to Cribl.

## 1. Analysis of Current State

The current implementation uses Fluent Bit to collect syslog data on port 5140 (TCP/UDP) and forward it to the backend API. Parsing is handled by custom regex rules defined in `ingestion_agents/parsers.conf`.

## 2. Proposed Docker Compose Configuration

The following changes will be made to the `docker-compose.yml` file to replace Fluent Bit with Cribl.

### Remove Fluent Bit Service

The existing `fluent-bit` service will be removed entirely.

### Add Cribl Service

A new `cribl` service will be added with the following configuration:

```yaml
  # Cribl Log Processor
  cribl:
    image: cribl/cribl:latest
    container_name: siembox-cribl
    volumes:
      - ./ingestion_agents/cribl/config:/opt/cribl/config
      - ./ingestion_agents/cribl/packs:/opt/cribl/packs
      - ./ingestion_agents/cribl/data:/opt/cribl/data
    ports:
      - "9000:9000"      # Cribl UI
      - "5140:5140/udp"  # Syslog UDP
      - "5140:5140/tcp"  # Syslog TCP
    networks:
      - siembox-network
    depends_on:
      backend:
        condition: service_healthy
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
```

### Key Changes:

*   **Image:** Uses the official `cribl/cribl:latest` image.
*   **Volumes:**
    *   `./ingestion_agents/cribl/config` will store the core Cribl configuration.
    *   `./ingestion_agents/cribl/packs` will store the downloaded Cribl Packs.
    *   `./ingestion_agents/cribl/data` will store Cribl's operational data.
*   **Ports:**
    *   `9000:9000` exposes the Cribl UI for management.
    *   `5140:5140` (TCP/UDP) replaces Fluent Bit for syslog ingestion.
*   **Healthcheck:** A basic healthcheck is included to monitor the Cribl API.

## 3. Directory Structure and Pack Management

To ensure our Cribl configuration is version-controlled and easily managed, we will adopt the following directory structure within the `ingestion_agents` directory:

```
ingestion_agents/
├── cribl/
│   ├── config/       # Stores core Cribl configuration (routes, pipelines, etc.)
│   ├── packs/        # Stores downloaded Cribl Packs
│   └── data/         # Stores Cribl operational data (not version-controlled)
└── ...
```

### Pack Management Strategy

Our strategy for managing Cribl Packs is as follows:

1.  **Download and Version Control:** Packs will be downloaded from the [Cribl Dispensary](https://packs.cribl.io/) or other sources (like GitHub) and placed in the `ingestion_agents/cribl/packs` directory. This directory will be committed to our Git repository.
2.  **Configuration:** Each pack will be configured through the Cribl UI. The resulting configuration changes will be saved to the `ingestion_agents/cribl/config` directory, which is also version-controlled.
3.  **Adding New Packs:** To add a new pack, a developer will:
    a.  Download the pack to the `ingestion_agents/cribl/packs` directory.
    b.  Configure the pack through the UI.
    c.  Commit the changes to both the `packs` and `config` directories.

### Identified Packs

Based on our current needs, we have identified the following initial set of packs:

*   **Ubiquiti/UniFi:** [cribl-ubiquiti-syslog](https://github.com/criblpacks/cribl-ubiquiti-syslog)
*   **Syslog:** A general syslog pack from the Cribl Dispensary (e.g., `cribl-syslog-input`).
*   **OPNsense:** We will start with a generic firewall or syslog pack and adapt it as needed. If a dedicated pack becomes available, we will migrate to it.

## 4. Backend API Changes

To support log ingestion from Cribl, the following changes will be made to the backend API:

### New Ingestion Endpoint

A new API endpoint, `/api/v1/logs/ingest/cribl`, will be created in `backend/app/api/v1/logs.py`. This endpoint will be responsible for receiving data from Cribl.

Unlike the existing Fluent Bit endpoint, the Cribl endpoint will expect a simple, clean JSON payload that maps directly to our `LogIngestRequest` schema. This is because all parsing and data transformation will be handled within Cribl itself.

### Example Cribl Endpoint Implementation

```python
# In backend/app/api/v1/logs.py

@router.post("/ingest/cribl", response_model=LogIngestResponse)
async def ingest_cribl_log(
    log_data: LogIngestRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Ingest a new log entry from Cribl.
    
    This endpoint assumes the log data has already been parsed and
    structured by Cribl to match the LogIngestRequest schema.
    """
    try:
        raw_log = await LogService.ingest_log(db, log_data)
        
        return LogIngestResponse(
            success=True,
            log_id=str(raw_log.id),
            message="Log successfully ingested from Cribl"
        )
        
    except Exception as e:
        logger.error(f"Cribl log ingestion failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to ingest Cribl log: {str(e)}"
        )
```

### Cribl Output Configuration

The Cribl instance will be configured with an HTTP destination that points to `http://backend:8000/api/v1/logs/ingest/cribl`. The output format will be configured to match the `LogIngestRequest` schema, ensuring a seamless integration.

## 5. Migration Steps

The migration will be performed in the following sequence:

1.  **Create New Directories:**
    *   Create the `ingestion_agents/cribl`, `ingestion_agents/cribl/config`, `ingestion_agents/cribl/packs`, and `ingestion_agents/cribl/data` directories.
    *   Add `ingestion_agents/cribl/data` to the `.gitignore` file.

2.  **Download Initial Packs:**
    *   Download the identified packs (`cribl-ubiquiti-syslog`, etc.) and place them in the `ingestion_agents/cribl/packs` directory.

3.  **Implement Backend Changes:**
    *   Add the new `/api/v1/logs/ingest/cribl` endpoint to `backend/app/api/v1/logs.py`.

4.  **Update Docker Compose:**
    *   Modify the `docker-compose.yml` file to remove the `fluent-bit` service and add the new `cribl` service.

5.  **Initial Cribl Configuration:**
    *   Start the new environment using `docker-compose up -d`.
    *   Access the Cribl UI at `http://localhost:9000`.
    *   Configure the following:
        *   **Sources:** Create a new Syslog source listening on port 5140 (TCP/UDP).
        *   **Packs:** Enable and configure the downloaded packs to parse incoming data.
        *   **Destinations:** Create a new HTTP destination pointing to `http://backend:8000/api/v1/logs/ingest/cribl`.
        *   **Routes:** Create routes to connect the Syslog source to the appropriate packs and then to the backend destination.

6.  **Testing and Validation:**
    *   Send test syslog messages from UniFi, OPNsense, and other sources to the Cribl listener.
    *   Verify that the data is correctly parsed and enriched by the Cribl packs.
    *   Verify that the transformed data is successfully ingested by the backend API.
    *   Verify that the logs appear correctly in the SIEM Box UI.

7.  **Commit Changes:**
    *   Commit the updated `docker-compose.yml`, the new backend code, the downloaded packs, and the new Cribl configuration to the Git repository.
