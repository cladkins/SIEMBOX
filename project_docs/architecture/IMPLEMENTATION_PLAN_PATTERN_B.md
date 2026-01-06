# Implementation Plan: Transition to Pattern B

## 1. Overview

This document outlines the step-by-step plan for transitioning from the current log management architecture (Pattern A) to the proposed architecture (Pattern B). This transition involves reconfiguring Cribl to retain data locally, refactoring the backend to query the Cribl Search API, and decommissioning the PostgreSQL `raw_logs` table.

**Architecture Shift:**

*   **From (Pattern A):** `Log Source -> Cribl -> Backend -> PostgreSQL`
*   **To (Pattern B):** `Log Source -> Cribl <-> Backend`

## 2. Phase 1: Cribl Reconfiguration

**Objective:** Reconfigure Cribl to stop forwarding logs to the backend and instead retain them locally for API-based queries.

### Step 1.1: Disable the HTTP Output to the Backend

1.  **Locate the Output Configuration:**
    *   Navigate to the Cribl UI or the configuration file at `ingestion_agents/cribl/local/cribl/outputs.yml`.

2.  **Disable the Existing Output:**
    *   In the `outputs.yml` file, set the `disabled` flag to `true` for the HTTP output targeting the backend.

    ```yaml
    outputs:
      "0":
        type: http
        disabled: true # Change this to true
        url: http://backend:8000/api/v1/logs/cribl
        method: POST
        headers:
          - name: Content-Type
            value: application/json
    ```

### Step 1.2: Configure Local Data Retention

1.  **Enable a Filesystem-based Destination:**
    *   Configure a `Filesystem/NFS` destination in Cribl to store logs locally. This will serve as the data source for the Cribl Search API.
    *   Define a clear directory structure for retained logs (e.g., `/opt/cribl/data/logs/{source_type}/{YYYY}/{MM}/{DD}/`).

2.  **Update Routes:**
    *   Modify the Cribl routes to send all incoming log data to the newly configured local filesystem destination.

3.  **Verify Data Retention:**
    *   After applying changes, monitor the configured directory to ensure logs are being written correctly.

## 3. Phase 2: Backend Refactoring

**Objective:** Remove the existing log ingestion logic and implement a new service to query the Cribl Search API.

### Step 2.1: Remove Obsolete Log Ingestion Code

1.  **Remove the Cribl Ingestion Endpoint:**
    *   In `backend/app/api/v1/logs.py`, delete the entire `ingest_cribl_logs` endpoint (`/api/v1/logs/cribl`).

2.  **Remove the Ingestion Service Logic:**
    *   In `backend/app/services/log_service.py`, delete the `create_log_from_cribl` method.

3.  **Remove Unused Schemas:**
    *   In `backend/app/schemas/logs.py`, review and remove any schemas that were exclusively used for the ingestion process, such as `CriblLogRecord`.

### Step 2.2: Implement the Cribl API Client

1.  **Add Configuration:**
    *   In `backend/app/core/config.py`, add settings for the Cribl API, including the base URL and any necessary authentication tokens.

2.  **Create a Cribl API Service:**
    *   Create a new service module (e.g., `backend/app/services/cribl_service.py`) to encapsulate all interactions with the Cribl Search API.
    *   Implement a method to execute search queries against the Cribl API, handling authentication, request formation, and response parsing.

### Step 2.3: Refactor the Log Retrieval Endpoint

1.  **Update the `get_raw_logs` Endpoint:**
    *   In `backend/app/api/v1/logs.py`, modify the `get_raw_logs` endpoint (`/api/v1/logs/`) to no longer use the `LogService` to query the database.
    *   Instead, it should use the new `CriblService` to proxy search requests to the Cribl API.
    *   The endpoint will need to translate its query parameters (e.g., `hostname`, `start_time`) into the appropriate Cribl search query syntax.

2.  **Update the `LogService`:**
    *   In `backend/app/services/log_service.py`, refactor the `get_logs` and `get_log_stats` methods.
    *   These methods will now call the `CriblService` to fetch data from Cribl instead of querying the PostgreSQL database.

## 4. Phase 3: Database Migration

**Objective:** Remove the `raw_logs` table and any related database components that are no longer needed.

### Step 4.1: Create a New Database Migration

1.  **Generate a Migration Script:**
    *   Use a database migration tool (like Alembic) to generate a new script.

2.  **Write the Down Migration:**
    *   The migration script should contain the necessary SQL to drop the `raw_logs` table. If `parsed_logs` is also being removed, include that as well.

    ```sql
    -- Example SQL to drop the table
    DROP TABLE raw_logs;
    ```

### Step 4.2: Remove the Database Model

1.  **Delete the Model Definition:**
    *   In `backend/app/models/logs.py`, remove the `RawLog` SQLAlchemy model.

### Step 4.3: Decommission PostgreSQL (Optional)

1.  **Analyze Dependencies:**
    *   Before removing the PostgreSQL service entirely, conduct a thorough analysis to ensure no other features rely on it.
    *   If other services (e.g., users, vulnerabilities) still require PostgreSQL, this step should be skipped.

2.  **Update `docker-compose.yml`:**
    *   If PostgreSQL is no longer needed, remove the `postgres` service definition from the `docker-compose.yml` file.

## 5. Phase 4: Testing and Validation

**Objective:** Ensure the refactored architecture functions correctly and meets all requirements.

1.  **Unit Tests:**
    *   Write unit tests for the new `CriblService` to verify correct API request formation and response handling.
    *   Update existing tests for the `LogService` and `logs.py` API to reflect the changes.

2.  **Integration Tests:**
    *   Create integration tests that simulate a request to the backend's `/api/v1/logs/` endpoint and verify that the correct query is sent to the Cribl API and that the response is processed correctly.

3.  **End-to-End Testing:**
    *   Perform manual end-to-end testing by sending logs from a source, verifying they are retained in Cribl, and then using the application's UI (which calls the backend) to search for and view the logs.