# SIEMBox - API Reference

This document provides a comprehensive reference for the SIEMBox REST API, detailing all available endpoints, methods, and data models.

## 1. Authentication

All API endpoints, unless otherwise noted, require JWT-based Bearer token authentication.

### `POST /api/v1/auth/login`

Authenticates a user and returns a JWT access token.

-   **Request Body**: `LoginRequest`
-   **Response**: `LoginResponse`

### `POST /api/v1/auth/token`

An alternative OAuth2-compatible endpoint for token acquisition.

-   **Request Body**: `OAuth2PasswordRequestForm`
-   **Response**: `Token`

### `GET /api/v1/auth/me`

Retrieves the profile of the currently authenticated user.

-   **Response**: `User`

## 2. Logs API

### `POST /api/v1/logs/cribl` ✅ **ACTIVE**

**Primary log ingestion endpoint** for receiving processed logs from Cribl Stream's HTTP destination.

-   **Purpose**: Receives structured log data that has been processed, enriched, and formatted by Cribl Stream
-   **Request Body**: A JSON array where each object represents a single processed log event
-   **Response**: `{"message": "Received {count} logs", "count": number}`
-   **Authentication**: None required (internal Cribl-to-Backend communication)

### `GET /api/v1/logs/parsed`

Retrieves a paginated list of parsed logs with filtering options.

-   **Query Parameters**: `skip`, `limit`, `hostname`, `app_name`, `start_time`, `end_time`
-   **Response**: `PaginatedResponse[ParsedLogResponse]`

### `GET /api/v1/logs/stats`

Returns summary statistics about the logs in the system.

-   **Response**: A JSON object with log statistics.

## 2.1. Deprecated Logs API Endpoints

### `POST /api/v1/logs/ingest` ❌ **DEPRECATED**

**Status**: HTTP 410 Gone

-   **Migration Path**: Configure log sources to send data to Cribl Stream instead
-   **Cribl Input**: Configure syslog input on port 10514 or HTTP input on port 8088
-   **Response**: `{"detail": "This endpoint has been deprecated. Please configure your log sources to send data directly to Cribl Stream..."}`

### `POST /api/v1/logs/ingest/fluent-bit` ❌ **DEPRECATED**

**Status**: HTTP 410 Gone

-   **Migration Path**: Configure Fluent Bit to send logs to Cribl Stream
-   **Response**: `{"detail": "This endpoint has been deprecated. Please configure Fluent Bit to send logs to Cribl Stream..."}`

### `GET /api/v1/logs` ❌ **DEPRECATED**

**Status**: Raw logs are no longer stored in the database (Pattern B architecture)

-   **Alternative**: Use Cribl Stream's filesystem destination for long-term log storage
-   **Location**: `/opt/cribl/data/SIEMBOX` (persistent volume)

## 3. Alerts API

### `GET /api/v1/alerts`

Retrieves a list of alerts with filtering options.

-   **Query Parameters**: `status`, `severity`, `category`, `hours`, `limit`, `offset`
-   **Response**: `List[AlertResponse]`

### `GET /api/v1/alerts/{alert_id}`

Retrieves a specific alert by its ID.

-   **Response**: `AlertResponse`

### `PUT /api/v1/alerts/{alert_id}`

Updates the status or other properties of an alert.

-   **Request Body**: `AlertUpdate`
-   **Response**: `AlertResponse`

## 4. Detection API

### `POST /api/v1/detection/rules`

Creates a new detection rule.

-   **Request Body**: `DetectionRuleCreate`
-   **Response**: `DetectionRuleResponse`

### `GET /api/v1/detection/rules`

Retrieves a list of detection rules with filtering options.

-   **Query Parameters**: `enabled_only`, `category`, `severity`
-   **Response**: `List[DetectionRuleResponse]`

### `PUT /api/v1/detection/rules/{rule_id}`

Updates an existing detection rule.

-   **Request Body**: `DetectionRuleUpdate`
-   **Response**: `DetectionRuleResponse`

## 5. Notifications API

### `GET /api/v1/notifications/channels`

Retrieves a list of all configured notification channels.

-   **Query Parameters**: `enabled_only`, `channel_type`
-   **Response**: `List[NotificationChannelResponse]`

### `POST /api/v1/notifications/channels`

Creates a new notification channel.

-   **Request Body**: `NotificationChannelCreate`
-   **Response**: `NotificationChannelResponse`

### `PUT /api/v1/notifications/channels/{channel_id}`

Updates an existing notification channel.

-   **Request Body**: `NotificationChannelUpdate`
-   **Response**: `NotificationChannelResponse`

## 6. Parsing API ❌ **DEPRECATED**

**Status**: All parsing endpoints return HTTP 410 Gone

**Migration Path**: Parsing is now handled by Cribl Stream

### `POST /api/v1/parsing/parse` ❌ **DEPRECATED**

**Status**: HTTP 410 Gone

-   **Migration Path**: Configure parsing pipelines in Cribl Stream UI at `http://localhost:9000`
-   **Response**: `{"detail": "Parsing is now handled by Cribl Stream. Please configure parsing pipelines in the Cribl UI..."}`

### `GET /api/v1/parsing/parsers` ❌ **DEPRECATED**

**Status**: HTTP 410 Gone

-   **Migration Path**: View and configure parsers in Cribl Stream UI
-   **Response**: `{"detail": "Parser configuration is now managed through Cribl Stream..."}`

## 7. Cribl Integration

### Cribl Stream Configuration

-   **Web UI**: `http://localhost:9000`
-   **API Authentication**: JWT token-based (configured in backend)
-   **Dual Destinations**:
    - **HTTP Output**: Real-time processing via `/api/v1/logs/cribl`
    - **Filesystem Output**: Long-term storage to `/opt/cribl/data/SIEMBOX`

### Cribl Stream Inputs

-   **Syslog**: Port 10514 (UDP/TCP)
-   **HTTP**: Port 8088
-   **Docker Logs**: Automatic collection from local containers

### Backend-to-Cribl Communication

The backend communicates with Cribl Stream via its REST API for:
-   Health checks and status monitoring
-   Configuration management
-   Output destination status