![SIEMBox Logo](./9c32256e1fe11d41ebf82f3edb471853d2c9b096bc202d170db206a886d6a1b1.png)

# SIEMBox

Realtime security monitoring and threat detection for your infrastructure. Built with Docker.

## Overview

SIEMBox is a containerized, microservice-based Security Information and Event Management (SIEM) system designed to provide real-time monitoring, threat detection using Sigma rules, and security analytics for your infrastructure.

## Features

*   **Log Collection:** Ingests logs via Syslog (TCP/UDP) and HTTP. Supports CEF, JSON, and plain text formats.
*   **Threat Detection:** Utilizes the Sigma standard for rule-based threat detection. Rules are automatically updated from the SigmaHQ repository.
*   **IP Intelligence:** Enriches logs with IP geolocation and threat information (requires optional API keys).
*   **VPS Security Auditing:** Performs scheduled security audits on configured remote servers via SSH.
*   **Web Interface:** Provides a dashboard for viewing logs, alerts, rule status, and system settings.
*   **API:** Offers a RESTful API for integration and interaction with system components.

## Getting Started

Follow these steps to get SIEMBox running locally using Docker.

**Prerequisites:**

*   Docker: [Install Docker](https://docs.docker.com/get-docker/)
*   Docker Compose: Usually included with Docker Desktop. If not, [Install Docker Compose](https://docs.docker.com/compose/install/).

**Steps:**

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/cladkins/siembox.git
    cd siembox
    ```

2.  **Configure Environment Variables:**
    Copy the example environment file and edit it with your specific settings.
    ```bash
    cp .env.example .env
    ```
    *   **Important:** You **must** set secure values for `DB_PASSWORD`, `JWT_SECRET`, and `ENCRYPTION_KEY` in the `.env` file.
    *   Review other variables in `.env` for optional API keys (like `IPAPI_KEY`, `CROWDSEC_API_KEY`) or custom port configurations.

3.  **Start the containers:**
    This command will build the images (if not already built) and start all the SIEMBox services in the background. The Sigma rules will be automatically cloned/updated by the detection service on its first start.
    ```bash
    docker-compose up -d
    ```

4.  **Access the Dashboard:**
    Once the containers are up and running (which might take a minute or two for the initial setup and rule download), you can access the web interface, typically at: `http://localhost:3000` (or the port configured via `FRONTEND_PORT` in your `.env` file).

## Documentation

For more detailed technical documentation, architecture diagrams, and API specifications, please refer to the [SIEMBox GitHub Wiki](https://github.com/cladkins/siembox/wiki) (link assumes wiki is enabled/used).

## License

This project is licensed under the MIT License.
