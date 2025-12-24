# Whois Lookup Service

This project provides a simple web service for performing WHOIS lookups. Users can enter a domain name or IP address, and the service will return the corresponding WHOIS information.

## Redis Database

This application heavily utilizes Redis for several key functionalities:

-   **Caching:** To store results of WHOIS, DNS, and Certificate Transparency (CT) lookups, improving performance and reducing external API calls.
-   **Rate Limiting:** To enforce API rate limits, preventing abuse and ensuring fair usage.
-   **DNS History:** To maintain a history of DNS changes for monitored items.
-   **Monitoring:** To store a list of items for scheduled monitoring and to manage the monitoring jobs.

The application connects to Redis using environment variables:
-   `REDIS_HOST`: The hostname or IP address of the Redis server (default: `redis`).
-   `REDIS_PORT`: The port of the Redis server (default: `6379`).
-   `REDIS_DB`: The Redis database index for general application data (default: `0`).
-   `REDIS_LIM_DB`: The Redis database index specifically for rate limiting (default: `1`).

## Application Configuration

The application can be configured using the following environment variables:

-   `SECRET_KEY`: A secret key used for session management and security. **It is crucial to change this in production.** (Default: `change-me-in-production`)
-   `CONFIG_USER`: Username for accessing the `/config` page (Default: None).
-   `CONFIG_PASS`: Password for accessing the `/config` page (Default: None).

If `CONFIG_USER` and `CONFIG_PASS` are set, a login will be required to access the `/config` endpoint for monitoring and other administrative tasks.

## How to Run

The application, along with its Redis dependency, can be run using Docker.

### Recommended Method: Docker Compose

The easiest way to get the application and its Redis database running is by using Docker Compose. Ensure you have Docker Compose installed.

1.  **Clone the repository** (if you haven't already).
2.  Navigate to the root directory of the project where `docker-compose.yml` is located.
3.  Run the following command to build (if necessary) and start both the web service and the Redis database:
    ```bash
    docker-compose up -d
    ```
    The `-d` flag runs the services in the background.

4.  Once the services are running, you can access the application in your web browser at `http://localhost:14400` (as configured in `docker-compose.yml`).

To stop the services, run:
```bash
docker-compose down
```

### Manual Docker Method (Requires separate Redis instance)

If you prefer to run the web service manually without Docker Compose, you must ensure a Redis instance is running and accessible to the web service.

#### 1. Start Redis

First, start a Redis container. Make sure it's on a network that your web service can access. For simplicity, you can run it on the default bridge network:

```bash
docker run -d --name whois-redis -p 6379:6379 redis:latest
```

This command starts a Redis container named `whois-redis` and exposes port `6379`. Note that `REDIS_HOST` would need to be set to the IP address of this Redis container or `host.docker.internal` (for Docker Desktop) if not using a custom network.

#### 2. Pull the Docker Image (for the web service)

You can pull the latest Docker image from the provided registry:

```bash
docker pull registry.reitetschlaeger.com/whois:latest
```

#### 3. Run the Docker Container (web service)

After pulling the image, you can run the container, linking it to the Redis instance (if using the same network) or providing the Redis host via environment variables.

Example (assuming Redis is accessible via hostname `whois-redis` on a shared network, or `host.docker.internal` if on Docker Desktop and using host's Redis):

```bash
docker run -p 5000:5000 --env REDIS_HOST=whois-redis registry.reitetschlaeger.com/whois:latest
```
Or if running Redis on the host machine directly or through `host.docker.internal` for Docker Desktop:
```bash
docker run -p 5000:5000 --env REDIS_HOST=host.docker.internal registry.reitetschlaeger.com/whois:latest
```

Once the container is running, you can access the application in your web browser at `http://IP:5000`.

### Build the Docker Image Locally (web service)

If you want to build the web service Docker image from source, navigate to the project's root directory (where the `Dockerfile` is located) and run the following command:

```bash
docker build -t whois-app .
```

This command builds an image named `whois-app` from the `Dockerfile` in the current directory.

### Run the Locally Built Docker Container (web service)

After building the image, you can run it, ensuring it can connect to your Redis instance (as described in "Manual Docker Method - Run the Docker Container"):

```bash
docker run -p 5000:5000 --env REDIS_HOST=whois-redis whois-app
```
Then, access the application in your web browser at `http://IP:5000`.
