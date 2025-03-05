# traefik-rolexpert-plugin

*A Traefik middleware plugin for implementing role-based access control (RBAC) on incoming requests.* This plugin checks
user roles (from JWT tokens or custom headers) and allows or denies access based on configured role requirements. It
enables **fine-grained authorization** at the gateway level, so you can protect routes according to user roles without
deploying a separate authorization service.

## Project Overview

**Traefik RoleXpert Plugin** is designed to extend Traefik's functionality by acting as a custom authorization
middleware. Traefik plugins are dynamically loaded extensions that modify request behavior (similar to built-in
middlewares). This plugin specifically focuses on **role-based authorization**. It intercepts HTTP requests at the
Traefik level and verifies that the requester has the required role(s) before allowing the request to proceed. If the
required roles are missing, the plugin responds with an **HTTP 403 Forbidden**, preventing unauthorized access.

This plugin is useful in microservices or containerized environments where Traefik is used as a reverse proxy. By using
Traefik RoleXpert, you can enforce that certain routes (e.g., administrative or sensitive APIs) are only accessible to
users with specific roles, all without modifying your application code.

## Features

- **Role-Based Access Control** – Define one or multiple roles that are allowed to access a route.
- **JWT Support** – Parse JSON Web Tokens (JWT) from the `Authorization` header (or a custom header) to extract user
  roles.
- **Customizable Claims & Headers** – Configure which JWT claim or header key contains the user's roles.
- **Flexible Role Matching** – Specify multiple allowed roles.
- **Configurable Token Verification** – Verify JWT signatures using a shared secret or public key.
- **Lightweight and Fast** – Runs inside Traefik with minimal overhead.
- **Optional Pass-Through of User Info** – Forward user identity information to backend services.
- **Dynamic Whitelist Support** – Skip authentication for whitelisted routes.
- **Service-Specific Whitelist via Traefik Labels** – Each service can define its own whitelist dynamically.
- **Configurable API & Caching** – Reduce API calls by caching whitelisted routes.

## Installation & Usage

### Step 1: Enable the Plugin in Static Configuration

Modify `traefik.yml`:

```yaml
experimental:
  plugins:
    rolexpert:
      moduleName: "github.com/rahkar-team/traefik-rolexpert-plugin"
      version: "v1.0.0"
```

Or use CLI flags:

```bash
--experimental.plugins.rolexpert.moduleName=github.com/rahkar-team/traefik-rolexpert-plugin \
--experimental.plugins.rolexpert.version=v1.0.0
```

### Step 2: Configure Middleware in Dynamic Configuration

Modify `dynamic_conf.yml`:

```yaml
http:
  middlewares:
    roles-check:
      plugin:
        rolexpert:
          clientId: "ClientIdFake"
          clientSecret: "ClientSecretFake"
          rolexpertBaseUrl: "http://rolexpert:8080"
          cacheTTL: 300  # Cache whitelist for 5 minutes
          whitelist: "GET:/test,/test1"

  routers:
    secure-api:
      rule: "PathPrefix(`/admin`)"
      service: api-service
      middlewares:
        - "roles-check"
```

### Step 3: Attach Middleware to Routes

For Docker Compose, use labels:

```yaml
services:
  traefik:
    image: traefik:v3
    command:
      - --experimental.plugins.rolexpert.moduleName=github.com/rahkar-team/traefik-rolexpert-plugin
      - --experimental.plugins.rolexpert.version=v1.0.0

  secure_app:
    image: "your-app-image:latest"
    labels:
      - "traefik.http.routers.secure-app.rule=Host(`example.com`) && PathPrefix(`/secure`)"
      - "traefik.http.routers.secure-app.middlewares=roles-check@file"
      - "traefik.http.middlewares.roles-check.plugin.rolexpert.requiredRoles=admin,editor"
      - "traefik.http.middlewares.roles-check.plugin.rolexpert.rolesClaim=roles"
      - "traefik.http.middlewares.roles-check.plugin.rolexpert.secretKey=myJWTsecret"
```

### Step 4: Allow Services to Define Their Own Whitelist

Each **service can define its own whitelist dynamically** using Traefik labels:

```yaml
services:
  my-service:
    image: my-app
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.my-service.rule=Host(`example.com`)"
      - "traefik.http.routers.my-service.middlewares=rolexpert-auth"
      - "traefik.http.middlewares.{my-service}-rolexpert.plugin.rolexpert.clientId={clientId}"
      - "traefik.http.middlewares.{my-service}-rolexpert.plugin.rolexpert.clientSecret={clientSecret}"
      - "traefik.http.middlewares.{my-service}-rolexpert.plugin.rolexpert.rolexpertBaseUrl=http://rolexpert:8080"
      - "traefik.http.middlewares.{my-service}-rolexpert.plugin.rolexpert.whitelist=/test,POST:/create,/users/**"
```

With this setup:

- **Plugin-defined whitelist (`whitelist` in `traefik.yml`)** → Applies globally.
- **Service-defined whitelist (`whitelist` label in services)** → Applies only to that service.

### Attention

If you are using Traefik with **Swarm mode**, add these labels to your Traefik compose file.

#### **Traefik:**

```yaml
  labels:
    - "traefik.http.middlewares.rolexpert-auth.plugin.rolexpert.clientId=treafik"
    - "traefik.http.middlewares.rolexpert-auth.plugin.rolexpert.clientSecret=Secret"
    - "traefik.http.middlewares.rolexpert-auth.plugin.rolexpert.rolexpertBaseUrl=http://rolexpert-url"
    - "traefik.http.middlewares.rolexpert-auth.plugin.rolexpert.cacheTTL=300"
```

#### **Service:**

```yaml
  labels:
    - "traefik.http.routers.{stack-namespace}.middlewares=rolexpert-auth"
    - "traefik.http.middlewares.rolexpert-auth.plugin.rolexpert.whitelist=/health,/metrics"
```

## Configuration Options

| Key                | Type   | Description                                                                           |
|--------------------|--------|---------------------------------------------------------------------------------------|
| `clientId`         | string | Client ID for authentication.                                                         |
| `clientSecret`     | string | Client secret for authentication.                                                     |
| `rolexpertBaseUrl` | string | The base URL of your RoleXpert service.                                               |
| `cacheTTL`         | int    | **(New)** How long (in seconds) to cache the whitelist. Default is `300` (5 minutes). |
| `whitelist`        | list   | **(New)** List of globally whitelisted paths and methods.                             |

## Development & Contribution

Contributions are welcome! Follow these steps:

1. Clone the repository.
2. Build the plugin using Go (`go build`).
3. Test locally using `plugins-local` mode in Traefik.
4. Submit pull requests with clear commit messages.

## License

This project is licensed under the **Apache License 2.0**.
