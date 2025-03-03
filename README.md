# traefik-rolexpert-plugin

*A Traefik middleware plugin for implementing role-based access control (RBAC) on incoming requests.* This plugin checks user roles (from JWT tokens or custom headers) and allows or denies access based on configured role requirements. It enables **fine-grained authorization** at the gateway level, so you can protect routes according to user roles without deploying a separate authorization service.

## Project Overview

**Traefik RoleXpert Plugin** is designed to extend Traefik's functionality by acting as a custom authorization middleware. Traefik plugins are dynamically loaded extensions that modify request behavior (similar to built-in middlewares). This plugin specifically focuses on **role-based authorization**. It intercepts HTTP requests at the Traefik level and verifies that the requester has the required role(s) before allowing the request to proceed. If the required roles are missing, the plugin responds with an **HTTP 403 Forbidden**, preventing unauthorized access.

This plugin is useful in microservices or containerized environments where Traefik is used as a reverse proxy. By using Traefik RoleXpert, you can enforce that certain routes (e.g., administrative or sensitive APIs) are only accessible to users with specific roles, all without modifying your application code.

## Features

- **Role-Based Access Control** – Define one or multiple roles that are allowed to access a route.
- **JWT Support** – Parse JSON Web Tokens (JWT) from the `Authorization` header (or a custom header) to extract user roles.
- **Customizable Claims & Headers** – Configure which JWT claim or header key contains the user's roles.
- **Flexible Role Matching** – Specify multiple allowed roles.
- **Configurable Token Verification** – Verify JWT signatures using a shared secret or public key.
- **Lightweight and Fast** – Runs inside Traefik with minimal overhead.
- **Optional Pass-Through of User Info** – Forward user identity information to backend services.

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
    image: traefik:v2.9
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

## Configuration Options


- **`clientId`** (*string*) – Client id for basic auth.
- **`clientSecret`** (*string*) – Client secret for basic auth.
- **`rolexpertBaseUrl`** (*string*) – The base url of your RoleXpert service.


## Development & Contribution

Contributions are welcome! Follow these steps:

1. Clone the repository.
2. Build the plugin using Go (`go build`).
3. Test locally using `plugins-local` mode in Traefik.
4. Submit pull requests with clear commit messages.

## License

This project is licensed under the **Apache License 2.0**.

## Related Links

- [Traefik Plugin Documentation](https://doc.traefik.io/traefik/plugins/)
- [Traefik Middleware Guide](https://doc.traefik.io/traefik/middlewares/)
- [JSON Web Token (JWT)](https://jwt.io/)

---

This README provides an overview of how to install, configure, and use the **traefik-rolexpert-plugin** to enforce role-based access control within Traefik.

