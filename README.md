# traefik-forwardauth-authentik-proxy

> [!CAUTION]
>
> I am still testing this project. Use at your own risk.

This is a proxy bridging traefik and authentik. Authentik only supports two
forwardauth modes: Single application and domain level.

This implement a 3rd option built on Single application, Delegated applications.

Assume the following setup:

- `authentik.example.com` - Authentik instance
- `access.example.com` - Instance of this project
- `*.example.com` - A bunch of internal services which require authorization

A user wants to authenticate to `admin.example.com`, which is restricted to the
`admin`-Authentik Usergroup. We also have `plausible.example.com` which every
user can access.

This is impossible with the Domain level mode. The single application mode would
require two individual providers, two proxy instances, two middleware
configurations etc.

This project exists to bridge that gap and avoid having to N-providers/proxy
instances/middleware configurations (where N is the number of services).

## Using

### Deploy the proxy

Deploy an instance of this proxy behind traefik, with forwardauth pointing to
it.

```yml
services:
  traefik-forwardauth-authentik-proxy:
    image: ghcr.io/le0developer/traefik-forwardauth-authentik-proxy:latest
    environment:
      ACCESS_BASE_URL: https://access.example.com
      AUTHENTIK_BASE_URL: https://authentik.example.com
      AUTHENTIK_CLIENT_ID: <forwardauth-client-id>
      AUTHENTIK_CLIENT_SECRET: <forwardauth-client-secret>
      # if you have a backchannel to authentik (e.g. internal network, same machine, etc)
      # AUTHENTIK_BACKCHANNEL_URL: http://authentik:9000
    networks:
      - proxy
    volumes:
      - /etc/ssl/certs/:/etc/ssl/certs/:ro
    labels:
      traefik.enable: true
      traefik.http.routers.traefik-forwardauth-authentik-proxy.rule:
        Host(`access.example.com`) ||
        PathPrefix(`/.well-known/traefik-forwardauth-authentik-proxy/`)
      traefik.http.routers.traefik-forwardauth-authentik-proxy.priority: 1000000
      traefik.http.services.traefik-forwardauth-authentik-proxy.loadbalancer.server.port: 8080
      traefik.http.middlewares.auth.forwardauth.address: http://traefik-forwardauth-authentik-proxy:8080/verify
      traefik.http.middlewares.auth.forwardauth.trustForwardHeader: true
      traefik.http.middlewares.auth.forwardauth.authResponseHeaders: X-authentik-username,X-authentik-groups,X-authentik-entitlements,X-authentik-email,X-authentik-name,X-authentik-uid

      traefik.http.middlewares.auth-owner.headers.customRequestHeaders.X-authentik-expected-groups: owner
    restart: unless-stopped
```

### Use the middleware in your services

Now, in your services, you can use the forwardauth middleware pointing to the
proxy, and set the expected groups per service.

```yml
services:
  admin-service:
    image: admin-service:latest
    networks:
      - proxy
    labels:
      traefik.enable: true
      traefik.http.routers.admin-service.rule: Host(`admin.example.com`)
      # The request header middleware for the expected groups must be used first
      traefik.http.routers.admin-service.middlewares: auth-owner,auth
    restart: unless-stopped

  plausible-service:
    image: plausible-service:latest
    networks:
      - proxy
    labels:
      traefik.enable: true
      traefik.http.routers.plausible-service.rule: Host(`plausible.example.com`)
      traefik.http.routers.plausible-service.middlewares: auth
    restart: unless-stopped
```
