---
title: Behind a Reverse Proxy
sidebar_label: Behind a Reverse Proxy
sidebar_position: 3
---

# Behind a Reverse Proxy

Many deployments already terminate TLS at a fronting proxy (Caddy, Traefik,
nginx). Reduit supports this with `tls.disabled` mode: the admin/MCP listener
serves **plaintext HTTP**, and the proxy handles inbound TLS.

This guide is governed by [ADR-0011](/decisions/ADR-0011-http-mode-for-reverse-proxy-fronting).

## When to use it

Use `tls.disabled` when **all** of the following hold:

- A reverse proxy on the same host or a trusted network terminates TLS.
- The proxy and Reduit talk over loopback or a private network.
- You only need to proxy the **HTTP** surface (admin UI + MCP).

Do **not** expose Reduit's plaintext port directly to clients.

## Configuration

```yaml
tls:
  disabled: true

server:
  http_addr: ":8080"   # plaintext HTTP for the proxy to hit
  imap_addr: ""        # MUST be empty — see below
  smtp_addr: ""        # MUST be empty — see below
```

### IMAPS and SMTPS cannot be reverse-proxied

IMAPS and SMTPS are raw TLS over TCP, not HTTP — an HTTP reverse proxy can't
terminate them. When `tls.disabled` is true, **`server.imap_addr` and
`server.smtp_addr` MUST be empty.** If you need IMAP/SMTP access in a
proxied deployment, give Reduit real certs for those listeners (don't disable
TLS), or place a TCP/SNI proxy (e.g. Caddy's `layer4`, HAProxy) in front of them
instead of an HTTP proxy.

## The public URL must still be HTTPS

:::danger Secure cookies break over plaintext
Reduit writes its session cookie and the `__Host-Reduit-Bind` cookie with
`Secure=true`. Browsers **silently drop** `Secure` cookies on pages served over
plain HTTP — login then fails with no useful error.

The browser-facing URL **must be HTTPS**. `tls.disabled` is only safe when a
proxy re-adds TLS in front. If you point a browser straight at the plaintext
port, login will not work.
:::

## Example: Caddy

```caddyfile
reduit.family.tld {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy provisions and renews the certificate, terminates TLS, and forwards plain
HTTP to Reduit on loopback. The browser always sees `https://`, so `Secure`
cookies survive.

## Trusted proxies and client IPs

Behind a proxy, Reduit sees the proxy's address as the connection source. So
that audit logs and any IP-based logic record the real client, ensure your
proxy sets `X-Forwarded-For` and that Reduit is configured to trust it. Keep the
proxy on a trusted network — a spoofable `X-Forwarded-For` from an untrusted
source must never be honored.
