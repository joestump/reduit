# ADR-0011: HTTP mode for reverse-proxy-fronted deployments

- **Status:** accepted
- **Date:** 2026-05-04
- **Deciders:** Joe Stump

## Context and Problem Statement

ADR-0009 established that reduit reads cert + key files from disk and
hot-reloads them, with all three listeners (HTTPS admin/MCP, IMAPS,
SMTPS) terminating TLS in-process. That fits the "single binary on a
public IP" deployment shape.

The other common self-hoster shape is a fleet behind a single TLS-
terminating reverse proxy (Caddy / Traefik / nginx) on shared port
443. In that shape the proxy handles ACME, port multiplexing, and TLS
termination for every service; backends speak plaintext HTTP over
loopback or the docker network. Forcing those operators to either:

- Re-issue a cert into reduit's volume so reduit can do its own TLS,
  or
- Configure HTTPS-to-HTTPS upstream in the proxy with
  `tls_insecure_skip_verify` (a pattern none of stumpcloud's 138
  services currently use)

is friction with no upside. The proxy already terminates TLS for the
public-facing URL; reduit doing it again just because the listener
was wired that way is busywork.

## Decision Drivers

- **Don't fight the proxy.** When the operator has Caddy / Traefik on
  443, give them a way to wire reduit in plaintext.
- **Don't compromise mail security.** IMAPS and SMTPS are TCP, not
  HTTP. They cannot be reverse-proxied in a way that survives the
  IMAP IDLE / SMTP STARTTLS / SASL handshakes. Mail listeners MUST
  continue to terminate TLS in-process per ADR-0009.
- **Fail loudly on misuse.** A misconfiguration where reduit's
  plaintext port is exposed directly to browsers silently breaks
  login (Secure-cookie-over-HTTP). The operator should see warnings
  at startup, not 4 hours of debugging at 2am.

## Considered Options

1. **Custom Caddy labels for HTTPS upstream.** Reduit keeps its
   in-process TLS; the proxy talks HTTPS-to-HTTPS with verify off.
   Works but ugly; new pattern in stumpcloud (138 services use
   plaintext upstreams).
2. **Per-listener TLS config.** HTTP listener can disable TLS while
   IMAPS/SMTPS keep theirs. More flexible but more config surface
   and more failure modes.
3. **Single `tls.disabled` flag governing the HTTP listener only.**
   When set, the admin/MCP listener serves plain HTTP. Mail
   listeners cannot be enabled (validation rejects); they require
   the certs ADR-0009 governs.

## Decision Outcome

**Chosen: option 3 — `tls.disabled: true` on `TLSConfig`.**

- When `tls.disabled: true`:
  - `cli/serve.go` skips `tlsloader.New` and the fsnotify watcher.
  - `server.New` is called with `GetCertificate: nil`, so
    `Server.Start` takes the `ListenAndServe` branch (plain HTTP)
    instead of `ListenAndServeTLS`.
  - `cert_path` and `key_path` become optional (validation skips
    them).
  - `imap_addr` and `smtp_addr` MUST be empty; setting them with
    `tls.disabled: true` is a configuration error caught at
    `Validate()` time. Mail listeners still need real certs.
- When `tls.disabled: false` (default): unchanged from ADR-0009.

The flag is opt-in. Default behavior is the universal-binary shape
ADR-0009 specified.

## Consequences

### Positive

- One-line config change for stumpcloud-style deployments. The
  generic `service` role's plaintext-upstream Caddy labels work
  unchanged.
- Reduit's listener code path branches cleanly: TLSConfig present
  → HTTPS, TLSConfig nil → HTTP. No `if tls.disabled` checks
  scattered through the codebase.
- The fsnotify watcher goroutine is never spawned in HTTP-only
  mode — saves resources, eliminates a class of "watcher exited"
  log noise on hosts that don't need it.

### Negative

- **Cookie-Secure footgun.** SCS session cookies and the OIDC
  `__Host-Reduit-Bind` cookie are written with `Secure: true`.
  Browsers honor that only when the page is served over HTTPS.
  In HTTP-only mode, the upstream proxy MUST present HTTPS to the
  browser — if the operator exposes reduit's plaintext port directly
  (LAN-side debug, misconfigured proxy), login silently breaks
  with no useful error. We log a loud `WARN` at startup; we do
  NOT auto-flip `InsecureCookies` because that would require
  trusting the operator's claim that the proxy is in front (we
  can't prove it).
- **`RemoteAddr` becomes the proxy IP.** Audit logs (`auth/callback
  rejected` etc.) will show loopback / docker-network addresses
  for every request. Trusted-proxy `X-Forwarded-For` parsing is
  follow-up work tracked separately.
- **Mail listeners cannot run in HTTP-only mode.** The
  `tls.disabled: true` deploy is admin/MCP-only. Operators wanting
  IMAPS/SMTPS must either run the standard ADR-0009 deploy (with
  in-process cert) or wait for Phase 2 (per-listener TLS configured
  separately, tracked as a future ADR).

### Neutral

- The default config (`Defaults()`) still sets `imap_addr: ":993"`
  and `smtp_addr: ":465"`. Operators using `tls.disabled: true`
  must override those to `""`. The validation error message points
  at exactly this case.

## Governing implementations

- `internal/config/config.go` — `TLSConfig.Disabled` field;
  `Validate()` rejects `disabled: true && (imap_addr || smtp_addr)`.
- `internal/server/server.go` — `Server.Start` branches on
  `s.srv.TLSConfig != nil`.
- `internal/cli/serve.go` — skips `tlsloader.New` and the watcher
  goroutine when `cfg.TLS.Disabled`.
- `internal/server/server_test.go` — `TestServer_StartPlaintext
  WhenNoCertificate` asserts the new branch actually accepts plain
  HTTP and refuses TLS handshakes.

## Related

- ADR-0009 (cert files + hot-reload) — still governs mail listeners
  and the default deploy shape.
- SPEC-0007 (mcp-tool-surface) — amended in PR #84 to read "TLS-
  terminated listener" instead of "HTTPS listener" so the MCP
  endpoint can ride the HTTP-only mode behind a proxy.
- Stumpcloud Ansible playbook (`playbooks/services/reduit.yaml` in
  stumpcloud/ansible#25) — the first downstream consumer of this
  mode.
