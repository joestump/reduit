package mcpserver_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/auth"
	"github.com/joestump/reduit/internal/auth/mcptoken"
	authoidc "github.com/joestump/reduit/internal/auth/oidc"
	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/mcpserver"
	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/storetest"
	"github.com/joestump/reduit/internal/users"
)

// TestMCPAuth_MissingBearer covers SPEC-0006 REQ "Bearer Authentication
// Required" Scenario "Unauthenticated MCP request is rejected": a POST
// to /mcp with no Authorization header MUST yield 401 with a generic
// body and a WWW-Authenticate header that does not include a realm
// parameter.
func TestMCPAuth_MissingBearer(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	defer f.close()

	resp := f.post(t, "", nil, `{}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	wa := resp.Header.Get("WWW-Authenticate")
	if wa == "" {
		t.Errorf("WWW-Authenticate header missing on 401")
	}
	// SPEC-0006 forbids a realm parameter that leaks deployment-
	// internal identifiers. The product name "reduit" is not a
	// deployment-internal identifier (it's static across every
	// install), so we permit `Bearer realm="reduit"` but reject
	// any realm that contains a host-shaped value or other
	// deployment-specific marker. Pin a tight allowlist so a
	// future change that broadens the realm to e.g. the OIDC
	// issuer URL trips this assertion immediately.
	lower := strings.ToLower(wa)
	if strings.Contains(lower, "realm") {
		// The single allowlisted form is `Bearer realm="reduit"`
		// (case-insensitive on the scheme + key, exact on the
		// value). Anything else fails the leak check.
		if !strings.Contains(lower, `realm="reduit"`) {
			t.Errorf("WWW-Authenticate %q realm leak: only realm=\"reduit\" is permitted", wa)
		}
	}
	if f.lastSeenAccountID() != "" {
		t.Errorf("downstream handler ran without auth (saw account_id=%q)", f.lastSeenAccountID())
	}
}

// TestMCPAuth_MalformedBearer covers SPEC-0006: a non-JWT, non-MCP-token
// bearer MUST yield 401.
func TestMCPAuth_MalformedBearer(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	defer f.close()

	resp := f.post(t, "Bearer not-a-real-token", nil, `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// TestMCPAuth_MCPToken_Valid covers the per-account MCP token bearer
// path. The token is bound to one account at issuance, so no
// X-Reduit-Account selector is required and the request reaches the
// downstream handler with the correct account on context.
//
// Governing: SPEC-0006 REQ "Bearer Authentication Required" Scenario
// "Per-account MCP token authenticates as the bound account".
func TestMCPAuth_MCPToken_Valid(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	defer f.close()
	const acctID = "acct-mcp-1"
	storetest.SeedUserAccountActive(t, f.st, acctID)

	tok, err := f.tokens.Issue(context.Background(), mcptoken.IssueParams{AccountID: acctID})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	resp := f.post(t, "Bearer "+tok.Plaintext, nil, `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if got := f.lastSeenAccountID(); got != acctID {
		t.Errorf("downstream saw account_id=%q, want %q", got, acctID)
	}
}

// TestMCPAuth_MCPToken_Revoked covers SPEC-0006 REQ "Token Issuance
// and Revocation": after revocation, the same token MUST yield 401
// within 1s.
func TestMCPAuth_MCPToken_Revoked(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	defer f.close()
	const acctID = "acct-mcp-revoke"
	storetest.SeedUserAccountActive(t, f.st, acctID)

	ctx := context.Background()
	tok, err := f.tokens.Issue(ctx, mcptoken.IssueParams{AccountID: acctID})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	resp := f.post(t, "Bearer "+tok.Plaintext, nil, `{}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-revoke status = %d, want 200", resp.StatusCode)
	}

	revStart := time.Now()
	if err := f.tokens.Revoke(ctx, tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	resp = f.post(t, "Bearer "+tok.Plaintext, nil, `{}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-revoke status = %d, want 401", resp.StatusCode)
	}
	if elapsed := time.Since(revStart); elapsed > time.Second {
		t.Fatalf("revoke -> 401 took %v, want <1s", elapsed)
	}
}

// TestMCPAuth_MCPToken_AccountIsolation covers SPEC-0006 REQ "Account
// Scope on All Operations" at the auth-binding layer: presenting
// account-A's token MUST result in account-A on the downstream
// context, NOT account-B's, even if account-B exists. This is the
// foundational invariant that #28-#30's per-tool SQL-scope discipline
// rests on.
func TestMCPAuth_MCPToken_AccountIsolation(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	defer f.close()

	const acctA = "acct-iso-A"
	const acctB = "acct-iso-B"
	storetest.SeedUserAccountActive(t, f.st, acctA)
	storetest.SeedUserAccountActive(t, f.st, acctB)

	ctx := context.Background()
	tokA, err := f.tokens.Issue(ctx, mcptoken.IssueParams{AccountID: acctA})
	if err != nil {
		t.Fatalf("Issue A: %v", err)
	}
	tokB, err := f.tokens.Issue(ctx, mcptoken.IssueParams{AccountID: acctB})
	if err != nil {
		t.Fatalf("Issue B: %v", err)
	}

	// Token A authenticates as account A, regardless of B's existence.
	resp := f.post(t, "Bearer "+tokA.Plaintext, nil, `{}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token A status = %d", resp.StatusCode)
	}
	if got := f.lastSeenAccountID(); got != acctA {
		t.Errorf("token A bound to %q, want %q", got, acctA)
	}

	// Token B authenticates as account B.
	resp = f.post(t, "Bearer "+tokB.Plaintext, nil, `{}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token B status = %d", resp.StatusCode)
	}
	if got := f.lastSeenAccountID(); got != acctB {
		t.Errorf("token B bound to %q, want %q", got, acctB)
	}

	// And no string-manipulation form of token A binds to B's
	// account: even token A's plaintext with B's account-id appended
	// in an X-Reduit-Account header is harmlessly ignored on the
	// MCP-token branch (the header only applies to OIDC bearers per
	// SPEC-0006 design.md "Header consulted only when path has no
	// selector" -- and even then, only for OIDC). For an MCP token
	// the binding comes from the token row, not the header.
	resp = f.post(t, "Bearer "+tokA.Plaintext, http.Header{"X-Reduit-Account": {acctB}}, `{}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := f.lastSeenAccountID(); got != acctA {
		t.Errorf("token A + header B bound to %q, want %q (MCP token MUST ignore selector)", got, acctA)
	}
}

// TestMCPAuth_OIDC_Valid_WithSelectorHeader covers SPEC-0006 Scenario
// "OIDC bearer token requires account selector": a valid JWT plus
// X-Reduit-Account header for an account owned by the JWT subject
// MUST authenticate and bind to that account.
func TestMCPAuth_OIDC_Valid_WithSelectorHeader(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	defer f.close()

	const sub = "oidc-joe"
	userID := storetest.SeedUser(t, f.st, sub)
	const acctID = "acct-oidc-1"
	if _, err := f.st.DB.ExecContext(context.Background(),
		`INSERT INTO accounts (id, user_id, state, key_envelope) VALUES (?, ?, 'active', X'00')`,
		acctID, userID); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	jwt := f.signJWT(t, sub)
	resp := f.post(t, "Bearer "+jwt, http.Header{"X-Reduit-Account": {acctID}}, `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if got := f.lastSeenAccountID(); got != acctID {
		t.Errorf("downstream saw account_id=%q, want %q", got, acctID)
	}
}

// TestMCPAuth_OIDC_NoSelector covers SPEC-0006 Scenario "No selector
// at all": valid OIDC JWT without an X-Reduit-Account header MUST
// yield 400 selector_required (the ONE distinct response code that
// distinguishes missing-selector from selector-failures, by design).
func TestMCPAuth_OIDC_NoSelector(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	defer f.close()
	const sub = "oidc-no-selector"
	storetest.SeedUser(t, f.st, sub)

	jwt := f.signJWT(t, sub)
	resp := f.post(t, "Bearer "+jwt, nil, `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if got := strings.TrimSpace(string(body)); got != `{"error":"selector_required"}` {
		t.Errorf("body = %q, want selector_required", got)
	}
}

// TestMCPAuth_OIDC_Indistinguishable_Forbidden covers SPEC-0006 REQ
// "Authorization-Failure Indistinguishability": case A (non-existent
// UUID), case B (existing but not owned), and case C (no users row
// for JWT subject) MUST produce byte-identical responses.
func TestMCPAuth_OIDC_Indistinguishable_Forbidden(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	defer f.close()

	storetest.SeedUser(t, f.st, "oidc-attacker")
	otherUserID := storetest.SeedUser(t, f.st, "oidc-victim")
	const otherAccountID = "acct-victim"
	if _, err := f.st.DB.ExecContext(context.Background(),
		`INSERT INTO accounts (id, user_id, state, key_envelope) VALUES (?, ?, 'active', X'00')`,
		otherAccountID, otherUserID); err != nil {
		t.Fatalf("seed victim account: %v", err)
	}

	caseA := func() (*http.Response, []byte) {
		jwt := f.signJWT(t, "oidc-attacker")
		resp := f.post(t, "Bearer "+jwt, http.Header{"X-Reduit-Account": {"acct-does-not-exist"}}, `{}`)
		body, _ := io.ReadAll(resp.Body)
		return resp, body
	}
	caseB := func() (*http.Response, []byte) {
		jwt := f.signJWT(t, "oidc-attacker")
		resp := f.post(t, "Bearer "+jwt, http.Header{"X-Reduit-Account": {otherAccountID}}, `{}`)
		body, _ := io.ReadAll(resp.Body)
		return resp, body
	}
	caseC := func() (*http.Response, []byte) {
		// No users row exists for this JWT subject.
		jwt := f.signJWT(t, "oidc-no-users-row")
		resp := f.post(t, "Bearer "+jwt, http.Header{"X-Reduit-Account": {otherAccountID}}, `{}`)
		body, _ := io.ReadAll(resp.Body)
		return resp, body
	}

	respA, bodyA := caseA()
	respA.Body.Close()
	respB, bodyB := caseB()
	respB.Body.Close()
	respC, bodyC := caseC()
	respC.Body.Close()

	for name, resp := range map[string]*http.Response{"A": respA, "B": respB, "C": respC} {
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("case %s: status = %d, want 403", name, resp.StatusCode)
		}
	}
	if string(bodyA) != string(bodyB) || string(bodyB) != string(bodyC) {
		t.Errorf("indistinguishability violated:\nA=%q\nB=%q\nC=%q", bodyA, bodyB, bodyC)
	}
	if got := strings.TrimSpace(string(bodyA)); got != `{"error":"forbidden"}` {
		t.Errorf("body = %q, want forbidden", got)
	}
	hA, hB, hC := stripVolatileHeaders(respA.Header), stripVolatileHeaders(respB.Header), stripVolatileHeaders(respC.Header)
	if !headersEqual(hA, hB) || !headersEqual(hB, hC) {
		t.Errorf("indistinguishability violated on headers:\nA=%v\nB=%v\nC=%v", hA, hB, hC)
	}
}

// TestMCPAuth_OIDC_Expired covers the SPEC-0006 expiry path: an
// expired OIDC bearer MUST be rejected with 401.
func TestMCPAuth_OIDC_Expired(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	defer f.close()

	jwt := f.signJWTWithExpiry(t, "oidc-expired", -time.Hour)
	resp := f.post(t, "Bearer "+jwt, http.Header{"X-Reduit-Account": {"any"}}, `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// --- fixture & helpers ---

// authFixture wires up the full auth chain with a sniffer terminal so
// tests can assert "what account_id did the post-auth context see".
// The sniffer terminal returns 200 OK with no body, which is valid as
// a downstream stand-in because these tests assert on auth behaviour,
// not on the SDK's wire shape (auth tests don't drive JSON-RPC).
type authFixture struct {
	st       *store.Store
	tokens   *mcptoken.Repository
	srv      *httptest.Server
	priv     crypto.PrivateKey
	keyID    string
	alg      string
	issuer   string
	observed atomicAccountID
}

// atomicAccountID stashes the most-recent account ID seen by the
// sniffer terminal. We use a small atomic helper so concurrent tests
// (t.Parallel) on a shared fixture don't race on a plain string.
type atomicAccountID struct{ v atomic.Value }

func (a *atomicAccountID) set(s string) { a.v.Store(s) }
func (a *atomicAccountID) get() string {
	if v, ok := a.v.Load().(string); ok {
		return v
	}
	return ""
}

func newAuthFixture(t *testing.T) *authFixture {
	t.Helper()
	st := openTempStore(t)

	priv, issuer, keyID, alg := newOIDCTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := authoidc.New(ctx, authoidc.Config{
		IssuerURL:   issuer,
		ClientID:    "reduit",
		RedirectURL: "https://reduit.example.com/auth/callback",
		Scopes:      []string{"openid"},
	})
	if err != nil {
		t.Fatalf("authoidc.New: %v", err)
	}
	tokens := mcptoken.NewRepository(st.DB)

	masterKey, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	accountSvc := account.New(st, masterKey)
	usersSvc := users.New(st)

	validator := auth.NewBearerValidator(c, tokens)

	f := &authFixture{
		st:     st,
		tokens: tokens,
		priv:   priv,
		keyID:  keyID,
		alg:    alg,
		issuer: issuer,
	}

	// Sniffer terminal: records the account_id from context and
	// returns 200 OK. Auth tests assert auth behaviour; the SDK is
	// out-of-scope for them and lives in its own integration-style
	// tests instead.
	terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if acct := mcpserver.AccountFromContext(r.Context()); acct != nil {
			f.observed.set(acct.ID)
		}
		w.WriteHeader(http.StatusOK)
	})

	mcpSrv := mcpserver.NewWithTerminal(mcpserver.Deps{
		Validator: validator,
		Accounts:  accountSvc,
		Users:     usersSvc,
		Limiter:   mcpserver.NoLimiter(),
	}, terminal)

	f.srv = httptest.NewServer(mcpSrv.Handler())
	t.Cleanup(f.srv.Close)
	return f
}

func (f *authFixture) close() { f.st.Close() }

func (f *authFixture) post(t *testing.T, authz string, extraHeaders http.Header, body string) *http.Response {
	t.Helper()
	// Reset the sniffer between requests so a stale value from a
	// prior call doesn't false-positive an "auth bound it" assertion
	// when actually the current request short-circuited 401.
	f.observed.set("")

	req, err := http.NewRequest(http.MethodPost, f.srv.URL, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	for k, vs := range extraHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

func (f *authFixture) lastSeenAccountID() string { return f.observed.get() }

func (f *authFixture) signJWT(t *testing.T, sub string) string {
	return f.signJWTWithExpiry(t, sub, time.Hour)
}

func (f *authFixture) signJWTWithExpiry(t *testing.T, sub string, ttl time.Duration) string {
	t.Helper()
	rawClaims := `{
		"iss": "` + f.issuer + `",
		"aud": "reduit",
		"sub": "` + sub + `",
		"email": "` + sub + `@example.com",
		"email_verified": true,
		"exp": ` + strconv.FormatInt(time.Now().Add(ttl).Unix(), 10) + `,
		"iat": ` + strconv.FormatInt(time.Now().Unix(), 10) + `
	}`
	return oidctest.SignIDToken(f.priv, f.keyID, f.alg, rawClaims)
}

func openTempStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir + "/reduit.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Migrate(""); err != nil {
		st.Close()
		t.Fatalf("Migrate: %v", err)
	}
	return st
}

func newOIDCTestServer(t *testing.T) (priv crypto.PrivateKey, srvURL, keyID, alg string) {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	keyID = "test-key"
	alg = gooidc.RS256
	tsrv := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{{
			PublicKey: rsaKey.Public(),
			KeyID:     keyID,
			Algorithm: alg,
		}},
	}
	srv := httptest.NewServer(tsrv)
	t.Cleanup(srv.Close)
	tsrv.SetIssuer(srv.URL)
	return rsaKey, srv.URL, keyID, alg
}

// stripVolatileHeaders returns a copy of h with headers expected to
// vary between requests removed (Date, Content-Length). Used by the
// indistinguishability test so a Date-second jitter doesn't
// false-positive a real header leak.
func stripVolatileHeaders(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		switch strings.ToLower(k) {
		case "date", "content-length":
			continue
		}
		out[k] = append([]string(nil), v...)
	}
	return out
}

func headersEqual(a, b http.Header) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || len(va) != len(vb) {
			return false
		}
		for i := range va {
			if va[i] != vb[i] {
				return false
			}
		}
	}
	return true
}
