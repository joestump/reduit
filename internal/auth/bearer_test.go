package auth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"

	"github.com/joestump/reduit/internal/auth"
	"github.com/joestump/reduit/internal/auth/mcptoken"
	authoidc "github.com/joestump/reduit/internal/auth/oidc"
	"github.com/joestump/reduit/internal/store"
)

// TestParseBearer covers the RFC 6750 fragments: case-insensitive
// scheme, exact-one-space, no embedded whitespace, non-empty value.
func TestParseBearer(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		header  string
		want    string
		wantErr error
	}{
		{"Bearer abc", "abc", nil},
		{"bearer abc", "abc", nil},
		{"BEARER abc", "abc", nil},
		{"Bearer  abc", "abc", nil}, // trailing space gets trimmed
		{"", "", auth.ErrBearerMissing},
		{"Bearer", "", auth.ErrBearerMissing},
		{"Bearer ", "", auth.ErrBearerMissing},
		{"Basic abc", "", auth.ErrBearerMissing},
		{"Bearer abc def", "", auth.ErrBearerInvalid},
	} {
		tc := tc
		t.Run(tc.header, func(t *testing.T) {
			t.Parallel()
			got, err := auth.ParseBearer(tc.header)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBearerValidator_OIDC_Valid covers SPEC-0006's "OIDC bearer
// token authenticates as the OIDC user" scenario. We sign a real ID
// token with the oidctest harness and run it through the production
// validator.
//
// Governing: SPEC-0006 REQ "Bearer Authentication Required".
func TestBearerValidator_OIDC_Valid(t *testing.T) {
	t.Parallel()
	priv, srvURL, keyID, alg := newOIDCTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := authoidc.New(ctx, authoidc.Config{
		IssuerURL:   srvURL,
		ClientID:    "reduit",
		RedirectURL: "https://reduit.example.com/auth/callback",
		Scopes:      []string{"openid"},
	})
	if err != nil {
		t.Fatalf("authoidc.New: %v", err)
	}
	v := auth.NewBearerValidator(c, nil)

	jwt := signIDToken(t, priv, keyID, alg, srvURL, "joe")
	p, err := v.Validate(ctx, jwt)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if p.Source != auth.PrincipalSourceOIDC {
		t.Errorf("Source = %v, want OIDC", p.Source)
	}
	if p.Subject != "joe" {
		t.Errorf("Subject = %q, want %q", p.Subject, "joe")
	}
}

// TestBearerValidator_OIDC_Tampered checks SPEC-0006's tampered-JWT
// rejection. A flipped signature byte MUST yield ErrBearerInvalid.
//
// Governing: issue #13 acceptance: "tampered JWT signature is rejected".
func TestBearerValidator_OIDC_Tampered(t *testing.T) {
	t.Parallel()
	priv, srvURL, keyID, alg := newOIDCTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := authoidc.New(ctx, authoidc.Config{
		IssuerURL:   srvURL,
		ClientID:    "reduit",
		RedirectURL: "https://reduit.example.com/auth/callback",
		Scopes:      []string{"openid"},
	})
	if err != nil {
		t.Fatalf("authoidc.New: %v", err)
	}
	v := auth.NewBearerValidator(c, nil)
	jwt := signIDToken(t, priv, keyID, alg, srvURL, "joe")
	parts := strings.Split(jwt, ".")
	// Flip a byte well inside the signature segment (not the last
	// char, which can fall in base64 padding bits and leave the
	// decoded signature unchanged). Mid-segment guarantees a real
	// signature byte change so RS256 verification fails.
	mid := len(parts[2]) / 2
	swap := byte('A')
	if parts[2][mid] == 'A' {
		swap = 'B'
	}
	parts[2] = parts[2][:mid] + string(swap) + parts[2][mid+1:]
	tampered := strings.Join(parts, ".")
	if _, err := v.Validate(ctx, tampered); !errors.Is(err, auth.ErrBearerInvalid) {
		t.Fatalf("Validate(tampered) err = %v, want ErrBearerInvalid", err)
	}
}

// TestBearerValidator_MCPToken_Valid covers SPEC-0006's "Per-user MCP
// token authenticates as the issuing user" scenario.
func TestBearerValidator_MCPToken_Valid(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	insertAccount(t, st, "acct-7")
	repo := mcptoken.NewRepository(st.DB)

	ctx := context.Background()
	tok, err := repo.Issue(ctx, mcptoken.IssueParams{AccountID: "acct-7"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	v := auth.NewBearerValidator(nil, repo)
	p, err := v.Validate(ctx, tok.Plaintext)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if p.Source != auth.PrincipalSourceMCPToken {
		t.Errorf("Source = %v, want MCPToken", p.Source)
	}
	if p.AccountID != "acct-7" {
		t.Errorf("AccountID = %q, want %q", p.AccountID, "acct-7")
	}
}

// TestBearerValidator_MCPToken_SubjectResolver covers C3 from the
// round-1 hostile review: Principal.Subject MUST be populated for
// MCP-token bearers when a SubjectResolver is wired (it's the
// account's OIDC sub), and MUST stay empty when none is wired (a
// downstream consumer that branches on Subject != "" needs that
// signal to be deterministic).
//
// Governing: SPEC-0006 REQ "Bearer Authentication Required".
func TestBearerValidator_MCPToken_SubjectResolver(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	insertAccount(t, st, "acct-resolved")
	repo := mcptoken.NewRepository(st.DB)

	ctx := context.Background()
	tok, err := repo.Issue(ctx, mcptoken.IssueParams{AccountID: "acct-resolved"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Without a resolver: Subject is empty (documented contract).
	v := auth.NewBearerValidator(nil, repo)
	p, err := v.Validate(ctx, tok.Plaintext)
	if err != nil {
		t.Fatalf("Validate (no resolver): %v", err)
	}
	if p.Subject != "" {
		t.Errorf("Subject = %q, want empty (no resolver wired)", p.Subject)
	}
	if p.AccountID != "acct-resolved" {
		t.Errorf("AccountID = %q, want %q", p.AccountID, "acct-resolved")
	}

	// With a resolver: Subject reflects the account's OIDC sub.
	v.WithSubjectResolver(func(ctx context.Context, accountID string) (string, error) {
		if accountID != "acct-resolved" {
			t.Errorf("resolver called with accountID=%q, want %q", accountID, "acct-resolved")
		}
		return "oidc-sub-9", nil
	})
	p, err = v.Validate(ctx, tok.Plaintext)
	if err != nil {
		t.Fatalf("Validate (with resolver): %v", err)
	}
	if p.Subject != "oidc-sub-9" {
		t.Errorf("Subject = %q, want oidc-sub-9", p.Subject)
	}

	// Resolver error: Subject silently empty, request still authorises
	// (Subject is audit metadata, not an authz key).
	v.WithSubjectResolver(func(ctx context.Context, accountID string) (string, error) {
		return "", errors.New("transient db error")
	})
	p, err = v.Validate(ctx, tok.Plaintext)
	if err != nil {
		t.Fatalf("Validate (resolver error): %v", err)
	}
	if p.Subject != "" {
		t.Errorf("Subject = %q on resolver error, want empty", p.Subject)
	}
	if p.AccountID != "acct-resolved" {
		t.Errorf("AccountID dropped on resolver error: %q", p.AccountID)
	}
}

// TestBearerValidator_MCPToken_Revoked covers issue #13 acceptance:
// "revoked MCP token returns 401 within 1s of revocation". We exercise
// the validator end-to-end via RequireBearer to prove the 401 reaches
// the wire.
func TestBearerValidator_MCPToken_Revoked(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	insertAccount(t, st, "acct-9")
	repo := mcptoken.NewRepository(st.DB)
	ctx := context.Background()

	tok, err := repo.Issue(ctx, mcptoken.IssueParams{AccountID: "acct-9"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	v := auth.NewBearerValidator(nil, repo)
	handler := auth.RequireBearer(v, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Pre-revocation: the token works.
	if got := getStatus(t, srv.URL, tok.Plaintext); got != 200 {
		t.Fatalf("pre-revoke status = %d, want 200", got)
	}

	revStart := time.Now()
	if err := repo.Revoke(ctx, tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got := getStatus(t, srv.URL, tok.Plaintext)
	if got != http.StatusUnauthorized {
		t.Fatalf("post-revoke status = %d, want 401", got)
	}
	if elapsed := time.Since(revStart); elapsed > time.Second {
		t.Fatalf("revocation -> 401 took %v, want <1s", elapsed)
	}
}

// TestRequireBearer_RejectsAnonymous covers SPEC-0006's
// "Unauthenticated MCP request is rejected" scenario.
func TestRequireBearer_RejectsAnonymous(t *testing.T) {
	t.Parallel()
	v := auth.NewBearerValidator(nil, nil)
	handler := auth.RequireBearer(v, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler reached without bearer")
	}))
	srv := httptest.NewServer(handler)
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got == "" {
		t.Errorf("WWW-Authenticate not set on 401")
	}
}

func getStatus(t *testing.T, baseURL, bearer string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// signIDToken builds a JWT that satisfies the production verifier for
// the given subject. Helper duplicated to keep test packages independent.
func signIDToken(t *testing.T, priv crypto.PrivateKey, keyID, alg, iss, sub string) string {
	t.Helper()
	rawClaims := `{
		"iss": "` + iss + `",
		"aud": "reduit",
		"sub": "` + sub + `",
		"email": "` + sub + `@example.com",
		"email_verified": true,
		"exp": ` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `,
		"iat": ` + strconv.FormatInt(time.Now().Unix(), 10) + `
	}`
	return oidctest.SignIDToken(priv, keyID, alg, rawClaims)
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

func insertAccount(t *testing.T, st *store.Store, id string) {
	t.Helper()
	const q = `
		INSERT INTO accounts (id, oidc_subject, state, key_envelope)
		VALUES (?, ?, 'pending_proton_setup', X'00')
	`
	if _, err := st.DB.ExecContext(context.Background(), q, id, "sub-"+uuid.NewString()); err != nil {
		t.Fatalf("insert account: %v", err)
	}
}
