package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

const (
	userSolSignPath = "/api/v1/user/signer/solana/signTransaction"
	axalSolSignPath = "/api/v1/axal/signer/solana/signTransaction"

	validSolSignBody = `{
		"privy_id": "did:privy:cm00000000000000000001",
		"method": "signTransaction",
		"params": { "transaction": "YSBzZXJpYWxpemVkIHNvbGFuYSB0cmFuc2FjdGlvbg==", "encoding": "base64" },
		"wallet_address": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
	}`
)

func newTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	initRoutes(r)

	return r
}

func postJSON(r *gin.Engine, path string, auth string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("auth", auth)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

// The paths are the contract with the callers, so they are pinned as written.
func TestSolanaSigningRoutesAreRegistered(t *testing.T) {
	registered := map[string]bool{}
	for _, route := range newTestRouter().Routes() {
		registered[route.Method+" "+route.Path] = true
	}

	for _, path := range []string{userSolSignPath, axalSolSignPath} {
		if !registered["POST "+path] {
			t.Errorf("POST %s is not registered", path)
		}
	}
}

func TestSolanaSigningRoutesRequireAuth(t *testing.T) {
	r := newTestRouter()

	for _, path := range []string{userSolSignPath, axalSolSignPath} {
		w := postJSON(r, path, "", validSolSignBody)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("POST %s without auth = %d, want 401", path, w.Code)
		}
	}
}

// A request that fails validation is answered before the signer is involved at all. These run
// with no Privy client configured, so reaching it would be a nil dereference, not a 400.
func TestSolanaSigningRoutesRejectAnInvalidRequest(t *testing.T) {
	r := newTestRouter()

	for name, body := range map[string]string{
		"not json": `not json`,
		"empty":    `{}`,
		"wrong method": strings.Replace(validSolSignBody,
			`"method": "signTransaction"`, `"method": "signAndSendTransaction"`, 1),
		"wrong encoding": strings.Replace(validSolSignBody,
			`"encoding": "base64"`, `"encoding": "hex"`, 1),
		"transaction is not base64": strings.Replace(validSolSignBody,
			`YSBzZXJpYWxpemVkIHNvbGFuYSB0cmFuc2FjdGlvbg==`, `not base64!`, 1),
		"no wallet": strings.Replace(validSolSignBody,
			`"wallet_address": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"`, `"wallet_address": ""`, 1),
		"an eth wallet": strings.Replace(validSolSignBody,
			`9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM`, `0xaaaa000000000000000000000000000000000001`, 1),
	} {
		for _, path := range []string{userSolSignPath, axalSolSignPath} {
			t.Run(name+" "+path, func(t *testing.T) {
				w := postJSON(r, path, "some-auth", body)

				if w.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400", w.Code)
				}
				if got := strings.TrimSpace(w.Body.String()); got != `{"message":"tx data is invalid"}` {
					t.Errorf("body = %s, want the tx data is invalid message", got)
				}
			})
		}
	}
}

// The Axal route has no session to take the user from, so a body that does not name one is
// invalid there and only there.
func TestAxalSolanaSigningRouteRequiresAPrivyID(t *testing.T) {
	r := newTestRouter()

	body := strings.Replace(validSolSignBody, `"privy_id": "did:privy:cm00000000000000000001",`, ``, 1)

	if w := postJSON(r, axalSolSignPath, "some-auth", body); w.Code != http.StatusBadRequest {
		t.Errorf("axal route without privy_id = %d, want 400", w.Code)
	}
}
