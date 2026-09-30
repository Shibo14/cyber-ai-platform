package tenantidentity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestParseTenantID(t *testing.T) {
	got, err := ParseTenantID("A0B1C2D3-E4F5-4678-9ABC-DEF012345678")
	if err != nil {
		t.Fatal(err)
	}
	if got != "a0b1c2d3-e4f5-4678-9abc-def012345678" {
		t.Fatalf("ParseTenantID() = %q", got)
	}

	for _, invalid := range []string{"", "not-a-uuid", "a0b1c2d3e4f546789abcdef012345678"} {
		if _, err := ParseTenantID(invalid); err == nil {
			t.Errorf("ParseTenantID(%q) unexpectedly succeeded", invalid)
		}
	}
}

func TestRequireIdentityFailsClosedAndIgnoresClientTenantHeader(t *testing.T) {
	router := chi.NewRouter()
	router.Use(RequireIdentity)
	router.Get("/tenant", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/tenant", nil)
	request.Header.Set("X-Tenant-ID", "a0b1c2d3-e4f5-4678-9abc-def012345678")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status without trusted context = %d, want %d", response.Code, http.StatusUnauthorized)
	}

	identity, err := ParseTenantID("a0b1c2d3-e4f5-4678-9abc-def012345678")
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/tenant", nil)
	request = request.WithContext(WithAuthenticatedIdentity(request.Context(), Identity{
		TenantID: identity, PrincipalID: "opaque-subject",
	}))
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status with trusted context = %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestFromContext(t *testing.T) {
	identity := Identity{TenantID: "a0b1c2d3-e4f5-4678-9abc-def012345678", PrincipalID: "subject"}
	got, ok := FromContext(WithAuthenticatedIdentity(context.Background(), identity))
	if !ok || got != identity {
		t.Fatalf("FromContext() = (%+v, %v), want (%+v, true)", got, ok, identity)
	}
}
