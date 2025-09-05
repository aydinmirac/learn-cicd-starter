package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		wantKey   string
		wantErr   error
		expectErr bool
	}{
		{
			name:      "no authorization header",
			headers:   http.Header{},
			wantKey:   "",
			wantErr:   auth.ErrNoAuthHeaderIncluded,
			expectErr: true,
		},
		{
			name: "malformed header - missing ApiKey",
			headers: http.Header{
				"Authorization": []string{"Bearer sometoken"},
			},
			wantKey:   "",
			expectErr: true,
		},
		{
			name: "malformed header - only ApiKey without token",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey:   "",
			expectErr: true,
		},
		{
			name: "valid header",
			headers: http.Header{
				"Authorization": []string{"ApiKey secret123"},
			},
			wantKey:   "secret123",
			expectErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, err := auth.GetAPIKey(tc.headers)

			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error but got nil")
				}
				// if a specific error is expected, check it
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Errorf("expected error %v, got %v", tc.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("did not expect error, got %v", err)
				}
				if gotKey != tc.wantKey {
					t.Errorf("expected key %q, got %q", tc.wantKey, gotKey)
				}
			}
		})
	}
}
