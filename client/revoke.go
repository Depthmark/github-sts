package client

import (
	"context"
	"fmt"
	"net/http"
)

// RevokeToken revokes a GitHub App installation token by calling
// DELETE /installation/token. Returns nil on success (204) or if the
// token was already revoked/expired (401/404). Returns an error on
// unexpected status codes.
//
// STS-issued tokens should NOT be revoked via this function — they are
// managed by the STS service.
func RevokeToken(ctx context.Context, token, apiURL string) error {
	url := apiURL + "/installation/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := defaultHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("DELETE %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusUnauthorized, http.StatusNotFound:
		// Token already revoked or expired — not an error.
		return nil
	default:
		return fmt.Errorf("DELETE %s returned %d", url, resp.StatusCode)
	}
}
