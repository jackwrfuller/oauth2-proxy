package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"encoding/base64"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

const lagoonOIDCProviderName = "Lagoon OIDC"

const lagoonGraphqlEndpoint = "http://lagoon-api.172.18.0.240.nip.io/graphql"

const queryGetEnvironmentByRoute = `
query GetEnvironmentByRoute($route: String!) {
  environmentByRoute(route: $route) {
    id
    name
  }
}
`
type environmentByRouteResponse struct {
    Data struct {
        EnvironmentByRoute struct {
            ID   int `json:"id"`
            Name string `json:"name"`
        } `json:"environmentByRoute"`
    } `json:"data"`
    Errors []struct {
        Message string `json:"message"`
    } `json:"errors,omitempty"`
}

type LagoonOIDCProvider struct {
	*OIDCProvider
}

var _ Provider = (*LagoonOIDCProvider)(nil)

func NewLagoonOIDCProvider(p *ProviderData, opts options.Provider) (*LagoonOIDCProvider, error) {
	p.setProviderDefaults(providerDefaults{
		name: lagoonOIDCProviderName,
	})

	provider := &LagoonOIDCProvider{
		OIDCProvider: NewOIDCProvider(p, opts.OIDCConfig),
	}

	return provider, nil
}

func (p *LagoonOIDCProvider) Authorize(ctx context.Context, s *sessions.SessionState) (bool, error) {
	logger.Printf("Checking Lagoon provider for authorization on %s\n", s.AppRedirect)

	parts := strings.Split(s.AccessToken, ".")
    if len(parts) == 3 {
		header, _ := base64.RawURLEncoding.DecodeString(parts[0])
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		logger.Printf("Access Token Header: %s\n", header)
		logger.Printf("Access Token Payload: %s\n", payload)
    }

	route := strings.TrimRight(s.AppRedirect, "/")
	if route == "" {
		return false, fmt.Errorf("missing redirect URL")
	}

	body := map[string]interface{}{
		"query":    queryGetEnvironmentByRoute,
		"variables": map[string]string{"route": route},
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return false, fmt.Errorf("failed to marshal GraphQL request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", lagoonGraphqlEndpoint, bytes.NewReader(bodyJSON))
	if err != nil {
		return false, fmt.Errorf("failed to create GraphQL request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer " + s.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to call Lagoon GraphQL API: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected GraphQL status: %d", resp.StatusCode)
	}

	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	logger.Printf("Lagoon Authorization returned:\n%s\n", string(bodyBytes))

	var gqlResp environmentByRouteResponse
	if err := json.Unmarshal(bodyBytes, &gqlResp); err != nil {
		return false, fmt.Errorf("failed to decode GraphQL response: %w", err)
	}

	if len(gqlResp.Errors) > 0 {
		return false, fmt.Errorf("GraphQL error: %s", gqlResp.Errors[0].Message)
	}

	if gqlResp.Data.EnvironmentByRoute.Name != "" {
		return true, nil
	}

	return false, nil
}

