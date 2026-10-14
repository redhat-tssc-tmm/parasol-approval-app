// Package auth handles Keycloak-based OIDC authentication for the Parasol Approval Process.
//
// Authentication & identity model (dual-token pattern):
//
// This application uses two distinct tokens from Keycloak, each serving a different purpose:
//
//  1. Access Token (used here): Validated by this package on every API request.
//     The frontend sends it as a Bearer token in the Authorization header.
//     We validate its signature against Keycloak's JWKS endpoint, check the issuer
//     and expiration, and extract the user's identity (username, email, name).
//     This token authorizes the user to call our API.
//
//  2. ID Token (passed through to cosign): NOT validated here — it is forwarded
//     by the frontend in the attestation request body and passed directly to
//     cosign's --identity-token flag. Fulcio (the Sigstore certificate authority)
//     validates this token against the Keycloak OIDC issuer and uses the user's
//     email from it to issue a short-lived signing certificate.
//     This token provides the cryptographic identity for the attestation signature.
//
// Why the "trusted-artifact-signer" Keycloak client:
//
// The application uses the existing "trusted-artifact-signer" public client in Keycloak's
// SSO realm. This client is specifically configured in the cluster's Trusted Artifact Signer
// (TAS) deployment — Fulcio's OIDC configuration trusts this client ID. Using a different
// client would require reconfiguring Fulcio's OIDCIssuers in the SecureSign CR.
//
// The client is public (no client secret), supports standard flow with PKCE, and has a
// wildcard redirect URI. The frontend uses the Keycloak JS adapter with PKCE for the
// authorization code flow.
package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Provider validates JWTs issued by a Keycloak realm using the realm's JWKS (JSON Web Key Set).
// It caches the public keys and refreshes them when an unknown key ID is encountered.
type Provider struct {
	issuerURL string             // Full issuer URL: https://sso.<subdomain>/realms/sso
	realm     string             // Keycloak realm name (e.g. "sso")
	clientID  string             // OIDC client ID (e.g. "trusted-artifact-signer")
	jwksURL   string             // JWKS endpoint: <issuerURL>/protocol/openid-connect/certs
	keys      map[string]*rsa.PublicKey // Cached signing keys, indexed by key ID (kid)
	mu        sync.RWMutex
	lastFetch time.Time
}

// UserInfo represents the authenticated user's identity, extracted from JWT claims.
// These fields come from standard OIDC claims in the Keycloak-issued access token.
type UserInfo struct {
	Username  string `json:"preferred_username"` // Keycloak username (e.g. "user1")
	Email     string `json:"email"`              // Used as the signer identity in attestation predicates
	FirstName string `json:"given_name"`          // Used in the attestation predicate's "approver" field
	LastName  string `json:"family_name"`
	Sub       string `json:"sub"`                // Keycloak user UUID
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kid string `json:"kid"` // Key ID — matches the "kid" header in JWTs
	Kty string `json:"kty"` // Key type (we only use "RSA")
	N   string `json:"n"`   // RSA modulus (base64url-encoded)
	E   string `json:"e"`   // RSA exponent (base64url-encoded)
	Use string `json:"use"` // Key usage — we only load "sig" (signing) keys
	Alg string `json:"alg"` // Algorithm (e.g. "RS256")
}

// New creates an auth Provider by fetching the JWKS from the Keycloak realm.
// This is called once at startup. The JWKS contains the public keys used to
// verify JWT signatures — these are the same keys Keycloak uses to sign tokens.
func New(keycloakURL, realm, clientID string) (*Provider, error) {
	issuerURL := fmt.Sprintf("%s/realms/%s", keycloakURL, realm)
	jwksURL := fmt.Sprintf("%s/protocol/openid-connect/certs", issuerURL)
	log.Printf("[auth] Initializing provider: issuer=%s jwksURL=%s clientID=%s", issuerURL, jwksURL, clientID)

	p := &Provider{
		issuerURL: issuerURL,
		realm:     realm,
		clientID:  clientID,
		jwksURL:   jwksURL,
		keys:      make(map[string]*rsa.PublicKey),
	}

	if err := p.fetchKeys(); err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	return p, nil
}

// IssuerURL returns the full Keycloak issuer URL (e.g. https://sso.<subdomain>/realms/sso).
// This is exposed to the /api/config endpoint so the frontend knows where to redirect for login.
func (p *Provider) IssuerURL() string {
	return p.issuerURL
}

// ClientID returns the OIDC client ID (e.g. "trusted-artifact-signer").
// Exposed to /api/config so the frontend uses the correct client for the Keycloak JS adapter.
func (p *Provider) ClientID() string {
	return p.clientID
}

// fetchKeys downloads the JWKS from Keycloak and caches the RSA public keys.
// Called at startup and when a JWT references an unknown key ID (key rotation).
func (p *Provider) fetchKeys() error {
	log.Printf("[auth] Fetching JWKS from %s", p.jwksURL)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(p.jwksURL)
	if err != nil {
		return fmt.Errorf("JWKS fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS fetch returned status %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("JWKS decode failed: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.Use != "sig" {
			continue
		}
		pubKey, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			log.Printf("[auth] WARNING: Failed to parse key kid=%s: %v", k.Kid, err)
			continue
		}
		p.keys[k.Kid] = pubKey
		log.Printf("[auth] Loaded RSA key kid=%s alg=%s", k.Kid, k.Alg)
	}

	p.lastFetch = time.Now()
	log.Printf("[auth] JWKS loaded: %d signing keys", len(p.keys))
	return nil
}

// getKey retrieves the RSA public key for a given key ID. If the key is not cached
// and enough time has passed since the last fetch, it refreshes the JWKS (handles key rotation).
func (p *Provider) getKey(kid string) (*rsa.PublicKey, error) {
	p.mu.RLock()
	key, ok := p.keys[kid]
	p.mu.RUnlock()

	if ok {
		return key, nil
	}

	if time.Since(p.lastFetch) > 1*time.Minute {
		log.Printf("[auth] Key kid=%s not found, refreshing JWKS...", kid)
		if err := p.fetchKeys(); err != nil {
			return nil, err
		}
		p.mu.RLock()
		key, ok = p.keys[kid]
		p.mu.RUnlock()
		if ok {
			return key, nil
		}
	}

	return nil, fmt.Errorf("key kid=%s not found in JWKS", kid)
}

// ValidateToken verifies a Keycloak access token's signature, issuer, and expiration.
// On success, it extracts and returns the user's identity claims.
//
// This validates the ACCESS token (used for API authorization).
// The ID token (used for cosign signing identity) is NOT validated here —
// it is passed through to Fulcio, which validates it independently.
func (p *Provider) ValidateToken(tokenStr string) (*UserInfo, error) {
	log.Printf("[auth] Validating token (length=%d)", len(tokenStr))

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		return p.getKey(kid)
	},
		jwt.WithIssuer(p.issuerURL),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		log.Printf("[auth] Token validation failed: %v", err)
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to extract claims")
	}

	info := &UserInfo{
		Username:  claimStr(claims, "preferred_username"),
		Email:     claimStr(claims, "email"),
		FirstName: claimStr(claims, "given_name"),
		LastName:  claimStr(claims, "family_name"),
		Sub:       claimStr(claims, "sub"),
	}

	log.Printf("[auth] Token valid: user=%s email=%s", info.Username, info.Email)
	return info, nil
}

// Middleware returns a Gin middleware that validates the Bearer access token on every request.
//
// The middleware:
//  1. Extracts the Bearer token from the Authorization header
//  2. Validates the token signature, issuer, and expiration via ValidateToken
//  3. Stores the authenticated UserInfo in the Gin context (retrievable via GetUser)
//  4. Also stores the raw access token string in context as "token"
//
// Protected endpoints (under /api) use this middleware. Unauthenticated endpoints
// like /healthz, /api/config, and /ws are registered outside the middleware group.
func Middleware(provider *Provider) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			log.Printf("[auth] Request rejected: no Authorization header (path=%s)", c.Request.URL.Path)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			log.Printf("[auth] Request rejected: malformed Authorization header")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}

		// Validate the access token — this proves the user is authenticated.
		// Note: This is the access_token, NOT the id_token. The id_token is sent
		// separately in the attestation request body and forwarded to cosign.
		userInfo, err := provider.ValidateToken(parts[1])
		if err != nil {
			log.Printf("[auth] Request rejected: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		c.Set("user", userInfo)
		c.Set("token", parts[1])
		c.Next()
	}
}

// GetUser retrieves the authenticated user's identity from the Gin context.
// Returns nil if the request was not authenticated (should not happen on protected routes).
func GetUser(c *gin.Context) *UserInfo {
	user, _ := c.Get("user")
	if u, ok := user.(*UserInfo); ok {
		return u
	}
	return nil
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func claimStr(claims jwt.MapClaims, key string) string {
	if v, ok := claims[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
