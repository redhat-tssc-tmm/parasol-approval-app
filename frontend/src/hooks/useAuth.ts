/**
 * useAuth — Keycloak OIDC authentication hook for the Parasol Approval Process.
 *
 * Authentication & Identity Flow:
 *
 * This hook manages the full OIDC authentication lifecycle with Keycloak. It produces
 * TWO tokens that serve different purposes in the attestation signing workflow:
 *
 *   1. access_token (state.token):
 *      - Used as a Bearer token for all API calls to the Go backend
 *      - The backend validates this JWT against Keycloak's JWKS endpoint
 *      - Contains the user's identity (preferred_username, email, etc.)
 *
 *   2. id_token (state.idToken):
 *      - Passed to the backend during attestation creation (POST /api/attest)
 *      - The backend forwards this to cosign via --identity-token
 *      - Fulcio (the certificate authority) validates this token and issues a
 *        short-lived x509 signing certificate with the user's email as the
 *        Subject Alternative Name (SAN)
 *      - This is HOW the user's identity gets cryptographically bound to the attestation
 *
 * Why "trusted-artifact-signer" as the Keycloak client:
 *
 *   Fulcio is configured to trust a specific OIDC client ID. On this cluster, the
 *   Trusted Artifact Signer (TAS) deployment registered "trusted-artifact-signer"
 *   as a public client in Keycloak AND configured Fulcio to accept tokens from this
 *   client. If we used a different client ID, Fulcio would reject the id_token and
 *   refuse to issue a signing certificate.
 *
 *   The client is configured as "public" (no client secret) with PKCE enabled,
 *   which is the recommended flow for browser-based applications.
 *
 * Token refresh:
 *
 *   Both tokens are refreshed together every 30 seconds. This is important because
 *   the id_token has a limited lifetime, and if a user takes a while to fill in the
 *   approval form, we need a fresh id_token when they submit. A stale id_token would
 *   be rejected by Fulcio.
 */
import { useState, useEffect, useRef, useCallback } from 'react';
import Keycloak from 'keycloak-js';
import { UserProfile } from '../types';

interface AuthState {
  authenticated: boolean;
  user: UserProfile | null;
  token: string | null;    // Keycloak access_token — used for API authentication
  idToken: string | null;  // Keycloak id_token — forwarded to cosign for Fulcio signing identity
  keycloak: Keycloak | null;
  loading: boolean;
  error: string | null;
}

export function useAuth() {
  const [state, setState] = useState<AuthState>({
    authenticated: false,
    user: null,
    token: null,
    idToken: null,
    keycloak: null,
    loading: true,
    error: null,
  });

  const initCalled = useRef(false);

  useEffect(() => {
    if (initCalled.current) return;
    initCalled.current = true;

    async function init() {
      // Defaults — the client ID MUST match what Fulcio is configured to trust.
      // See the SecureSign CR's fulcio.config.OIDCIssuers[].ClientID field.
      let keycloakUrl = import.meta.env.VITE_KEYCLOAK_URL || '';
      let realm = import.meta.env.VITE_KEYCLOAK_REALM || 'sso';
      let clientId = import.meta.env.VITE_KEYCLOAK_CLIENT_ID || 'trusted-artifact-signer';

      // Fetch the Keycloak URL from the backend's /api/config endpoint (unauthenticated).
      // This avoids hardcoding the Keycloak URL at frontend build time — the backend
      // auto-detects it from the cluster subdomain.
      console.log('[auth] Fetching config from /api/config...');
      try {
        const configResp = await fetch('/api/config');
        if (configResp.ok) {
          const config = await configResp.json();
          console.log('[auth] Got server config:', config);
          if (config.keycloakURL) {
            // The backend returns the issuer URL (e.g. https://sso.../realms/sso).
            // The Keycloak JS adapter needs the base URL without /realms/sso.
            const issuer: string = config.keycloakURL;
            const realmSuffix = `/realms/${realm}`;
            if (issuer.endsWith(realmSuffix)) {
              keycloakUrl = issuer.slice(0, -realmSuffix.length);
            } else {
              keycloakUrl = issuer;
            }
          }
          if (config.keycloakClientID) {
            clientId = config.keycloakClientID;
          }
        } else {
          console.log('[auth] /api/config returned', configResp.status);
        }
      } catch (err) {
        console.log('[auth] /api/config fetch failed:', err);
      }

      if (!keycloakUrl) {
        console.error('[auth] No Keycloak URL available from /api/config or VITE_KEYCLOAK_URL');
        setState(prev => ({ ...prev, loading: false, error: 'Keycloak URL not configured. Set VITE_KEYCLOAK_URL or check /api/config.' }));
        return;
      }

      console.log('[auth] Initializing Keycloak:', { url: keycloakUrl, realm, clientId });

      const kc = new Keycloak({
        url: keycloakUrl,
        realm: realm,
        clientId: clientId,
      });

      try {
        // Initialize with authorization code flow + PKCE (Proof Key for Code Exchange).
        // PKCE is required for public clients to prevent authorization code interception.
        // 'login-required' redirects to Keycloak login immediately if not authenticated.
        const authenticated = await kc.init({
          onLoad: 'login-required',
          checkLoginIframe: false,
          pkceMethod: 'S256',
        });

        console.log('[auth] Keycloak initialized, authenticated:', authenticated);

        if (authenticated && kc.tokenParsed) {
          // Extract user profile from the access token's claims.
          // These claims are also present in the id_token and will appear in the
          // Fulcio certificate's Subject Alternative Name (email) when signing.
          const profile: UserProfile = {
            preferred_username: kc.tokenParsed.preferred_username || '',
            email: kc.tokenParsed.email || '',
            given_name: kc.tokenParsed.given_name || '',
            family_name: kc.tokenParsed.family_name || '',
            sub: kc.tokenParsed.sub || '',
          };

          console.log('[auth] User profile:', profile);
          console.log('[auth] ID token available:', !!kc.idToken);
          console.log('[auth] Access token available:', !!kc.token);

          // Store both tokens:
          // - token (access_token): sent as Bearer header on API calls
          // - idToken: sent in the attestation form body, forwarded to cosign --identity-token
          setState({
            authenticated: true,
            user: profile,
            token: kc.token || null,
            idToken: kc.idToken || null,
            keycloak: kc,
            loading: false,
            error: null,
          });

          // Refresh both tokens every 30 seconds. The id_token must be fresh when the
          // user submits an attestation — Fulcio rejects expired tokens. updateToken(30)
          // refreshes if the token expires within 30 seconds.
          setInterval(async () => {
            try {
              const refreshed = await kc.updateToken(30);
              if (refreshed) {
                console.log('[auth] Token refreshed');
                setState(prev => ({
                  ...prev,
                  token: kc.token || null,
                  idToken: kc.idToken || null,
                }));
              }
            } catch (err) {
              console.error('[auth] Token refresh failed:', err);
              kc.login();
            }
          }, 30000);
        } else {
          setState(prev => ({ ...prev, loading: false, error: 'Not authenticated' }));
        }
      } catch (err) {
        console.error('[auth] Keycloak init failed:', err);
        setState(prev => ({
          ...prev,
          loading: false,
          error: `Keycloak initialization failed: ${err}`,
        }));
      }
    }

    init();
  }, []);

  const logout = useCallback(() => {
    if (state.keycloak) {
      state.keycloak.logout();
    }
  }, [state.keycloak]);

  return { ...state, logout };
}
