# Parasol Release Approval Process

A web application for approving or rejecting container image releases in the Parasol Insurance secured pipeline. It creates cryptographically signed attestations (in-toto / SLSA) using cosign keyless signing via Trusted Artifact Signer (TAS), and attaches them to images in Quay alongside existing Tekton Chains attestations.

## What It Does

1. Authenticates users via Keycloak SSO (any user in the `sso` realm)
2. Shows container image tags from the user's `*-secured` Quay repository
3. Shows the currently deployed image in the user's preprod namespace
4. Highlights which image tag is deployed
5. Shows the release status of each image (approved/rejected/none) by verifying existing attestations
6. Lets the user approve or reject the current preprod image with a reason and optional file attachment
7. On submit: creates a custom attestation predicate, signs it with the user's Keycloak identity via Fulcio/Rekor, and attaches it to the image in Quay using the legacy DSSE format (compatible with Tekton Chains)
8. Reports the transparency log entry index back to the user
9. Attached documentation can be downloaded directly from the UI by clicking the paperclip icon

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Browser (React + PatternFly + Keycloak JS)         │
│  - OIDC login via Keycloak (public client, PKCE)    │
│  - WebSocket for live updates (images, deployments, │
│    attestation results, release status)              │
│  - Approve/Reject form with file upload             │
│  - Dark/light mode toggle                           │
└──────────────┬──────────────────────────────────────┘
               │ REST + WebSocket (Bearer token)
┌──────────────▼──────────────────────────────────────┐
│  Go Backend (single pod in parasol-approval ns)     │
│                                                     │
│  ┌──────────┐ ┌──────────┐ ┌───────────┐           │
│  │ auth     │ │ quay     │ │ k8s       │           │
│  │ (JWKS)   │ │ (API +   │ │ (client-  │           │
│  │          │ │  Poller) │ │  go Watch)│           │
│  └──────────┘ └──────────┘ └───────────┘           │
│  ┌──────────┐ ┌──────────┐ ┌───────────┐           │
│  │ cosign   │ │ ws       │ │ api       │           │
│  │ (Runner) │ │ (Hub)    │ │ (Handlers)│           │
│  └──────────┘ └──────────┘ └───────────┘           │
└─────────────────────────────────────────────────────┘
```

## Technology Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Backend | Go 1.22 + Gin | Single binary, goroutines for parallel cosign, client-go for K8s |
| Frontend | React 18 + Vite + PatternFly 6 | Red Hat design system, responsive, dark/light mode |
| Auth | Keycloak JS adapter + JWT validation | Uses existing `trusted-artifact-signer` public client |
| Real-time | WebSocket (gorilla/websocket) | Demand-driven: only polls/watches for connected tenants |
| Signing | cosign CLI (subprocess) | Keyless signing via Fulcio/Rekor (TAS), legacy DSSE format |
| Container | Multi-stage Containerfile (UBI 9) | Node build → Go build → UBI-minimal runtime |

## Directory Structure

```
parasol-approval-process/
├── ARCHITECTURE.md          ← This file
├── Containerfile            ← Multi-stage build (Node + Go → UBI-minimal)
├── .containerignore
├── go.mod / go.sum          ← Go dependencies
├── main.go                  ← Entry point: config, wiring, HTTP server
├── internal/
│   ├── auth/
│   │   └── auth.go          ← Keycloak JWKS validation, JWT middleware
│   ├── quay/
│   │   ├── client.go        ← Quay API client (repos, tags)
│   │   └── poller.go        ← Demand-driven Quay poller (only active tenants)
│   ├── k8s/
│   │   ├── client.go        ← K8s client, deployments, Quay creds, subdomain detection
│   │   └── watcher.go       ← Demand-driven deployment watcher (start/stop per tenant)
│   ├── cosign/
│   │   └── runner.go        ← cosign subprocess: initialize, attest, verify-attestation
│   ├── ws/
│   │   └── hub.go           ← Tenant-aware WebSocket hub with tenant change callbacks
│   └── api/
│       └── handler.go       ← HTTP handlers: images, deployments, attest, release-status, config
├── frontend/
│   ├── package.json
│   ├── vite.config.ts       ← Dev proxy → Go backend on :8080
│   ├── tsconfig.json
│   ├── index.html
│   └── src/
│       ├── main.tsx          ← React entry
│       ├── App.tsx           ← Main app: auth, data fetch, WS, dark/light mode
│       ├── types.ts          ← TypeScript interfaces
│       ├── vite-env.d.ts     ← Vite env type declarations
│       ├── components/
│       │   ├── ImageTable.tsx      ← Tag list with release status, deployed highlight, docs download
│       │   ├── DeploymentCard.tsx   ← Preprod deployment with Approve/Reject
│       │   └── ApprovalModal.tsx    ← Form: reason + file upload → attest, expandable error details
│       └── hooks/
│           ├── useAuth.ts    ← Keycloak init (config from /api/config), token refresh
│           └── useWebSocket.ts ← Tenant-aware, auto-reconnecting WS
└── deploy/
    └── deployment.yaml       ← OpenShift manifests (NS, SA, RBAC, Deployment, Route)
```

## Authentication and Identity Flow

This application uses a **dual-token pattern** — two different OIDC tokens serve two different purposes:

| Token | Purpose | Used by | Contains |
|-------|---------|---------|----------|
| **Access token** | API authorization | Backend (JWT middleware) | Roles, permissions, username |
| **ID token** | Signing identity for cosign/Fulcio | cosign CLI (`--identity-token`) | Email, name, OIDC issuer |

### Step-by-step flow

1. Browser loads → frontend fetches `/api/config` (unauthenticated) to get Keycloak URL
2. Keycloak JS adapter redirects to SSO login (authorization code + PKCE)
3. User logs in → Keycloak returns **both** `id_token` and `access_token`
4. Frontend stores both tokens and sends `access_token` as Bearer header on all API calls
5. Backend validates the `access_token` JWT against Keycloak JWKS endpoint, extracts `preferred_username`
6. Username maps to tenant (user1 → user1-preprod namespace, user1 Quay org)
7. **For attestation only**: frontend also sends the **`id_token`** in the multipart form body
8. Backend passes the `id_token` to cosign via `--identity-token` flag
9. cosign sends the `id_token` to Fulcio (the certificate authority)
10. Fulcio validates the token against the Keycloak OIDC issuer, then issues a short-lived x509 certificate (~10 min validity) with the user's **email** as the Subject Alternative Name (SAN)
11. cosign signs the attestation with an ephemeral key pair and the Fulcio certificate
12. The signing event is recorded in the Rekor transparency log (immutable audit trail)
13. The signed attestation is pushed as a new layer on the image's `.att` tag in Quay

### Why two tokens?

The **access token** is for standard API authorization — the backend validates it to know who the user is and what they can access. It's a standard OIDC pattern.

The **ID token** is passed through to cosign/Fulcio to establish the **signing identity**. Fulcio needs to know WHO is signing, and it gets that from the ID token's claims (email, issuer). The resulting certificate embeds the user's email, creating a cryptographic link between the attestation and the human who approved/rejected it.

This is the same mechanism that `gitsign` uses for signing git commits — the developer's OIDC identity is embedded in the Fulcio certificate.

### Keycloak Client

Uses the existing `trusted-artifact-signer` client (public, PKCE-enabled). This is critical because Fulcio's OIDC config trusts this client ID. The client already has `redirectUris: ["*"]` so no redirect changes are needed.

**Audience concern**: The audience mapper currently sets `id.token.claim: false`. If Fulcio rejects the ID token, flip this to `true` in the mapper config.

## Cosign Attestation Flow

### Initialization (on startup)

```bash
cosign initialize \
  --mirror=https://tuf-trusted-artifact-signer.SUBDOMAIN \
  --root=https://tuf-trusted-artifact-signer.SUBDOMAIN/root.json
```

This stores the TUF root at `$HOME/.sigstore/root/` (the deployment sets `HOME=/tmp` for writability). The TUF root is used by `cosign verify-attestation` to resolve Fulcio/Rekor URLs.

### Attesting (per approval/rejection)

```bash
cosign attest \
  -d \
  --new-bundle-format=false \
  --use-signing-config=false \
  --fulcio-url=https://fulcio-server-trusted-artifact-signer.SUBDOMAIN \
  --rekor-url=https://rekor-server-trusted-artifact-signer.SUBDOMAIN \
  --identity-token=<user's Keycloak ID token> \
  --type=https://parasol-insurance.com/releases/v1 \
  --predicate=/tmp/predicate-XXXXX.json \
  --registry-username=<user> \
  --registry-password=<from K8s secret> \
  --yes \
  <image>@<digest>
```

Key flags:
- **`--new-bundle-format=false`**: Uses legacy DSSE format (same as Tekton Chains). This is critical — the default new bundle format replaces existing attestations on the `.att` tag instead of appending to them. With legacy format, our attestations coexist as separate layers alongside Chains attestations.
- **`--use-signing-config=false`**: Required when using `--new-bundle-format=false` with a TUF root installed. Disables TUF-based URL resolution for signing (URLs are passed explicitly instead).
- **`-d`**: Verbose output, required to capture the transparency log index from cosign's JSON bundle output.
- No temp docker config files — `--registry-username` and `--registry-password` pass Quay credentials directly per invocation.

### Verifying release status (background, per image)

```bash
cosign verify-attestation \
  --type=https://parasol-insurance.com/releases/v1 \
  --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer-regexp=".*" \
  --registry-username=<user> \
  --registry-password=<from K8s secret> \
  <image>@<digest>
```

This uses the TUF root (from `cosign initialize`) to resolve Rekor URLs. Returns all matching attestations; the backend parses every payload and picks the one with the latest `decisionDate`.

## Attestation Storage: .att Tag vs OCI Referrers

Container image attestations can be stored in two locations in an OCI registry:

### 1. `.att` tag (legacy cosign format) — **what we use**

Attestations are stored as layers in a single OCI manifest at a tag derived from the image digest:
```
sha256-<image_digest>.att
```

Each attestation is a separate layer in this manifest, using the DSSE (Dead Simple Signing Envelope) format. The signing certificate is stored in OCI annotations on each layer (`dev.sigstore.cosign/certificate`).

This is the format used by:
- **Tekton Chains** (SLSA provenance attestations)
- **This application** (release approval/rejection attestations)
- **EC/Conforma** (reads from here for policy validation)

### 2. OCI 1.1 Referrers API (new Sigstore bundle format)

Cosign v3+ can store attestations as separate OCI artifacts linked to the image via the [OCI Referrers API](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers). Each attestation is its own manifest, tagged by content type.

**EC/Conforma does NOT read from OCI referrers** — it only checks the `.att` tag. If attestations are stored via the referrers API, EC/Conforma validation will fail because it won't find any attestations.

### Why legacy DSSE format is required

Cosign v3+ defaults to the new Sigstore bundle format (`--new-bundle-format=true`). When this format is used:
1. The attestation is stored via OCI referrers (not the `.att` tag), OR
2. If forced to the `.att` tag, it **replaces the entire manifest** instead of appending a layer

Both behaviors break compatibility:
- Storing via referrers → EC/Conforma can't find the attestation
- Replacing the manifest → destroys existing Tekton Chains attestations

The fix is `--new-bundle-format=false` which:
- Writes in the legacy DSSE format (same as Tekton Chains)
- Appends a new layer to the existing `.att` manifest
- Preserves all existing attestations (Chains + previous approvals)

This also requires `--use-signing-config=false` because the TUF-based signing config mandates the new bundle format.

### Coexistence of multiple attestation types

A single image can have many attestations from different sources on its `.att` tag:

| Layer | Predicate Type | Signer | Source |
|-------|---------------|--------|--------|
| 0 | `https://slsa.dev/provenance/v0.2` (TaskRun) | `tekton-chains-controller` SA | Tekton Chains |
| 1 | `https://slsa.dev/provenance/v0.2` (PipelineRun) | `tekton-chains-controller` SA | Tekton Chains |
| 2 | `https://parasol-insurance.com/releases/v1` | `user2@demo.redhat.com` | This application |
| 3 | `https://parasol-insurance.com/releases/v1` | `user1@demo.redhat.com` | This application |

EC/Conforma policies can selectively validate specific attestation types by filtering on `predicateType` and `certificate-identity`.

### Certificate storage in OCI annotations

For legacy DSSE attestations, the signing certificate is NOT embedded in the DSSE envelope itself. Instead, it's stored as an OCI annotation on the manifest layer:

```
dev.sigstore.cosign/certificate: <PEM-encoded Fulcio certificate>
dev.sigstore.cosign/chain: <PEM-encoded certificate chain>
```

This means:
- `cosign download attestation` returns envelopes WITHOUT certificates
- `cosign verify-attestation` retrieves and validates certificates during verification
- To inspect certificates without verification, the OCI manifest must be fetched directly from the registry API (which this application does for the attestation inspector view)

## Custom Predicate Format

Type URI: `https://parasol-insurance.com/releases/v1`

```json
{
  "release": {
    "approved": true,
    "decisionDate": "2026-10-09T14:30:00Z",
    "approver": "user1 Demo",
    "approverEmail": "user1@demo.redhat.com"
  },
  "documentation": [
    {
      "reason": "<base64 encoded reason text>",
      "docs": "<base64 encoded uploaded file>",
      "filename": "evidence.pdf"
    }
  ],
  "metadata": {
    "processVersion": "1.0",
    "complianceFramework": "Parasol Release Policy",
    "notes": "Release approved process completed"
  }
}
```

The `filename` field preserves the original name of the uploaded documentation file. The `docs` field contains the file content base64-encoded. Both are stored in the signed attestation and can be retrieved and downloaded from the UI.

**Size limit**: Rekor has a `maxRequestBodySize` of 10MB and attestation storage limit of 100KB on this cluster. With base64 overhead, uploaded files should stay under ~60KB. Larger files will cause the attestation to fail.

## Real-Time Updates

| Source | Method | Trigger | What |
|--------|--------|---------|------|
| Quay images/tags | HTTP poll (10s) | Only when tenants connected via WS | New tags, digest changes |
| K8s deployments | Watch API (streaming) | Started/stopped per tenant connect/disconnect | Deployment updates in *-preprod |
| Release status | cosign verify-attestation | On image load + after new attestation | Approved/rejected/none per digest |

All updates are demand-driven — zero polling or watching when no users are connected. The WebSocket connection includes `?tenant=<username>` so the backend knows which tenants are active.

### WebSocket Message Types

| Type | Direction | Data |
|------|-----------|------|
| `images_update` | Server → Client | Tenant, repository, tags |
| `deployment_update` | Server → Client | Tenant, deployment info, event type |
| `attestation_created` | Server → Client | Tenant, image, digest, approved, tlog index |
| `release_status` | Server → Client | Tenant, digest, status, approver, date, reason, docs filename/content |

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/healthz` | No | Health check |
| GET | `/api/config` | No | Keycloak URL, client ID, Quay URL |
| GET | `/api/images/:user` | Yes | List image repos and tags from Quay |
| GET | `/api/deployments/:user` | Yes | List deployments in user-preprod namespace |
| POST | `/api/attest` | Yes | Create approval/rejection attestation (multipart form) |
| POST | `/api/check-release-status` | Yes | Trigger async release status checks (results via WS) |
| GET | `/ws?tenant=<user>` | No | WebSocket connection |

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CLUSTER_SUBDOMAIN` | No | Auto-detected | Override for non-cluster usage. On OpenShift, auto-detected from `ingresses.config.openshift.io/cluster` |
| `COSIGN_BIN` | No | `/usr/local/bin/cosign` | Path to cosign binary |
| `PORT` | No | `8080` | HTTP listen port |
| `KEYCLOAK_REALM` | No | `sso` | Keycloak realm name |
| `KEYCLOAK_CLIENT_ID` | No | `trusted-artifact-signer` | OIDC client ID |
| `FULCIO_URL` | No | Auto from subdomain | Fulcio server URL |
| `REKOR_URL` | No | Auto from subdomain | Rekor server URL |
| `OIDC_ISSUER` | No | Auto from subdomain | OIDC issuer URL |
| `TUF_MIRROR` | No | Auto from subdomain | TUF mirror URL |
| `GIN_MODE` | No | `debug` | Set to `release` for production |
| `HOME` | No | `/tmp` (in deployment) | Must be writable for cosign TUF cache (`$HOME/.sigstore/`) |

Frontend env vars (build-time, via Vite) — all optional, the app fetches config from `/api/config` at runtime:

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_KEYCLOAK_URL` | From /api/config | Keycloak base URL (without /realms/...) |
| `VITE_KEYCLOAK_REALM` | `sso` | Keycloak realm |
| `VITE_KEYCLOAK_CLIENT_ID` | `trusted-artifact-signer` | OIDC client |
| `VITE_QUAY_URL` | - | Quay base URL (for tag links in UI) |

## Building

### Locally (requires Go 1.22+ and Node 20+)

```bash
# Frontend
cd frontend && npm install --legacy-peer-deps && npm run build && cd ..

# Backend (embeds frontend/dist/)
go build -o parasol-approval-process .

# Run (auto-detects cluster subdomain via kubeconfig, reads Quay creds from cluster secrets)
# Override only if not on the target cluster:
#   CLUSTER_SUBDOMAIN=apps.cluster-gnpvw.dyn.redhatworkshops.io
COSIGN_BIN=$(which cosign) \
./parasol-approval-process
```

### Container (no local toolchain needed)

```bash
podman build -t parasol-approval:latest -f Containerfile .
```

## Deployment (OpenShift)

The `deploy/deployment.yaml` creates:
- Namespace `parasol-approval`
- ServiceAccount with ClusterRole:
  - `get/list/watch` on `apps/deployments` (all namespaces)
  - `get` on `secrets` scoped to `resourceNames: ["quay-push-secret"]`
  - `get` on `ingresses` in `config.openshift.io` scoped to `resourceNames: ["cluster"]`
- Deployment with init container that fetches cosign from TAS CLI server
- `HOME=/tmp` env var for cosign TUF cache writability
- Service + Route with TLS edge termination

```bash
oc apply -f deploy/deployment.yaml
```

### Init Container

The cosign binary is fetched at pod startup from the TAS CLI server (gzipped):
```
http://cli-server.trusted-artifact-signer.svc:8080/clients/linux/cosign-amd64.gz
```
Uses `registry.access.redhat.com/ubi9:latest` (has `gunzip`). This avoids baking cosign into the image and keeps it in sync with the cluster's TAS version.

## Verifying Attestations

After an approval or rejection attestation has been created, you can verify and inspect it using cosign. Since we sign keylessly via Fulcio/Rekor (not with a static key), verification uses `--certificate-identity` and `--certificate-oidc-issuer` instead of `--key`.

### Verify the attestation signature

```bash
SUBDOMAIN=apps.cluster-gnpvw.dyn.redhatworkshops.io
IMAGE=quay.${SUBDOMAIN}/user1/parasol-insurance-secured

# Get the current digest
DIGEST=$(cosign triangulate ${IMAGE}:latest 2>/dev/null | head -1 | cut -d@ -f2)
# Or use a known digest directly:
# DIGEST=sha256:d127ab4cbf915d15a940154b6bd077b5f1ce00310055266e0b6ce48045d987e6

# Verify the release attestation (keyless — signed by user via Keycloak/Fulcio)
cosign verify-attestation \
  --type https://parasol-insurance.com/releases/v1 \
  --certificate-identity-regexp=".*@demo.redhat.com" \
  --certificate-oidc-issuer="https://sso.${SUBDOMAIN}/realms/sso" \
  --rekor-url="https://rekor-server-trusted-artifact-signer.${SUBDOMAIN}" \
  ${IMAGE}@${DIGEST}
```

You can also narrow verification to a specific user's attestations:

```bash
cosign verify-attestation \
  --type https://parasol-insurance.com/releases/v1 \
  --certificate-identity="user1@demo.redhat.com" \
  --certificate-oidc-issuer="https://sso.${SUBDOMAIN}/realms/sso" \
  --rekor-url="https://rekor-server-trusted-artifact-signer.${SUBDOMAIN}" \
  ${IMAGE}@${DIGEST}
```

### Inspect the attestation payload

```bash
cosign verify-attestation \
  --type https://parasol-insurance.com/releases/v1 \
  --certificate-identity-regexp=".*@demo.redhat.com" \
  --certificate-oidc-issuer="https://sso.${SUBDOMAIN}/realms/sso" \
  --rekor-url="https://rekor-server-trusted-artifact-signer.${SUBDOMAIN}" \
  ${IMAGE}@${DIGEST} | jq -r '.payload' | base64 -d | jq .
```

This outputs the full in-toto statement including the custom predicate:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://parasol-insurance.com/releases/v1",
  "subject": [{ "name": "quay.../parasol-insurance-secured", "digest": {"sha256": "..."} }],
  "predicate": {
    "release": {
      "approved": true,
      "decisionDate": "2026-10-09T14:30:00Z",
      "approver": "user1 Demo",
      "approverEmail": "user1@demo.redhat.com"
    },
    "documentation": [{ "reason": "<base64>", "docs": "<base64>", "filename": "evidence.pdf" }],
    "metadata": { ... }
  }
}
```

### Decode the reason text

```bash
cosign verify-attestation \
  --type https://parasol-insurance.com/releases/v1 \
  --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer="https://sso.${SUBDOMAIN}/realms/sso" \
  --rekor-url="https://rekor-server-trusted-artifact-signer.${SUBDOMAIN}" \
  ${IMAGE}@${DIGEST} \
  | jq -r '.payload' | base64 -d \
  | jq -r '.predicate.documentation[0].reason' | base64 -d
```

### Extract the attached documentation file

```bash
cosign verify-attestation \
  --type https://parasol-insurance.com/releases/v1 \
  --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer="https://sso.${SUBDOMAIN}/realms/sso" \
  --rekor-url="https://rekor-server-trusted-artifact-signer.${SUBDOMAIN}" \
  ${IMAGE}@${DIGEST} \
  | jq -r '.payload' | base64 -d \
  | jq -r '.predicate.documentation[0].docs' | base64 -d > output-file
```

### Both signing flows are keyless

Both Tekton Chains and the Release Approval app use keyless signing via the same Fulcio/Rekor (TAS) infrastructure. The difference is the identity:

| | Tekton Chains (pipeline attestations) | Release Approval (approval attestations) |
|---|---|---|
| **OIDC Issuer** | `https://kubernetes.default.svc` | `https://sso.SUBDOMAIN/realms/sso` |
| **Certificate Identity** | `https://kubernetes.io/namespaces/openshift-pipelines/serviceaccounts/tekton-chains-controller` | `user1@demo.redhat.com` (user's email) |
| **Identity type** | Kubernetes ServiceAccount | Keycloak user (email) |
| **Predicate type** | `https://slsa.dev/provenance/v0.2` | `https://parasol-insurance.com/releases/v1` |
| **Attestation format** | Legacy DSSE (layers on `.att` tag) | Legacy DSSE (layers on `.att` tag) — must match |
| **Verification** | `--certificate-oidc-issuer="https://kubernetes.default.svc"` | `--certificate-oidc-issuer="https://sso.SUBDOMAIN/realms/sso"` |

### Verifying Tekton Chains attestations (for comparison)

```bash
cosign verify-attestation \
  --type=slsaprovenance02 \
  --certificate-identity="https://kubernetes.io/namespaces/openshift-pipelines/serviceaccounts/tekton-chains-controller" \
  --certificate-oidc-issuer="https://kubernetes.default.svc" \
  --rekor-url="https://rekor-server-trusted-artifact-signer.${SUBDOMAIN}" \
  ${IMAGE}@${DIGEST} | jq -r '.payload' | base64 -d | jq .
```

## Debugging

All components emit structured log lines with component prefixes:
- `[main]` — startup, config, server lifecycle
- `[config]` — subdomain detection, env var loading
- `[auth]` — JWKS fetch, token validation
- `[quay]` — API calls, tag listing
- `[quay-poller]` — polling cycle, change detection, active tenants
- `[k8s]` — client init, deployment listing, Quay credential reads, subdomain detection
- `[k8s-watch]` — watch start/stop per tenant, events, reconnections
- `[cosign]` — initialize, attest (line-by-line stdout/stderr), verify, release status
- `[ws-hub]` — client connect/disconnect with tenant, active tenant list
- `[api]` — HTTP request handling, image ref resolution

Frontend console logs use `[auth]`, `[ws]`, `[app]`, `[attest]` prefixes.

## Known Considerations

1. **Audience mapper**: The Keycloak audience mapper for `trusted-artifact-signer` currently only adds the audience to access tokens (`id.token.claim: false`). If Fulcio rejects the ID token, update the mapper to include it in ID tokens too.

2. **Attestation format compatibility**: The `--new-bundle-format=false` and `--use-signing-config=false` flags are critical. Without them, cosign v3 uses the new Sigstore bundle format which replaces the entire `.att` manifest instead of appending a layer. This destroys existing Tekton Chains attestations. The legacy DSSE format appends as a new layer, preserving coexistence.

3. **Parallel attestations**: Each cosign attest runs as a separate subprocess with its own temp predicate file. The TUF root is initialized once and shared (read-only after init).

4. **Quay credentials**: Read at runtime from Kubernetes secrets. When a user triggers an attestation, the backend reads `quay-push-secret` from `<tenant>-secured-build` namespace, decodes the `.dockerconfigjson`, and passes credentials to cosign via `--registry-username`/`--registry-password`. The RBAC ClusterRole is scoped to only allow `get` on secrets named `quay-push-secret`.

5. **Multiple attestations**: An image may have many release attestations (multiple approvals/rejections over time). The verify logic parses all of them and picks the one with the latest `decisionDate`. The UI shows the latest status.

6. **Probe endpoints**: `/healthz` and `/api/config` are unauthenticated. All other `/api/*` endpoints require a valid Bearer token.

7. **Attestation size limit**: Rekor on this cluster has `maxRequestBodySize: 10MB` and `attestations.maxSize: 100KB`. Uploaded documentation files should stay under ~60KB (accounting for base64 overhead).

8. **Cluster subdomain**: Auto-detected from `ingresses.config.openshift.io/cluster` at startup. Override with `CLUSTER_SUBDOMAIN` env var for non-cluster usage.

9. **Demand-driven polling**: Quay polling and K8s watches only run for tenants with active WebSocket connections. When the last client for a tenant disconnects, its watch is stopped and polling skips that tenant. Scales to any number of tenants without wasted resources.
