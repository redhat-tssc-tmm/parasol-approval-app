# Parasol Release Approval Process

A web application for approving or rejecting container image releases in the Parasol Insurance secured software supply chain. Users authenticate via Keycloak, review images deployed to pre-production, and create cryptographically signed attestations that are attached to the container image in Quay.

## Key Features

- **Keycloak SSO authentication** — users log in with their existing identity
- **Live image and deployment tracking** — real-time updates via WebSocket when new images appear or deployments change
- **Release approval/rejection workflow** — submit a reason and optional documentation, creating a signed in-toto attestation
- **Keyless signing via Trusted Artifact Signer** — attestations are signed with the user's Keycloak identity through Fulcio, with every signing event recorded in the Rekor transparency log
- **Attestation inspector** — browse all attestations on an image (Tekton Chains SLSA provenance + release approvals), view signing certificates, and explore the full predicate structure
- **Coexistence with Tekton Chains** — uses legacy DSSE format to append attestations alongside existing pipeline provenance without overwriting
- **Dark/light mode** — PatternFly 6 theme toggle

## Quick Start

```bash
# Build container (no local toolchain needed)
podman build -t parasol-approval:latest -f Containerfile .

# Or build locally (requires Go 1.22+ and Node 20+)
cd frontend && npm install --legacy-peer-deps && npm run build && cd ..
go build -o parasol-approval-process .
COSIGN_BIN=$(which cosign) ./parasol-approval-process
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for full details on:

- Authentication and identity flow (dual-token pattern)
- Cosign attestation commands and flags
- Attestation storage (.att tag vs OCI referrers) and EC/Conforma compatibility
- Custom predicate format
- Real-time update mechanism
- Deployment manifests and RBAC
- Verifying and inspecting attestations from the CLI
