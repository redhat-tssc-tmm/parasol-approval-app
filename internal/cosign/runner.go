// Package cosign wraps the cosign CLI to create and verify attestations on container images.
//
// This package is the core of the attestation workflow. It handles:
//   - TUF initialization: setting up the trust root for the cluster's Trusted Artifact Signer (TAS)
//   - Attesting images: creating signed in-toto attestations with custom predicates using keyless signing
//   - Verifying attestations: checking existing release attestations on images
//   - Downloading attestations: retrieving all attestations from an image for inspection
//   - Certificate matching: correlating downloaded attestations with their signing certificates
//
// IMPORTANT: Attestation format compatibility
//
// Tekton Chains writes attestations in the "legacy DSSE" format — each attestation is a layer
// on the image's .att tag in the OCI registry. Cosign v3+ defaults to the "new Sigstore bundle"
// format, which REPLACES the entire .att manifest instead of appending a layer.
//
// To ensure our custom attestations coexist with Tekton Chains attestations, we must use:
//   --new-bundle-format=false    (write legacy DSSE layers, not Sigstore bundles)
//   --use-signing-config=false   (required when disabling new bundle format with TUF initialized)
//
// Without these flags, creating a new attestation destroys all existing Chains attestations
// (PipelineRun + TaskRun SLSA provenance), breaking EC/Conforma policy validation.
//
// Attestation storage: .att tag vs OCI referrers
//
// Cosign stores attestations in two possible locations:
//   1. .att tag (legacy): All attestations are layers in a single OCI manifest at the
//      sha256-<digest>.att tag. This is what Tekton Chains and EC/Conforma use.
//   2. OCI 1.1 Referrers API: Attestations stored as separate OCI artifacts linked via
//      the referrers API. EC/Conforma does NOT read from referrers — it only checks .att tags.
//
// We use .att tag storage exclusively to maintain compatibility with EC/Conforma validation.
package cosign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/parasol-insurance/parasol-approval-process/internal/quay"
)

// Config holds the endpoints for the cluster's Trusted Artifact Signer (TAS) deployment.
// These URLs are used for keyless signing via Fulcio (certificate authority) and Rekor
// (transparency log). TUFMirror provides the trust root for signature verification.
type Config struct {
	CosignBin  string // Path to the cosign binary (typically /shared/cosign from init container)
	FulcioURL  string // Fulcio CA endpoint — issues short-lived signing certificates
	RekorURL   string // Rekor transparency log endpoint — records all signing events
	OIDCIssuer string // OIDC issuer URL (Keycloak realm) — identifies the token issuer for Fulcio
	TUFMirror  string // TUF mirror URL — provides the trust root for the TAS deployment
}

type Runner struct {
	config      Config
	initialized bool // Whether cosign initialize has been run (TUF root cached)
	mu          sync.Mutex
}

// AttestRequest contains everything needed to create a signed attestation on an image.
type AttestRequest struct {
	ImageRef      string           `json:"imageRef"`      // Full image reference (e.g. quay.example.com/user1/app)
	Digest        string           `json:"digest"`        // Image digest (sha256:...)
	PredicateType string           `json:"predicateType"` // in-toto predicate type URI
	Predicate     interface{}      `json:"predicate"`     // The predicate content (will be JSON-serialized)
	IDToken       string           `json:"idToken"`       // Keycloak OIDC ID token — used as identity for Fulcio certificate
	QuayCreds     quay.Credentials `json:"quayCreds"`     // Registry credentials for pushing the attestation
}

type AttestResult struct {
	Success   bool   `json:"success"`
	TlogIndex string `json:"tlogIndex"` // Rekor transparency log entry index
	Message   string `json:"message"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
}

func NewRunner(config Config) *Runner {
	return &Runner{config: config}
}

// Initialize sets up the TUF trust root for the cluster's TAS deployment.
// This downloads and caches the root of trust from the TUF mirror, which contains
// the Fulcio root certificate, Rekor public key, and CTFE (Certificate Transparency
// Frontend) key. Must be run once before any verify operations.
//
// The TUF root is cached at $HOME/.sigstore/root/ — the deployment sets HOME=/tmp
// to ensure writability in the container.
//
// Note: After initialization, cosign verify-attestation uses the cached TUF root
// to resolve Fulcio/Rekor URLs automatically. However, cosign attest with
// --use-signing-config=false requires explicit URL flags (see Attest method).
func (r *Runner) Initialize(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.initialized {
		log.Println("[cosign] Already initialized, skipping")
		return nil
	}

	log.Printf("[cosign] Initializing TUF root: mirror=%s", r.config.TUFMirror)

	rootURL := r.config.TUFMirror + "/root.json"

	args := []string{
		"initialize",
		"--mirror=" + r.config.TUFMirror,
		"--root=" + rootURL,
	}

	log.Printf("[cosign] Running: %s %v", r.config.CosignBin, args)
	cmd := exec.CommandContext(ctx, r.config.CosignBin, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		log.Printf("[cosign] Initialize FAILED: err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
		return fmt.Errorf("cosign initialize failed: %w\nstderr: %s", err, stderr.String())
	}

	log.Printf("[cosign] Initialize SUCCESS: stdout=%s", stdout.String())
	r.initialized = true
	return nil
}

// Attest creates a signed in-toto attestation and attaches it to an image in the registry.
//
// Identity flow (keyless signing):
//   1. The user logs into Keycloak via the browser (OIDC authorization code flow with PKCE)
//   2. The frontend receives an ID token from Keycloak (contains the user's email, name, etc.)
//   3. The ID token is sent to this backend in the attestation request
//   4. cosign passes the ID token to Fulcio via --identity-token
//   5. Fulcio validates the token against the Keycloak OIDC issuer, then issues a short-lived
//      x509 certificate (valid ~10 minutes) with the user's email as the Subject Alternative Name
//   6. cosign signs the attestation with the ephemeral private key and the Fulcio certificate
//   7. The signing event is recorded in the Rekor transparency log
//   8. The signed attestation is pushed as a new layer on the image's .att tag in the registry
//
// Critical flags:
//   --new-bundle-format=false: Write legacy DSSE format (compatible with Tekton Chains).
//     Without this, cosign uses the new Sigstore bundle format which REPLACES the entire
//     .att manifest, destroying existing Chains attestations.
//   --use-signing-config=false: Required when --new-bundle-format=false is set and TUF
//     is initialized. The TUF signing config mandates the new bundle format, so we must
//     opt out and provide Fulcio/Rekor URLs explicitly.
//   -d: Verbose output, needed to capture the transparency log index from cosign's output.
func (r *Runner) Attest(ctx context.Context, req AttestRequest) (*AttestResult, error) {
	if err := r.Initialize(ctx); err != nil {
		return nil, fmt.Errorf("cosign not initialized: %w", err)
	}

	predicateFile, err := r.writePredicateFile(req.Predicate)
	if err != nil {
		return nil, fmt.Errorf("failed to write predicate: %w", err)
	}
	defer func() {
		os.Remove(predicateFile)
		log.Printf("[cosign] Cleaned up predicate file: %s", predicateFile)
	}()

	imageWithDigest := fmt.Sprintf("%s@%s", req.ImageRef, req.Digest)

	args := []string{
		"attest",
		"-d",
		// Legacy DSSE format — appends a layer to .att tag instead of replacing the manifest.
		// This is essential for coexistence with Tekton Chains attestations.
		"--new-bundle-format=false",
		// Disable TUF-based URL resolution since it requires the new bundle format.
		// We provide Fulcio/Rekor URLs explicitly instead.
		"--use-signing-config=false",
		"--fulcio-url=" + r.config.FulcioURL,
		"--rekor-url=" + r.config.RekorURL,
		// The user's Keycloak ID token — Fulcio uses this to issue a signing certificate
		// with the user's email as the certificate identity (SAN).
		"--identity-token=" + req.IDToken,
		"--type=" + req.PredicateType,
		"--predicate=" + predicateFile,
		"--yes",
	}

	// Registry credentials for pushing the attestation layer to Quay.
	// Passed per-invocation to avoid writing docker config files to disk.
	if req.QuayCreds.Username != "" {
		args = append(args, "--registry-username="+req.QuayCreds.Username)
		args = append(args, "--registry-password="+req.QuayCreds.Password)
	}

	args = append(args, imageWithDigest)

	log.Printf("[cosign] Running attest for image=%s predicateType=%s", imageWithDigest, req.PredicateType)
	log.Printf("[cosign] Command: %s %v", r.config.CosignBin, redactArgs(args))

	cmd := exec.CommandContext(ctx, r.config.CosignBin, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	startTime := time.Now()
	err = cmd.Run()
	duration := time.Since(startTime)

	result := &AttestResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if err != nil {
		log.Printf("[cosign] Attest FAILED (duration=%s): err=%v", duration, err)
		log.Printf("[cosign] Attest stdout: %s", stdout.String())
		log.Printf("[cosign] Attest stderr: %s", stderr.String())
		result.Success = false
		result.Message = fmt.Sprintf("cosign attest failed: %v\n%s", err, stderr.String())
		return result, nil
	}

	log.Printf("[cosign] Attest SUCCESS (duration=%s)", duration)
	for _, line := range splitLines(stdout.String()) {
		if strings.TrimSpace(line) != "" {
			log.Printf("[cosign] Attest stdout> %s", line)
		}
	}
	for _, line := range splitLines(stderr.String()) {
		if strings.TrimSpace(line) != "" {
			log.Printf("[cosign] Attest stderr> %s", line)
		}
	}

	allOutput := stderr.String() + "\n" + stdout.String()
	tlogIndex := extractTlogIndex(allOutput)
	result.Success = true
	result.TlogIndex = tlogIndex
	result.Message = fmt.Sprintf("Attestation successful. Transparency log index: %s", tlogIndex)

	return result, nil
}

func (r *Runner) writePredicateFile(predicate interface{}) (string, error) {
	data, err := json.MarshalIndent(predicate, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal predicate: %w", err)
	}

	tmpDir := os.TempDir()
	file, err := os.CreateTemp(tmpDir, "predicate-*.json")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}

	filePath := file.Name()
	log.Printf("[cosign] Writing predicate to %s (%d bytes)", filePath, len(data))

	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(filePath)
		return "", fmt.Errorf("failed to write predicate: %w", err)
	}

	file.Close()
	return filePath, nil
}

// ReleaseStatus represents the latest approval/rejection status for an image digest.
// Determined by verifying all release attestations and picking the one with the most
// recent decisionDate.
type ReleaseStatus struct {
	Digest       string `json:"digest"`
	Status       string `json:"status"` // "approved", "rejected", "none", "error"
	Approver     string `json:"approver,omitempty"`
	Date         string `json:"date,omitempty"`
	Reason       string `json:"reason,omitempty"`
	DocsFilename string `json:"docsFilename,omitempty"`
	DocsBase64   string `json:"docsBase64,omitempty"`
	Error        string `json:"error,omitempty"`
}

// VerifyReleaseAttestation checks whether an image has been approved or rejected by
// verifying all attestations matching our custom predicate type.
//
// Uses cosign verify-attestation which:
//   1. Downloads attestations from the image's .att tag
//   2. Filters by --type (our custom predicate URI)
//   3. Verifies each attestation's signature against the Fulcio certificate
//   4. Checks the certificate chain back to the TUF-provided root
//   5. Verifies the signing event exists in the Rekor transparency log
//
// We use broad identity/issuer regexps (.*) because attestations may be signed by
// any user in the Keycloak realm. The certificate identity and OIDC issuer are
// displayed in the UI for transparency, but not restricted here.
//
// Multiple attestations may exist (approvals and rejections over time). We parse all
// of them and return the one with the latest decisionDate as the current status.
func (r *Runner) VerifyReleaseAttestation(ctx context.Context, imageRef, digest string, creds quay.Credentials) ReleaseStatus {
	if err := r.Initialize(ctx); err != nil {
		return ReleaseStatus{Digest: digest, Status: "error", Error: fmt.Sprintf("cosign not initialized: %v", err)}
	}

	imageWithDigest := fmt.Sprintf("%s@%s", imageRef, digest)

	// verify-attestation uses the TUF root (from cosign initialize) to resolve Rekor URLs.
	// Unlike attest, verify does not conflict with TUF signing config.
	args := []string{
		"verify-attestation",
		"--type=https://parasol-insurance.com/releases/v1",
		// Broad regexps — accept any signer identity and OIDC issuer.
		// The actual identity is extracted from the predicate for display.
		"--certificate-identity-regexp=.*",
		"--certificate-oidc-issuer-regexp=.*",
	}

	if creds.Username != "" {
		args = append(args, "--registry-username="+creds.Username)
		args = append(args, "--registry-password="+creds.Password)
	}

	args = append(args, imageWithDigest)

	log.Printf("[cosign] Verifying release attestation for %s", imageWithDigest)

	cmd := exec.CommandContext(ctx, r.config.CosignBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	if err != nil {
		stderrStr := stderr.String()
		if strings.Contains(stderrStr, "no matching attestations") ||
			strings.Contains(stderrStr, "none of the attestations matched") {
			log.Printf("[cosign] No release attestation found for %s (duration=%s)", imageWithDigest, duration)
			return ReleaseStatus{Digest: digest, Status: "none"}
		}
		log.Printf("[cosign] Verify attestation FAILED for %s (duration=%s): %v stderr=%s", imageWithDigest, duration, err, stderrStr)
		return ReleaseStatus{Digest: digest, Status: "error", Error: stderrStr}
	}

	log.Printf("[cosign] Verify attestation SUCCESS for %s (duration=%s)", imageWithDigest, duration)

	// Parse all verified attestation envelopes and find the one with the latest decisionDate.
	// cosign outputs one JSON envelope per line to stdout.
	var latest ReleaseStatus
	var latestTime time.Time
	found := false

	for _, line := range splitLines(stdout.String()) {
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}

		// Each line is a DSSE envelope: {"payloadType":"...","payload":"<base64>","signatures":[...]}
		var envelope struct {
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			continue
		}

		// The payload is a base64-encoded in-toto statement containing our custom predicate
		payloadBytes, err := base64.StdEncoding.DecodeString(envelope.Payload)
		if err != nil {
			continue
		}

		var statement struct {
			Predicate struct {
				Release struct {
					Approved      bool   `json:"approved"`
					Approver      string `json:"approver"`
					ApproverEmail string `json:"approverEmail"`
					DecisionDate  string `json:"decisionDate"`
				} `json:"release"`
				Documentation []struct {
					Reason   string `json:"reason"`
					Docs     string `json:"docs"`
					Filename string `json:"filename"`
				} `json:"documentation"`
			} `json:"predicate"`
		}
		if err := json.Unmarshal(payloadBytes, &statement); err != nil {
			continue
		}

		status := "rejected"
		if statement.Predicate.Release.Approved {
			status = "approved"
		}

		var reasonText, docsFilename, docsBase64 string
		if len(statement.Predicate.Documentation) > 0 {
			doc := statement.Predicate.Documentation[0]
			if doc.Reason != "" {
				decoded, err := base64.StdEncoding.DecodeString(doc.Reason)
				if err == nil {
					reasonText = string(decoded)
				}
			}
			docsFilename = doc.Filename
			docsBase64 = doc.Docs
		}

		decisionTime, _ := time.Parse(time.RFC3339, statement.Predicate.Release.DecisionDate)
		log.Printf("[cosign] Release attestation for %s: %s by %s at %s",
			imageWithDigest, status, statement.Predicate.Release.Approver, statement.Predicate.Release.DecisionDate)

		// Keep the attestation with the latest decisionDate as the "current" status
		if !found || decisionTime.After(latestTime) {
			latest = ReleaseStatus{
				Digest:       digest,
				Status:       status,
				Approver:     statement.Predicate.Release.Approver,
				Date:         statement.Predicate.Release.DecisionDate,
				Reason:       reasonText,
				DocsFilename: docsFilename,
				DocsBase64:   docsBase64,
			}
			latestTime = decisionTime
			found = true
		}
	}

	if found {
		log.Printf("[cosign] Latest release attestation for %s: %s by %s at %s",
			imageWithDigest, latest.Status, latest.Approver, latest.Date)
		return latest
	}

	return ReleaseStatus{Digest: digest, Status: "none"}
}

func redactArgs(args []string) []string {
	redacted := make([]string, len(args))
	for i, a := range args {
		if len(a) > 16 && a[:16] == "--identity-token" {
			redacted[i] = "--identity-token=<REDACTED>"
		} else if len(a) > 21 && a[:21] == "--registry-password=" {
			redacted[i] = "--registry-password=<REDACTED>"
		} else {
			redacted[i] = a
		}
	}
	return redacted
}

// extractTlogIndex parses the Rekor transparency log entry index from cosign output.
// In verbose mode (-d), cosign outputs a JSON bundle containing the tlog entry with logIndex.
func extractTlogIndex(output string) string {
	for _, line := range splitLines(output) {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "logIndex") {
			continue
		}
		var bundle struct {
			VerificationMaterial struct {
				TlogEntries []struct {
					LogIndex string `json:"logIndex"`
				} `json:"tlogEntries"`
			} `json:"verificationMaterial"`
		}
		if err := json.Unmarshal([]byte(line), &bundle); err == nil {
			if len(bundle.VerificationMaterial.TlogEntries) > 0 {
				return bundle.VerificationMaterial.TlogEntries[0].LogIndex
			}
		}
	}

	prefix := "tlog entry created with index: "
	for _, line := range splitLines(output) {
		if idx := strings.Index(line, prefix); idx >= 0 {
			return strings.TrimSpace(line[idx+len(prefix):])
		}
	}
	return "unknown"
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// CertInfo contains details extracted from the Fulcio-issued signing certificate.
// These short-lived certificates (typically valid for ~10 minutes) are issued by
// Fulcio based on the signer's OIDC identity token.
type CertInfo struct {
	Identity   string `json:"identity,omitempty"`   // SAN: email (user) or URI (service account)
	Issuer     string `json:"issuer,omitempty"`     // Certificate issuer (e.g. "O=Parasol, CN=CISO-office")
	OIDCIssuer string `json:"oidcIssuer,omitempty"` // OIDC provider that issued the identity token (Fulcio extension OID 1.3.6.1.4.1.57264.1.1)
	ValidFrom  string `json:"validFrom,omitempty"`  // Certificate not-before time
	ValidTo    string `json:"validTo,omitempty"`     // Certificate not-after time
}

type AttestationSummary struct {
	Index         int       `json:"index"`
	PredicateType string    `json:"predicateType"`
	Date          string    `json:"date"`
	Signer        string    `json:"signer"`
	BuildType     string    `json:"buildType,omitempty"` // For SLSA attestations: tekton.dev/v1/PipelineRun or TaskRun
	Approved      *bool     `json:"approved,omitempty"`  // For release attestations: true/false
	Cert          *CertInfo `json:"cert,omitempty"`      // Signing certificate details (from OCI manifest annotations)
}

type AttestationDetail struct {
	Summary  AttestationSummary     `json:"summary"`
	Payload  map[string]interface{} `json:"payload"` // Full decoded in-toto statement with base64 values replaced by placeholders
}

// DownloadAttestations retrieves all attestations from an image's .att tag using
// "cosign download attestation". Unlike verify-attestation, this does not filter
// by predicate type — it returns ALL attestations (Chains SLSA + our custom ones).
//
// Certificate matching:
// The downloaded DSSE envelopes (legacy format) do not contain certificates inline.
// The certificates are stored as OCI manifest annotations on each layer. We match
// them by computing the sha256 digest of each downloaded envelope and looking it up
// in the manifest's layer digests (provided via layerCerts from the Quay API).
func (r *Runner) DownloadAttestations(ctx context.Context, imageRef, digest string, creds quay.Credentials, layerCerts []quay.LayerCertInfo) ([]AttestationSummary, []json.RawMessage, error) {
	imageWithDigest := fmt.Sprintf("%s@%s", imageRef, digest)

	args := []string{"download", "attestation"}
	if creds.Username != "" {
		args = append(args, "--registry-username="+creds.Username)
		args = append(args, "--registry-password="+creds.Password)
	}
	args = append(args, imageWithDigest)

	log.Printf("[cosign] Downloading attestations for %s", imageWithDigest)

	cmd := exec.CommandContext(ctx, r.config.CosignBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	startTime := time.Now()
	if err := cmd.Run(); err != nil {
		log.Printf("[cosign] Download attestations FAILED for %s (duration=%s): %v stderr=%s",
			imageWithDigest, time.Since(startTime), err, stderr.String())
		return nil, nil, fmt.Errorf("cosign download attestation failed: %w\n%s", err, stderr.String())
	}

	log.Printf("[cosign] Download attestations SUCCESS for %s (duration=%s)", imageWithDigest, time.Since(startTime))

	var summaries []AttestationSummary
	var rawEnvelopes []json.RawMessage
	envelopeIndex := 0

	// Each line from cosign download attestation is a DSSE envelope (legacy format):
	// {"payloadType":"application/vnd.in-toto+json","payload":"<base64>","signatures":[...]}
	for _, line := range splitLines(stdout.String()) {
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}

		currentLayerIdx := envelopeIndex
		envelopeIndex++

		var envelope struct {
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			log.Printf("[cosign] Failed to parse envelope %d: %v", currentLayerIdx, err)
			rawEnvelopes = append(rawEnvelopes, json.RawMessage(line))
			summaries = append(summaries, AttestationSummary{PredicateType: "unknown", Signer: "parse error"})
			continue
		}

		payloadBytes, err := base64.StdEncoding.DecodeString(envelope.Payload)
		if err != nil {
			log.Printf("[cosign] Failed to decode payload %d: %v", currentLayerIdx, err)
			rawEnvelopes = append(rawEnvelopes, json.RawMessage(line))
			summaries = append(summaries, AttestationSummary{PredicateType: "unknown", Signer: "decode error"})
			continue
		}

		rawEnvelopes = append(rawEnvelopes, json.RawMessage(line))

		var statement struct {
			PredicateType string                 `json:"predicateType"`
			Predicate     map[string]interface{} `json:"predicate"`
		}
		if err := json.Unmarshal(payloadBytes, &statement); err != nil {
			log.Printf("[cosign] Failed to parse statement %d: %v", currentLayerIdx, err)
			summaries = append(summaries, AttestationSummary{PredicateType: "unknown", Signer: "parse error"})
			continue
		}

		summary := AttestationSummary{
			Index:         len(summaries),
			PredicateType: statement.PredicateType,
		}

		extractSummaryFromPredicate(&summary, statement.Predicate, statement.PredicateType)

		summaries = append(summaries, summary)
		log.Printf("[cosign] Attestation %d: type=%s signer=%s date=%s",
			len(summaries)-1, summary.PredicateType, summary.Signer, summary.Date)
	}

	// Match certificates to attestations by digest (see matchCertsByDigest for details)
	matchCertsByDigest(summaries, rawEnvelopes, layerCerts)

	sortAttestationsByDate(summaries, rawEnvelopes)
	for i := range summaries {
		summaries[i].Index = i
	}

	log.Printf("[cosign] Downloaded %d attestations for %s", len(summaries), imageWithDigest)
	return summaries, rawEnvelopes, nil
}

// matchCertsByDigest correlates attestation envelopes with their signing certificates.
//
// The challenge: cosign download attestation outputs envelopes in a different order than
// the OCI manifest layers, so index-based matching fails. Instead, we compute the sha256
// hash of each raw envelope and match it against the layer digest in the OCI manifest.
//
// The certificates are stored as OCI annotations on each manifest layer:
//   - dev.sigstore.cosign/certificate: PEM-encoded Fulcio signing certificate
//   - dev.sigstore.cosign/chain: PEM-encoded certificate chain
//
// These annotations are fetched from the Quay registry API (see quay.GetAttestationManifestCerts).
func matchCertsByDigest(summaries []AttestationSummary, rawEnvelopes []json.RawMessage, layerCerts []quay.LayerCertInfo) {
	if len(layerCerts) == 0 {
		return
	}

	// Build a lookup map: layer digest → parsed certificate info
	certByDigest := make(map[string]*CertInfo)
	for _, lc := range layerCerts {
		if lc.Certificate == "" || lc.Digest == "" {
			continue
		}
		ci := parseCertPEM(lc.Certificate)
		if ci != nil {
			certByDigest[lc.Digest] = ci
		}
	}

	// For each downloaded envelope, compute its sha256 and look up the matching cert
	for i := range summaries {
		if i >= len(rawEnvelopes) {
			break
		}
		h := sha256.Sum256(rawEnvelopes[i])
		envelopeDigest := "sha256:" + hex.EncodeToString(h[:])

		if ci, ok := certByDigest[envelopeDigest]; ok {
			summaries[i].Cert = ci
			log.Printf("[cosign] Matched cert to attestation %d by digest: identity=%s", i, ci.Identity)
		} else {
			log.Printf("[cosign] No cert match for attestation %d (envelope digest=%s)", i, envelopeDigest[:30])
		}
	}
}

// parseCertPEM extracts identity and issuer information from a PEM-encoded x509 certificate.
// These are short-lived Fulcio certificates issued during keyless signing.
//
// Extracted fields:
//   - Identity: from the Subject Alternative Name (email for users, URI for service accounts)
//   - Issuer: the certificate issuer (the Fulcio CA, e.g. "O=Parasol, CN=CISO-office")
//   - OIDC Issuer: from the Fulcio-specific extension OID 1.3.6.1.4.1.57264.1.1
//     This identifies which OIDC provider authenticated the signer:
//     - https://sso.<subdomain>/realms/sso for Keycloak users
//     - https://kubernetes.default.svc for Tekton Chains (Kubernetes SA)
func parseCertPEM(certPEM string) *CertInfo {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("[cosign] Failed to parse certificate: %v", err)
		return nil
	}

	info := &CertInfo{
		Issuer:    cert.Issuer.String(),
		ValidFrom: cert.NotBefore.UTC().Format(time.RFC3339),
		ValidTo:   cert.NotAfter.UTC().Format(time.RFC3339),
	}

	if len(cert.EmailAddresses) > 0 {
		info.Identity = cert.EmailAddresses[0]
	} else if len(cert.URIs) > 0 {
		info.Identity = cert.URIs[0].String()
	}

	// Fulcio extension OID 1.3.6.1.4.1.57264.1.1 contains the OIDC issuer URL
	oidcIssuerOID := "1.3.6.1.4.1.57264.1.1"
	for _, ext := range cert.Extensions {
		if ext.Id.String() == oidcIssuerOID {
			issuerVal := string(ext.Value)
			if u, err := url.Parse(issuerVal); err == nil && u.Scheme != "" {
				info.OIDCIssuer = issuerVal
			} else {
				// The extension value may have ASN.1 encoding prefix bytes; scan for the URL
				for i := 0; i < len(issuerVal); i++ {
					if i+8 < len(issuerVal) && issuerVal[i:i+8] == "https://" {
						info.OIDCIssuer = issuerVal[i:]
						break
					}
					if i+7 < len(issuerVal) && issuerVal[i:i+7] == "http://" {
						info.OIDCIssuer = issuerVal[i:]
						break
					}
				}
			}
			break
		}
	}

	return info
}

// GetAttestationDetail decodes a raw DSSE envelope into a full in-toto statement
// for display in the attestation inspector UI. Large base64 values (>256 chars)
// are replaced with size placeholders to avoid sending megabytes to the frontend.
func (r *Runner) GetAttestationDetail(rawEnvelope json.RawMessage) (*AttestationDetail, error) {
	var envelope struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(rawEnvelope, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse envelope: %w", err)
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var fullPayload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &fullPayload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}

	replaceBase64Values(fullPayload)

	var statement struct {
		PredicateType string                 `json:"predicateType"`
		Predicate     map[string]interface{} `json:"predicate"`
	}
	json.Unmarshal(payloadBytes, &statement)

	summary := AttestationSummary{PredicateType: statement.PredicateType}
	extractSummaryFromPredicate(&summary, statement.Predicate, statement.PredicateType)

	return &AttestationDetail{
		Summary: summary,
		Payload: fullPayload,
	}, nil
}

// extractSummaryFromPredicate populates signer, date, and status fields from the
// predicate content based on the predicate type:
//   - Release attestations: signer from release.approver, date from release.decisionDate
//   - SLSA provenance (Tekton Chains): signer="Tekton Chains", date from metadata.buildFinishedOn
func extractSummaryFromPredicate(summary *AttestationSummary, predicate map[string]interface{}, predicateType string) {
	if strings.Contains(predicateType, "parasol-insurance.com/releases") {
		if release, ok := predicate["release"].(map[string]interface{}); ok {
			if approver, ok := release["approver"].(string); ok {
				summary.Signer = approver
			}
			if email, ok := release["approverEmail"].(string); ok {
				if summary.Signer == "" {
					summary.Signer = email
				}
			}
			if date, ok := release["decisionDate"].(string); ok {
				summary.Date = date
			}
			if approved, ok := release["approved"].(bool); ok {
				summary.Approved = &approved
			}
		}
	} else if strings.Contains(predicateType, "slsa.dev/provenance") {
		if bt, ok := predicate["buildType"].(string); ok {
			summary.BuildType = bt
			summary.Signer = "Tekton Chains"
		}
		if meta, ok := predicate["metadata"].(map[string]interface{}); ok {
			if t, ok := meta["buildFinishedOn"].(string); ok {
				summary.Date = t
			} else if t, ok := meta["buildStartedOn"].(string); ok {
				summary.Date = t
			}
		}
	} else {
		summary.Signer = "unknown"
	}
}

func sortAttestationsByDate(summaries []AttestationSummary, rawEnvelopes []json.RawMessage) {
	n := len(summaries)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			t1, _ := time.Parse(time.RFC3339, summaries[j].Date)
			t2, _ := time.Parse(time.RFC3339, summaries[j+1].Date)
			if t2.After(t1) {
				summaries[j], summaries[j+1] = summaries[j+1], summaries[j]
				rawEnvelopes[j], rawEnvelopes[j+1] = rawEnvelopes[j+1], rawEnvelopes[j]
			}
		}
	}
}

// replaceBase64Values recursively walks a JSON structure and replaces large base64-encoded
// strings with human-readable size placeholders. This prevents sending large binary data
// (e.g. uploaded documentation files) to the frontend for the attestation inspector view.
func replaceBase64Values(data map[string]interface{}) {
	for key, val := range data {
		switch v := val.(type) {
		case string:
			if len(v) > 256 && isLikelyBase64(v) {
				decoded, err := base64.StdEncoding.DecodeString(v)
				if err == nil {
					size := len(decoded)
					label := fmt.Sprintf("%d bytes", size)
					if size > 1024 {
						label = fmt.Sprintf("%.1f KB", float64(size)/1024)
					}
					if size > 1024*1024 {
						label = fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
					}
					data[key] = fmt.Sprintf("<base64 data, %s>", label)
				}
			}
		case map[string]interface{}:
			replaceBase64Values(v)
		case []interface{}:
			replaceBase64InArray(v)
		}
	}
}

func replaceBase64InArray(arr []interface{}) {
	for i, val := range arr {
		switch v := val.(type) {
		case string:
			if len(v) > 256 && isLikelyBase64(v) {
				decoded, err := base64.StdEncoding.DecodeString(v)
				if err == nil {
					size := len(decoded)
					label := fmt.Sprintf("%d bytes", size)
					if size > 1024 {
						label = fmt.Sprintf("%.1f KB", float64(size)/1024)
					}
					arr[i] = fmt.Sprintf("<base64 data, %s>", label)
				}
			}
		case map[string]interface{}:
			replaceBase64Values(v)
		case []interface{}:
			replaceBase64InArray(v)
		}
	}
}

func isLikelyBase64(s string) bool {
	if len(s) < 32 {
		return false
	}
	for i := 0; i < 64 && i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}
