// Package api provides the HTTP handlers for the Parasol Approval Process application.
//
// This package wires together authentication, registry access, Kubernetes API calls,
// and cosign operations into a REST API consumed by the React frontend.
//
// Key endpoints:
//
//   POST /api/attest — Creates a signed release attestation on an image.
//     The frontend sends the user's Keycloak ID token, which is forwarded to cosign
//     as the signing identity. See the Attest handler for the full identity flow.
//
//   POST /api/check-release-status — Triggers async verification of release attestations.
//     Results are pushed to the frontend via WebSocket as they complete (one per digest).
//
//   GET /api/attestations/:user/:digest — Lists all attestations on an image with
//     certificate details extracted from the OCI manifest layer annotations.
//
//   GET /api/attestations/:user/:digest/:index — Returns the full decoded payload
//     of a specific attestation for the inspector view (with base64 placeholders).
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/parasol-insurance/parasol-approval-process/internal/auth"
	cosignpkg "github.com/parasol-insurance/parasol-approval-process/internal/cosign"
	"github.com/parasol-insurance/parasol-approval-process/internal/k8s"
	"github.com/parasol-insurance/parasol-approval-process/internal/quay"
	"github.com/parasol-insurance/parasol-approval-process/internal/ws"
)

// attestationCache holds downloaded raw DSSE envelopes so the detail endpoint can
// serve individual attestations without re-downloading from the registry.
type attestationCache struct {
	rawEnvelopes []json.RawMessage
	expiry       time.Time
}

type Handler struct {
	auth       *auth.Provider
	quay       *quay.Client
	k8s        *k8s.Client
	cosign     *cosignpkg.Runner
	hub        *ws.Hub
	attCache   map[string]*attestationCache // keyed by "user/digest"
	attCacheMu sync.RWMutex
}

func NewHandler(authProvider *auth.Provider, quayClient *quay.Client, k8sClient *k8s.Client, cosignRunner *cosignpkg.Runner, hub *ws.Hub) *Handler {
	return &Handler{
		auth:     authProvider,
		quay:     quayClient,
		k8s:      k8sClient,
		cosign:   cosignRunner,
		hub:      hub,
		attCache: make(map[string]*attestationCache),
	}
}

// GetImages returns all image repositories and their tags from the user's Quay organization.
func (h *Handler) GetImages(c *gin.Context) {
	user := c.Param("user")
	log.Printf("[api] GET /api/images/%s", user)

	repos, err := h.quay.ListRepositories(user)
	if err != nil {
		log.Printf("[api] ERROR listing repos for %s: %v", user, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var images []quay.ImageInfo
	for _, repo := range repos {
		info, err := h.quay.GetImageInfo(user, repo.Name)
		if err != nil {
			log.Printf("[api] WARNING: failed to get image info for %s/%s: %v", user, repo.Name, err)
			continue
		}
		images = append(images, *info)
	}

	log.Printf("[api] Returning %d images for user=%s", len(images), user)
	c.JSON(http.StatusOK, images)
}

// GetDeployments returns all deployments in the user's preprod namespace.
func (h *Handler) GetDeployments(c *gin.Context) {
	user := c.Param("user")
	namespace := fmt.Sprintf("%s-preprod", user)
	log.Printf("[api] GET /api/deployments/%s (namespace=%s)", user, namespace)

	deployments, err := h.k8s.GetDeployments(c.Request.Context(), namespace)
	if err != nil {
		log.Printf("[api] ERROR listing deployments for %s: %v", namespace, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[api] Returning %d deployments for user=%s", len(deployments), user)
	c.JSON(http.StatusOK, deployments)
}

type AttestRequestBody struct {
	ImageRef string `json:"imageRef" binding:"required"`
	Digest   string `json:"digest" binding:"required"`
	Approved bool   `json:"approved"`
	Reason   string `json:"reason" binding:"required"`
	IDToken  string `json:"idToken" binding:"required"`
}

// Attest creates a signed release approval/rejection attestation on a container image.
//
// Identity flow (end-to-end):
//
//  1. User authenticates via Keycloak in the browser → receives access_token + id_token
//  2. Frontend sends BOTH tokens to this endpoint:
//     - access_token: in the Authorization header (validated by auth middleware)
//     - id_token: in the form body as "idToken" (passed through to cosign, NOT validated here)
//  3. This handler builds the custom predicate (release approval/rejection with reason + docs)
//  4. Quay registry credentials are read from the user's Kubernetes secret
//     (<user>-secured-build/quay-push-secret) — NOT from environment variables
//  5. cosign attest is invoked with:
//     - The user's id_token as --identity-token (Fulcio issues a cert with the user's email)
//     - --new-bundle-format=false (legacy DSSE format for Tekton Chains compatibility)
//     - --registry-username/--registry-password for Quay push access
//  6. On success, a WebSocket broadcast notifies connected clients of the new attestation
//
// The predicate is an in-toto statement with type "https://parasol-insurance.com/releases/v1"
// containing the approval decision, approver identity, reason (base64), and optional
// documentation file (base64 with original filename preserved).
func (h *Handler) Attest(c *gin.Context) {
	// The user identity comes from the validated access_token (via auth middleware).
	// This tells us WHO is making the request (for predicate fields and Quay cred lookup).
	userInfo := auth.GetUser(c)
	if userInfo == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no user context"})
		return
	}

	log.Printf("[api] POST /api/attest from user=%s", userInfo.Username)

	if err := c.Request.ParseMultipartForm(32 << 20); err != nil {
		log.Printf("[api] ERROR parsing multipart form: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse form data"})
		return
	}

	imageRef := c.PostForm("imageRef")
	digest := c.PostForm("digest")
	approved := c.PostForm("approved") == "true"
	reason := c.PostForm("reason")

	// The ID token from Keycloak — this is the SIGNING IDENTITY.
	// It is NOT the same as the access token used for API authentication.
	// This token is passed directly to cosign's --identity-token flag, which forwards
	// it to Fulcio. Fulcio validates the token against the Keycloak OIDC issuer and
	// issues a short-lived x509 certificate with the user's email in the SAN.
	// The attestation is then signed with the corresponding ephemeral private key.
	idToken := c.PostForm("idToken")

	if imageRef == "" || digest == "" || reason == "" || idToken == "" {
		log.Printf("[api] ERROR: missing required fields imageRef=%v digest=%v reason=%v idToken=%v",
			imageRef != "", digest != "", reason != "", idToken != "")
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing required fields: imageRef, digest, reason, idToken"})
		return
	}

	log.Printf("[api] Attest request: image=%s digest=%s approved=%v user=%s",
		imageRef, digest, approved, userInfo.Username)

	// Handle optional documentation file upload
	var docsBase64 string
	var docsFilename string
	file, header, err := c.Request.FormFile("documentation")
	if err == nil {
		defer file.Close()
		docsFilename = header.Filename
		log.Printf("[api] Documentation file uploaded: name=%s size=%d", header.Filename, header.Size)
		fileBytes, err := io.ReadAll(file)
		if err != nil {
			log.Printf("[api] ERROR reading uploaded file: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read uploaded file"})
			return
		}
		docsBase64 = base64.StdEncoding.EncodeToString(fileBytes)
	} else {
		log.Printf("[api] No documentation file uploaded")
	}

	// Build the custom predicate — this becomes the signed content of the attestation.
	// The reason and documentation are base64-encoded within the predicate itself
	// (they are stored as-is in the signed in-toto statement).
	reasonBase64 := base64.StdEncoding.EncodeToString([]byte(reason))

	decision := "rejected"
	if approved {
		decision = "approved"
	}

	predicate := map[string]interface{}{
		"release": map[string]interface{}{
			"approved":      approved,
			"decisionDate":  time.Now().UTC().Format(time.RFC3339),
			"approver":      fmt.Sprintf("%s %s", userInfo.FirstName, userInfo.LastName),
			"approverEmail": userInfo.Email,
		},
		"documentation": []map[string]interface{}{
			{
				"reason":   reasonBase64,
				"docs":     docsBase64,
				"filename": docsFilename,
			},
		},
		"metadata": map[string]interface{}{
			"processVersion":      "1.0",
			"complianceFramework": "Parasol Release Policy",
			"notes":               fmt.Sprintf("Release %s process completed", decision),
		},
	}

	log.Printf("[api] Built predicate: approved=%v approver=%s %s <%s>",
		approved, userInfo.FirstName, userInfo.LastName, userInfo.Email)

	// Read Quay push credentials from the user's Kubernetes secret at runtime.
	// The secret is in the <user>-secured-build namespace (e.g. user1-secured-build/quay-push-secret).
	// This avoids hardcoding credentials in environment variables and ensures each user
	// pushes attestations using their own Quay identity.
	quayCreds, err := h.k8s.GetQuayCredentials(c.Request.Context(), userInfo.Username)
	if err != nil {
		log.Printf("[api] ERROR fetching Quay credentials for %s: %v", userInfo.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to get Quay credentials: %v", err)})
		return
	}
	log.Printf("[api] Using Quay credentials for user=%s (username=%s)", userInfo.Username, quayCreds.Username)

	attestReq := cosignpkg.AttestRequest{
		ImageRef:      imageRef,
		Digest:        digest,
		PredicateType: "https://parasol-insurance.com/releases/v1",
		Predicate:     predicate,
		IDToken:       idToken, // Forwarded to cosign → Fulcio for signing certificate issuance
		QuayCreds:     quayCreds,
	}

	result, err := h.cosign.Attest(c.Request.Context(), attestReq)
	if err != nil {
		log.Printf("[api] ERROR cosign attest failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[api] Attest result: success=%v tlogIndex=%s message=%s", result.Success, result.TlogIndex, result.Message)

	// Broadcast the attestation event to all connected WebSocket clients.
	// The frontend uses this to refresh the release status column and show a toast notification.
	if result.Success {
		h.hub.Broadcast(ws.Message{
			Type: "attestation_created",
			Data: map[string]interface{}{
				"tenant":    userInfo.Username,
				"imageRef":  imageRef,
				"digest":    digest,
				"approved":  approved,
				"tlogIndex": result.TlogIndex,
			},
		})
	}

	status := http.StatusOK
	if !result.Success {
		status = http.StatusInternalServerError
	}

	c.JSON(status, result)
}

type CheckReleaseRequest struct {
	ImageRef string   `json:"imageRef"` // May be relative (user/repo) — resolved to full registry ref
	Digests  []string `json:"digests"`  // Image digests to check for release attestations
}

// CheckReleaseStatus triggers asynchronous verification of release attestations for
// one or more image digests. Results are pushed to the frontend via WebSocket as each
// verification completes (one "release_status" message per digest).
//
// This async pattern avoids blocking the HTTP request while cosign runs verification
// (which takes ~1 second per digest). The frontend shows a spinner per image tag
// until the WebSocket message arrives with the result.
func (h *Handler) CheckReleaseStatus(c *gin.Context) {
	userInfo := auth.GetUser(c)
	if userInfo == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no user context"})
		return
	}

	var req CheckReleaseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// The frontend may send a relative image ref (e.g. "user1/parasol-insurance-secured")
	// without the registry hostname. We resolve it by prepending the Quay hostname from config.
	// A ref containing a dot is assumed to already include a registry hostname.
	imageRef := req.ImageRef
	if !strings.Contains(imageRef, ".") {
		quayHost := strings.TrimPrefix(strings.TrimPrefix(h.quay.BaseURL(), "https://"), "http://")
		imageRef = quayHost + "/" + imageRef
		log.Printf("[api] Resolved image ref to %s", imageRef)
	}

	log.Printf("[api] POST /api/check-release-status from user=%s image=%s digests=%d",
		userInfo.Username, imageRef, len(req.Digests))

	quayCreds, err := h.k8s.GetQuayCredentials(c.Request.Context(), userInfo.Username)
	if err != nil {
		log.Printf("[api] WARNING: Could not get Quay creds for release check: %v", err)
	}

	// Launch a goroutine per digest — each runs cosign verify-attestation independently.
	// Results are pushed to the WebSocket hub as they complete.
	for _, digest := range req.Digests {
		go func(d string) {
			status := h.cosign.VerifyReleaseAttestation(
				context.Background(), imageRef, d, quayCreds,
			)
			h.hub.Broadcast(ws.Message{
				Type: "release_status",
				Data: map[string]interface{}{
					"tenant":       userInfo.Username,
					"imageRef":     req.ImageRef,
					"digest":       d,
					"status":       status.Status,
					"approver":     status.Approver,
					"date":         status.Date,
					"reason":       status.Reason,
					"docsFilename": status.DocsFilename,
					"docsBase64":   status.DocsBase64,
					"error":        status.Error,
				},
			})
		}(digest)
	}

	c.JSON(http.StatusAccepted, gin.H{"message": fmt.Sprintf("Checking %d digests", len(req.Digests))})
}

// ListAttestations downloads all attestations from an image's .att tag and returns
// summaries with signing certificate details.
//
// This endpoint:
//  1. Fetches the .att tag's OCI manifest from Quay to get layer-level certificate annotations
//  2. Runs "cosign download attestation" to get all DSSE envelopes (all predicate types)
//  3. Matches certificates to envelopes by computing the sha256 of each envelope and
//     looking it up in the manifest's layer digests (see cosign.matchCertsByDigest)
//  4. Caches the raw envelopes (5-minute TTL) for the detail endpoint
//  5. Returns summaries sorted by date (newest first)
func (h *Handler) ListAttestations(c *gin.Context) {
	userInfo := auth.GetUser(c)
	if userInfo == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no user context"})
		return
	}

	user := c.Param("user")
	digest := c.Param("digest")
	log.Printf("[api] GET /api/attestations/%s/%s from user=%s", user, digest, userInfo.Username)

	quayHost := strings.TrimPrefix(strings.TrimPrefix(h.quay.BaseURL(), "https://"), "http://")
	imageRef := fmt.Sprintf("%s/%s/parasol-insurance-secured", quayHost, user)

	quayCreds, err := h.k8s.GetQuayCredentials(c.Request.Context(), user)
	if err != nil {
		log.Printf("[api] WARNING: Could not get Quay creds: %v", err)
	}

	// Fetch signing certificates from the OCI manifest layer annotations.
	// Each layer in the .att manifest has annotations containing the PEM-encoded
	// Fulcio certificate used to sign that attestation layer.
	layerCerts, err := h.quay.GetAttestationManifestCerts(user, "parasol-insurance-secured", digest)
	if err != nil {
		log.Printf("[api] WARNING: Could not fetch cert info from .att manifest: %v", err)
	}

	summaries, rawEnvelopes, err := h.cosign.DownloadAttestations(c.Request.Context(), imageRef, digest, quayCreds, layerCerts)
	if err != nil {
		log.Printf("[api] ERROR downloading attestations: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Cache the raw envelopes so GetAttestationDetail can serve individual
	// attestations without re-downloading from the registry.
	cacheKey := user + "/" + digest
	h.attCacheMu.Lock()
	h.attCache[cacheKey] = &attestationCache{
		rawEnvelopes: rawEnvelopes,
		expiry:       time.Now().Add(5 * time.Minute),
	}
	h.attCacheMu.Unlock()

	log.Printf("[api] Returning %d attestation summaries for %s@%s", len(summaries), user, digest[:16])
	c.JSON(http.StatusOK, summaries)
}

// GetAttestationDetail returns the full decoded in-toto statement for a specific
// attestation, identified by its index in the sorted list from ListAttestations.
// Large base64 values are replaced with size placeholders to avoid sending megabytes
// of binary data to the frontend inspector view.
//
// Requires ListAttestations to have been called first (populates the cache).
func (h *Handler) GetAttestationDetail(c *gin.Context) {
	userInfo := auth.GetUser(c)
	if userInfo == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no user context"})
		return
	}

	user := c.Param("user")
	digest := c.Param("digest")
	indexStr := c.Param("index")
	index, err := strconv.Atoi(indexStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid index"})
		return
	}

	log.Printf("[api] GET /api/attestations/%s/%s/%d from user=%s", user, digest, index, userInfo.Username)

	cacheKey := user + "/" + digest
	h.attCacheMu.RLock()
	cached, ok := h.attCache[cacheKey]
	h.attCacheMu.RUnlock()

	if !ok || time.Now().After(cached.expiry) {
		c.JSON(http.StatusNotFound, gin.H{"error": "attestation data not cached, please list attestations first"})
		return
	}

	if index < 0 || index >= len(cached.rawEnvelopes) {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("index %d out of range (0-%d)", index, len(cached.rawEnvelopes)-1)})
		return
	}

	detail, err := h.cosign.GetAttestationDetail(cached.rawEnvelopes[index])
	if err != nil {
		log.Printf("[api] ERROR parsing attestation detail: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	detail.Summary.Index = index
	log.Printf("[api] Returning attestation detail %d for %s@%s", index, user, digest[:16])
	c.JSON(http.StatusOK, detail)
}

// GetConfig returns public configuration for the frontend (unauthenticated).
// The frontend uses this to initialize the Keycloak JS adapter with the correct
// issuer URL and client ID before any authentication has occurred.
func (h *Handler) GetConfig(c *gin.Context) {
	log.Printf("[api] GET /api/config")
	c.JSON(http.StatusOK, gin.H{
		"keycloakURL":      h.auth.IssuerURL(),
		"keycloakClientID": h.auth.ClientID(),
		"quayURL":          h.quay.BaseURL(),
	})
}
