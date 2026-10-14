package quay

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

type Credentials struct {
	Username string
	Password string
}

type Repository struct {
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	Description string `json:"description"`
}

type Tag struct {
	Name           string `json:"name"`
	ManifestDigest string `json:"manifest_digest"`
	LastModified   string `json:"last_modified"`
	Size           int64  `json:"size"`
	IsManifestList bool   `json:"is_manifest_list"`
}

type ImageInfo struct {
	Repository string `json:"repository"`
	Namespace  string `json:"namespace"`
	Tags       []Tag  `json:"tags"`
}

type repoListResponse struct {
	Repositories []Repository `json:"repositories"`
}

type tagListResponse struct {
	Tags          []Tag `json:"tags"`
	HasAdditional bool  `json:"has_additional"`
	Page          int   `json:"page"`
}

func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (c *Client) BaseURL() string {
	return c.baseURL
}

func (c *Client) ListRepositories(namespace string) ([]Repository, error) {
	url := fmt.Sprintf("%s/api/v1/repository?namespace=%s&public=true", c.baseURL, namespace)
	log.Printf("[quay] Listing repositories for namespace=%s url=%s", namespace, url)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		log.Printf("[quay] ERROR listing repos for %s: %v", namespace, err)
		return nil, fmt.Errorf("failed to list repos: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[quay] ERROR listing repos for %s: status=%d", namespace, resp.StatusCode)
		return nil, fmt.Errorf("quay returned status %d", resp.StatusCode)
	}

	var result repoListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode repo list: %w", err)
	}

	log.Printf("[quay] Found %d repositories for namespace=%s", len(result.Repositories), namespace)
	return result.Repositories, nil
}

func (c *Client) ListTags(namespace, repo string) ([]Tag, error) {
	url := fmt.Sprintf("%s/api/v1/repository/%s/%s/tag/?limit=50&onlyActiveTags=true", c.baseURL, namespace, repo)
	log.Printf("[quay] Listing tags for %s/%s url=%s", namespace, repo, url)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		log.Printf("[quay] ERROR listing tags for %s/%s: %v", namespace, repo, err)
		return nil, fmt.Errorf("failed to list tags: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[quay] ERROR listing tags for %s/%s: status=%d", namespace, repo, resp.StatusCode)
		return nil, fmt.Errorf("quay returned status %d", resp.StatusCode)
	}

	var result tagListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode tag list: %w", err)
	}

	var filtered []Tag
	for _, t := range result.Tags {
		if !isArtifactTag(t.Name) {
			filtered = append(filtered, t)
		}
	}

	log.Printf("[quay] Found %d tags (%d after filtering artifacts) for %s/%s", len(result.Tags), len(filtered), namespace, repo)
	return filtered, nil
}

func (c *Client) GetImageInfo(namespace, repo string) (*ImageInfo, error) {
	tags, err := c.ListTags(namespace, repo)
	if err != nil {
		return nil, err
	}

	return &ImageInfo{
		Repository: repo,
		Namespace:  namespace,
		Tags:       tags,
	}, nil
}

type LayerCertInfo struct {
	Digest      string `json:"digest"`
	Certificate string `json:"certificate"`
	Chain       string `json:"chain"`
}

type AttManifest struct {
	Layers []LayerCertInfo
}

func (c *Client) GetAttestationManifestCerts(namespace, repo, imageDigest string) ([]LayerCertInfo, error) {
	attTag := "sha256-" + imageDigest[7:] + ".att"
	url := fmt.Sprintf("%s/v2/%s/%s/manifests/%s", c.baseURL, namespace, repo, attTag)
	log.Printf("[quay] Fetching .att manifest for %s/%s tag=%s", namespace, repo, attTag)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("[quay] ERROR fetching .att manifest: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[quay] .att manifest returned status %d", resp.StatusCode)
		return nil, fmt.Errorf("att manifest returned status %d", resp.StatusCode)
	}

	var manifest struct {
		Layers []struct {
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"layers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("failed to decode att manifest: %w", err)
	}

	var certs []LayerCertInfo
	for _, layer := range manifest.Layers {
		cert := layer.Annotations["dev.sigstore.cosign/certificate"]
		chain := layer.Annotations["dev.sigstore.cosign/chain"]
		certs = append(certs, LayerCertInfo{Digest: layer.Digest, Certificate: cert, Chain: chain})
	}

	log.Printf("[quay] Found %d layers with cert info in .att manifest", len(certs))
	return certs, nil
}

func isArtifactTag(name string) bool {
	for _, suffix := range []string{".sig", ".att", ".sbom"} {
		if len(name) > len(suffix) && name[len(name)-len(suffix):] == suffix {
			return true
		}
	}
	if len(name) > 7 && name[:7] == "sha256-" {
		return true
	}
	return false
}
