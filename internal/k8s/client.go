package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/parasol-insurance/parasol-approval-process/internal/quay"
)

type Client struct {
	clientset  *kubernetes.Clientset
	restConfig *rest.Config
}

type DeploymentInfo struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Image     string `json:"image"`
	Tag       string `json:"tag"`
	Digest    string `json:"digest"`
	Ready     bool   `json:"ready"`
	Replicas  int32  `json:"replicas"`
	Available int32  `json:"available"`
}

func NewClient() (*Client, error) {
	log.Println("[k8s] Creating Kubernetes client...")

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Printf("[k8s] Not running in-cluster, trying kubeconfig: %v", err)
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		configOverrides := &clientcmd.ConfigOverrides{}
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
		config, err = kubeConfig.ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create k8s config: %w", err)
		}
		log.Println("[k8s] Using kubeconfig")
	} else {
		log.Println("[k8s] Using in-cluster config")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s clientset: %w", err)
	}

	version, err := clientset.Discovery().ServerVersion()
	if err != nil {
		log.Printf("[k8s] WARNING: Could not get server version: %v", err)
	} else {
		log.Printf("[k8s] Connected to Kubernetes %s", version.GitVersion)
	}

	return &Client{clientset: clientset, restConfig: config}, nil
}

func (c *Client) Clientset() *kubernetes.Clientset {
	return c.clientset
}

func (c *Client) GetDeployments(ctx context.Context, namespace string) ([]DeploymentInfo, error) {
	log.Printf("[k8s] Listing deployments in namespace=%s", namespace)

	deployments, err := c.clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Printf("[k8s] ERROR listing deployments in %s: %v", namespace, err)
		return nil, fmt.Errorf("failed to list deployments: %w", err)
	}

	var result []DeploymentInfo
	for _, d := range deployments.Items {
		info := deploymentToInfo(&d)
		result = append(result, info)
		log.Printf("[k8s] Deployment: %s/%s image=%s tag=%s digest=%s ready=%v",
			namespace, info.Name, info.Image, info.Tag, info.Digest, info.Ready)
	}

	log.Printf("[k8s] Found %d deployments in %s", len(result), namespace)
	return result, nil
}

func (c *Client) GetClusterSubdomain(ctx context.Context) (string, error) {
	log.Println("[k8s] Auto-detecting cluster subdomain from ingresses.config.openshift.io/cluster")

	data, err := c.clientset.RESTClient().Get().
		AbsPath("/apis/config.openshift.io/v1/ingresses/cluster").
		DoRaw(ctx)
	if err != nil {
		log.Printf("[k8s] ERROR reading ingresses.config.openshift.io/cluster: %v", err)
		return "", fmt.Errorf("failed to read cluster ingress config: %w", err)
	}

	var ingress struct {
		Spec struct {
			Domain string `json:"domain"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(data, &ingress); err != nil {
		return "", fmt.Errorf("failed to parse ingress config: %w", err)
	}

	if ingress.Spec.Domain == "" {
		return "", fmt.Errorf("ingress config has empty spec.domain")
	}

	log.Printf("[k8s] Detected cluster subdomain: %s", ingress.Spec.Domain)
	return ingress.Spec.Domain, nil
}

func (c *Client) GetQuayCredentials(ctx context.Context, tenant string) (quay.Credentials, error) {
	namespace := fmt.Sprintf("%s-secured-build", tenant)
	secretName := "quay-push-secret"
	log.Printf("[k8s] Reading secret %s/%s for tenant %s", namespace, secretName, tenant)

	secret, err := c.clientset.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		log.Printf("[k8s] ERROR reading secret %s/%s: %v", namespace, secretName, err)
		return quay.Credentials{}, fmt.Errorf("failed to read quay-push-secret in %s: %w", namespace, err)
	}

	dockerConfigJSON, ok := secret.Data[".dockerconfigjson"]
	if !ok {
		return quay.Credentials{}, fmt.Errorf("secret %s/%s missing .dockerconfigjson key", namespace, secretName)
	}

	var dockerConfig struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(dockerConfigJSON, &dockerConfig); err != nil {
		return quay.Credentials{}, fmt.Errorf("failed to parse dockerconfigjson: %w", err)
	}

	for registry, authEntry := range dockerConfig.Auths {
		decoded, err := base64.StdEncoding.DecodeString(authEntry.Auth)
		if err != nil {
			log.Printf("[k8s] WARNING: failed to decode auth for registry %s: %v", registry, err)
			continue
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			log.Printf("[k8s] WARNING: unexpected auth format for registry %s", registry)
			continue
		}
		creds := quay.Credentials{Username: parts[0], Password: parts[1]}
		log.Printf("[k8s] Got Quay credentials for tenant %s: registry=%s username=%s", tenant, registry, creds.Username)
		return creds, nil
	}

	return quay.Credentials{}, fmt.Errorf("no auth entries found in %s/%s", namespace, secretName)
}

func deploymentToInfo(d *appsv1.Deployment) DeploymentInfo {
	info := DeploymentInfo{
		Name:      d.Name,
		Namespace: d.Namespace,
		Ready:     d.Status.ReadyReplicas > 0,
		Replicas:  d.Status.Replicas,
		Available: d.Status.AvailableReplicas,
	}

	if len(d.Spec.Template.Spec.Containers) > 0 {
		image := d.Spec.Template.Spec.Containers[0].Image
		info.Image = image

		if atIdx := strings.Index(image, "@"); atIdx != -1 {
			info.Digest = image[atIdx+1:]
			imageBase := image[:atIdx]
			if colonIdx := strings.LastIndex(imageBase, ":"); colonIdx != -1 {
				info.Tag = imageBase[colonIdx+1:]
			}
		} else if colonIdx := strings.LastIndex(image, ":"); colonIdx != -1 {
			afterColon := image[colonIdx+1:]
			if !strings.Contains(afterColon, "/") {
				info.Tag = afterColon
			}
		}
	}

	return info
}
