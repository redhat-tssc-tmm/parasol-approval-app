package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/parasol-insurance/parasol-approval-process/internal/ws"
)

type DeploymentWatcher struct {
	client  *Client
	hub     *ws.Hub
	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

func NewDeploymentWatcher(client *Client, hub *ws.Hub) *DeploymentWatcher {
	return &DeploymentWatcher{
		client:  client,
		hub:     hub,
		cancels: make(map[string]context.CancelFunc),
	}
}

func (w *DeploymentWatcher) Start(ctx context.Context) {
	w.hub.OnTenantChange(func(activeTenants []string) {
		w.reconcile(ctx, activeTenants)
	})
	log.Println("[k8s-watch] Watcher started (demand-driven by active WebSocket tenants)")
}

func (w *DeploymentWatcher) reconcile(parentCtx context.Context, activeTenants []string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	active := make(map[string]bool, len(activeTenants))
	for _, t := range activeTenants {
		active[t] = true
	}

	for tenant, cancel := range w.cancels {
		if !active[tenant] {
			log.Printf("[k8s-watch] Stopping watch for tenant %s (no active clients)", tenant)
			cancel()
			delete(w.cancels, tenant)
		}
	}

	for _, tenant := range activeTenants {
		if _, exists := w.cancels[tenant]; !exists {
			namespace := fmt.Sprintf("%s-preprod", tenant)
			ctx, cancel := context.WithCancel(parentCtx)
			w.cancels[tenant] = cancel
			go w.watchNamespace(ctx, tenant, namespace)
			log.Printf("[k8s-watch] Started watch for tenant %s (namespace=%s)", tenant, namespace)
		}
	}
}

func (w *DeploymentWatcher) watchNamespace(ctx context.Context, tenant, namespace string) {
	for {
		if err := w.doWatch(ctx, tenant, namespace); err != nil {
			if ctx.Err() != nil {
				log.Printf("[k8s-watch] Watch stopped for %s", namespace)
				return
			}
			log.Printf("[k8s-watch] Watch error for %s: %v, reconnecting in 5s...", namespace, err)
			time.Sleep(5 * time.Second)
		}
	}
}

func (w *DeploymentWatcher) doWatch(ctx context.Context, tenant, namespace string) error {
	watcher, err := w.client.clientset.AppsV1().Deployments(namespace).Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to start watch: %w", err)
	}
	defer watcher.Stop()

	log.Printf("[k8s-watch] Watch established for namespace=%s", namespace)

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return fmt.Errorf("watch channel closed")
			}

			if event.Type == watch.Error {
				log.Printf("[k8s-watch] Watch error event for %s: %v", namespace, event.Object)
				continue
			}

			deployment, ok := event.Object.(*appsv1.Deployment)
			if !ok {
				continue
			}

			info := deploymentToInfo(deployment)
			data, _ := json.Marshal(info)
			log.Printf("[k8s-watch] Event %s for %s/%s: %s", event.Type, namespace, deployment.Name, string(data))

			w.hub.Broadcast(ws.Message{
				Type: "deployment_update",
				Data: map[string]interface{}{
					"tenant":     tenant,
					"event":      string(event.Type),
					"deployment": info,
				},
			})
		}
	}
}
