package quay

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/parasol-insurance/parasol-approval-process/internal/ws"
)

type Poller struct {
	client   *Client
	hub      *ws.Hub
	interval time.Duration
	cache    map[string]string
	mu       sync.Mutex
}

func NewPoller(client *Client, hub *ws.Hub, interval time.Duration) *Poller {
	return &Poller{
		client:   client,
		hub:      hub,
		interval: interval,
		cache:    make(map[string]string),
	}
}

func (p *Poller) Start(ctx context.Context) {
	log.Printf("[quay-poller] Starting poller (interval=%s, demand-driven by active WebSocket tenants)", p.interval)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[quay-poller] Stopping")
			return
		case <-ticker.C:
			tenants := p.hub.ActiveTenants()
			if len(tenants) == 0 {
				continue
			}
			log.Printf("[quay-poller] Polling for %d active tenant(s): %v", len(tenants), tenants)
			for _, tenant := range tenants {
				p.pollTenant(tenant)
			}
		}
	}
}

func (p *Poller) pollTenant(tenant string) {
	namespace := tenant
	repos, err := p.client.ListRepositories(namespace)
	if err != nil {
		log.Printf("[quay-poller] ERROR polling tenant %s: %v", tenant, err)
		return
	}

	for _, repo := range repos {
		if isArtifactTag(repo.Name) {
			continue
		}
		tags, err := p.client.ListTags(namespace, repo.Name)
		if err != nil {
			log.Printf("[quay-poller] ERROR polling tags for %s/%s: %v", namespace, repo.Name, err)
			continue
		}

		info := &ImageInfo{
			Repository: repo.Name,
			Namespace:  namespace,
			Tags:       tags,
		}

		data, _ := json.Marshal(info)
		cacheKey := namespace + "/" + repo.Name
		dataStr := string(data)

		p.mu.Lock()
		changed := p.cache[cacheKey] != dataStr
		if changed {
			p.cache[cacheKey] = dataStr
		}
		p.mu.Unlock()

		if changed {
			log.Printf("[quay-poller] Change detected for %s/%s, broadcasting", namespace, repo.Name)
			p.hub.Broadcast(ws.Message{
				Type: "images_update",
				Data: map[string]interface{}{
					"tenant":     tenant,
					"repository": repo.Name,
					"namespace":  namespace,
					"tags":       tags,
				},
			})
		}
	}
}
