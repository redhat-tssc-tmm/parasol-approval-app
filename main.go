package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/parasol-insurance/parasol-approval-process/internal/api"
	"github.com/parasol-insurance/parasol-approval-process/internal/auth"
	"github.com/parasol-insurance/parasol-approval-process/internal/cosign"
	"github.com/parasol-insurance/parasol-approval-process/internal/k8s"
	"github.com/parasol-insurance/parasol-approval-process/internal/quay"
	"github.com/parasol-insurance/parasol-approval-process/internal/ws"
)

//go:embed frontend/dist/*
var frontendFS embed.FS

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	log.Println("[main] Parasol Approval Process starting...")

	k8sClient, err := k8s.NewClient()
	if err != nil {
		log.Fatalf("[main] Failed to create Kubernetes client: %v", err)
	}
	log.Println("[main] Kubernetes client initialized")

	cfg := loadConfig(k8sClient)
	log.Printf("[main] Config loaded: quayURL=%s keycloakURL=%s realm=%s", cfg.QuayURL, cfg.KeycloakURL, cfg.KeycloakRealm)
	log.Printf("[main] TUF mirror=%s fulcioURL=%s rekorURL=%s", cfg.TUFMirror, cfg.FulcioURL, cfg.RekorURL)

	authProvider, err := auth.New(cfg.KeycloakURL, cfg.KeycloakRealm, cfg.KeycloakClientID)
	if err != nil {
		log.Fatalf("[main] Failed to initialize auth provider: %v", err)
	}
	log.Println("[main] Auth provider initialized (JWKS fetched)")

	quayClient := quay.NewClient(cfg.QuayURL)
	log.Printf("[main] Quay client initialized: %s", cfg.QuayURL)

	cosignRunner := cosign.NewRunner(cosign.Config{
		CosignBin: cfg.CosignBin,
		FulcioURL: cfg.FulcioURL,
		RekorURL:  cfg.RekorURL,
		OIDCIssuer: cfg.OIDCIssuer,
		TUFMirror: cfg.TUFMirror,
	})
	log.Println("[main] Cosign runner initialized")

	if err := cosignRunner.Initialize(context.Background()); err != nil {
		log.Printf("[main] WARNING: cosign initialize failed (will retry on first attest): %v", err)
	} else {
		log.Println("[main] cosign TUF root initialized successfully")
	}

	hub := ws.NewHub()
	go hub.Run()
	log.Println("[main] WebSocket hub started")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher := k8s.NewDeploymentWatcher(k8sClient, hub)
	go watcher.Start(ctx)
	log.Println("[main] Deployment watcher started (demand-driven)")

	quayPoller := quay.NewPoller(quayClient, hub, 10*time.Second)
	go quayPoller.Start(ctx)
	log.Println("[main] Quay poller started (demand-driven, interval=10s)")

	handler := api.NewHandler(authProvider, quayClient, k8sClient, cosignRunner, hub)
	router := setupRouter(handler, authProvider, hub, cfg)

	port := envOrDefault("PORT", "8080")
	srv := &http.Server{Addr: ":" + port, Handler: router}
	log.Printf("[main] HTTP server starting on :%s", port)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[main] Server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("[main] Received signal %v, shutting down...", sig)

	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[main] Server forced shutdown: %v", err)
	}
	log.Println("[main] Server stopped")
}

func setupRouter(handler *api.Handler, authProvider *auth.Provider, hub *ws.Hub, cfg *Config) *gin.Engine {
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.DebugMode)
	}
	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	router.GET("/api/config", handler.GetConfig)
	router.GET("/healthz", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })

	apiGroup := router.Group("/api")
	apiGroup.Use(auth.Middleware(authProvider))
	{
		apiGroup.GET("/images/:user", handler.GetImages)
		apiGroup.GET("/deployments/:user", handler.GetDeployments)
		apiGroup.POST("/attest", handler.Attest)
		apiGroup.POST("/check-release-status", handler.CheckReleaseStatus)
		apiGroup.GET("/attestations/:user/:digest", handler.ListAttestations)
		apiGroup.GET("/attestations/:user/:digest/:index", handler.GetAttestationDetail)
	}

	router.GET("/ws", func(c *gin.Context) {
		hub.HandleWebSocket(c.Writer, c.Request)
	})

	distFS, err := fs.Sub(frontendFS, "frontend/dist")
	if err != nil {
		log.Printf("[main] WARNING: embedded frontend not found, serving API only: %v", err)
	} else {
		router.NoRoute(gin.WrapH(spaHandler(http.FS(distFS))))
		log.Println("[main] Serving embedded frontend from frontend/dist")
	}

	return router
}

func spaHandler(fsys http.FileSystem) http.Handler {
	fileServer := http.FileServer(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if _, err := fsys.Open(path); err != nil {
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

type Config struct {
	QuayURL          string
	KeycloakURL      string
	KeycloakRealm    string
	KeycloakClientID string
	FulcioURL        string
	RekorURL         string
	OIDCIssuer       string
	TUFMirror        string
	CosignBin        string
}

func loadConfig(k8sClient *k8s.Client) *Config {
	subdomain := os.Getenv("CLUSTER_SUBDOMAIN")
	if subdomain == "" {
		log.Println("[config] CLUSTER_SUBDOMAIN not set, auto-detecting from cluster...")
		detected, err := k8sClient.GetClusterSubdomain(context.Background())
		if err != nil {
			log.Fatalf("[config] Failed to auto-detect cluster subdomain: %v. Set CLUSTER_SUBDOMAIN env var for non-cluster usage.", err)
		}
		subdomain = detected
		log.Printf("[config] Auto-detected cluster subdomain: %s", subdomain)
	} else {
		log.Printf("[config] Using CLUSTER_SUBDOMAIN from env: %s", subdomain)
	}

	cfg := &Config{
		QuayURL:          fmt.Sprintf("https://quay.%s", subdomain),
		KeycloakURL:      fmt.Sprintf("https://sso.%s", subdomain),
		KeycloakRealm:    envOrDefault("KEYCLOAK_REALM", "sso"),
		KeycloakClientID: envOrDefault("KEYCLOAK_CLIENT_ID", "trusted-artifact-signer"),
		FulcioURL:        envOrDefault("FULCIO_URL", fmt.Sprintf("https://fulcio-server-trusted-artifact-signer.%s", subdomain)),
		RekorURL:         envOrDefault("REKOR_URL", fmt.Sprintf("https://rekor-server-trusted-artifact-signer.%s", subdomain)),
		OIDCIssuer:       envOrDefault("OIDC_ISSUER", fmt.Sprintf("https://sso.%s/realms/sso", subdomain)),
		TUFMirror:        envOrDefault("TUF_MIRROR", fmt.Sprintf("https://tuf-trusted-artifact-signer.%s", subdomain)),
		CosignBin:        envOrDefault("COSIGN_BIN", "/usr/local/bin/cosign"),
	}

	log.Println("[config] Quay credentials will be read from K8s secrets at runtime (<tenant>-secured-build/quay-push-secret)")

	return cfg
}

func envOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
