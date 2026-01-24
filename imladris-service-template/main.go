// Imladris Service Template - Go HTTP Server
// Zero Trust Banking Service Template

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Configuration
type Config struct {
	Port        int    `json:"port"`
	MetricsPort int    `json:"metrics_port"`
	LogLevel    string `json:"log_level"`
	LogFormat   string `json:"log_format"`
	ServiceName string `json:"service_name"`
	Environment string `json:"environment"`
	AWSRegion   string `json:"aws_region"`
}

// Application structure
type App struct {
	Config  Config
	Server  *http.Server
	Metrics *http.Server
}

// Health check response
type HealthResponse struct {
	Status      string            `json:"status"`
	Version     string            `json:"version"`
	ServiceName string            `json:"service_name"`
	Environment string            `json:"environment"`
	Timestamp   time.Time         `json:"timestamp"`
	Checks      map[string]string `json:"checks"`
}

// Business logic response
type AccountResponse struct {
	AccountID   string  `json:"account_id"`
	Balance     float64 `json:"balance"`
	Currency    string  `json:"currency"`
	Status      string  `json:"status"`
	LastUpdated time.Time `json:"last_updated"`
}

// Prometheus metrics
var (
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status_code"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "http_request_duration_seconds",
			Help: "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)

	businessOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "business_operations_total",
			Help: "Total number of business operations",
		},
		[]string{"operation", "status"},
	)
)

// Load configuration from environment variables
func loadConfig() Config {
	port, _ := strconv.Atoi(getEnv("PORT", "8080"))
	metricsPort, _ := strconv.Atoi(getEnv("METRICS_PORT", "9090"))

	return Config{
		Port:        port,
		MetricsPort: metricsPort,
		LogLevel:    getEnv("LOG_LEVEL", "info"),
		LogFormat:   getEnv("LOG_FORMAT", "json"),
		ServiceName: getEnv("SERVICE_NAME", "banking-core-service"),
		Environment: getEnv("ENVIRONMENT", "dev"),
		AWSRegion:   getEnv("AWS_REGION", "us-east-1"),
	}
}

// Get environment variable with default
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Middleware for metrics collection
func metricsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap ResponseWriter to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}

		// Process request
		next.ServeHTTP(wrapped, r)

		// Record metrics
		duration := time.Since(start).Seconds()
		statusCode := strconv.Itoa(wrapped.statusCode)

		httpRequestsTotal.WithLabelValues(r.Method, r.URL.Path, statusCode).Inc()
		httpRequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
	}
}

// ResponseWriter wrapper to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Health check handler
func (app *App) healthHandler(w http.ResponseWriter, r *http.Request) {
	checks := make(map[string]string)
	checks["database"] = "ok"  // Simulate database check
	checks["vpc_lattice"] = "ok" // Simulate VPC Lattice check
	checks["aws_services"] = "ok" // Simulate AWS services check

	response := HealthResponse{
		Status:      "healthy",
		Version:     "1.0.0",
		ServiceName: app.Config.ServiceName,
		Environment: app.Config.Environment,
		Timestamp:   time.Now().UTC(),
		Checks:      checks,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Printf("Health check requested from %s", r.RemoteAddr)
}

// Readiness check handler
func (app *App) readyHandler(w http.ResponseWriter, r *http.Request) {
	// Simplified readiness check
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ready",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// Account handler - example business logic
func (app *App) accountHandler(w http.ResponseWriter, r *http.Request) {
	// Extract account ID from URL path
	accountID := r.URL.Query().Get("account_id")
	if accountID == "" {
		accountID = "ACC-123456789"
	}

	// Simulate business logic
	response := AccountResponse{
		AccountID:   accountID,
		Balance:     15000.50,
		Currency:    "USD",
		Status:      "active",
		LastUpdated: time.Now().UTC(),
	}

	// Record business metrics
	businessOperationsTotal.WithLabelValues("get_account", "success").Inc()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Printf("Account request for %s from %s", accountID, r.RemoteAddr)
}

// VPC Lattice service discovery handler
func (app *App) serviceDiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	services := map[string]interface{}{
		"service_name": app.Config.ServiceName,
		"environment": app.Config.Environment,
		"vpc_lattice_network": fmt.Sprintf("imladris-%s-lattice", app.Config.Environment),
		"endpoints": map[string]string{
			"health": "/health",
			"ready": "/ready",
			"accounts": "/api/v1/accounts",
			"metrics": fmt.Sprintf(":%d/metrics", app.Config.MetricsPort),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(services)
}

// Initialize HTTP server
func (app *App) initServer() {
	mux := http.NewServeMux()

	// Health endpoints
	mux.HandleFunc("/health", metricsMiddleware(app.healthHandler))
	mux.HandleFunc("/ready", metricsMiddleware(app.readyHandler))

	// Business endpoints
	mux.HandleFunc("/api/v1/accounts", metricsMiddleware(app.accountHandler))

	// Service discovery
	mux.HandleFunc("/.well-known/service", metricsMiddleware(app.serviceDiscoveryHandler))

	// Root handler
	mux.HandleFunc("/", metricsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Imladris Banking Service - %s\n", app.Config.Environment)
		fmt.Fprintf(w, "Service: %s\n", app.Config.ServiceName)
		fmt.Fprintf(w, "Version: 1.0.0\n")
	}))

	app.Server = &http.Server{
		Addr:         fmt.Sprintf(":%d", app.Config.Port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// Initialize metrics server
func (app *App) initMetricsServer() {
	app.Metrics = &http.Server{
		Addr:    fmt.Sprintf(":%d", app.Config.MetricsPort),
		Handler: promhttp.Handler(),
	}
}

// Start the application
func (app *App) start() error {
	// Start metrics server
	go func() {
		log.Printf("Starting metrics server on port %d", app.Config.MetricsPort)
		if err := app.Metrics.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Metrics server failed: %v", err)
		}
	}()

	// Start main server
	log.Printf("Starting %s on port %d", app.Config.ServiceName, app.Config.Port)
	log.Printf("Environment: %s", app.Config.Environment)
	log.Printf("AWS Region: %s", app.Config.AWSRegion)

	return app.Server.ListenAndServe()
}

// Graceful shutdown
func (app *App) shutdown(ctx context.Context) error {
	log.Println("Shutting down servers...")

	// Shutdown main server
	if err := app.Server.Shutdown(ctx); err != nil {
		return err
	}

	// Shutdown metrics server
	if err := app.Metrics.Shutdown(ctx); err != nil {
		return err
	}

	return nil
}

func main() {
	// Load configuration
	config := loadConfig()

	// Create application
	app := &App{Config: config}

	// Initialize servers
	app.initServer()
	app.initMetricsServer()

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Received shutdown signal")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := app.shutdown(ctx); err != nil {
			log.Printf("Shutdown error: %v", err)
		}

		log.Println("Application stopped")
		os.Exit(0)
	}()

	// Start the application
	if err := app.start(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
}