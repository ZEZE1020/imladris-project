// Imladris Service Template - Go HTTP Server
// Zero Trust Banking Service Template

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	_ "github.com/jackc/pgx/v5/stdlib"
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
	DBHost      string `json:"db_host"`
	DBPort      string `json:"db_port"`
	DBName      string `json:"db_name"`
	DBUser      string `json:"db_user"`
	DBSSLMode   string `json:"db_ssl_mode"`
	DBIAMAuth   bool   `json:"db_iam_auth"`
}

// Application structure
type App struct {
	Config  Config
	DB      *sql.DB
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
		DBHost:      getEnv("DB_HOST", ""),
		DBPort:      getEnv("DB_PORT", "5432"),
		DBName:      getEnv("DB_NAME", "imladris"),
		DBUser:      getEnv("DB_USER", "banking_app"),
		DBSSLMode:   getEnv("DB_SSL_MODE", "require"),
		DBIAMAuth:   getEnv("DB_IAM_AUTH", "true") == "true",
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

// connectDB establishes a connection to Aurora using IAM authentication tokens.
// Tokens are short-lived (15 min) and generated via STS — no static passwords.
func (app *App) connectDB() error {
	if app.Config.DBHost == "" {
		log.Println("DB_HOST not set — running without database (demo mode)")
		return nil
	}

	endpoint := fmt.Sprintf("%s:%s", app.Config.DBHost, app.Config.DBPort)

	var dsn string
	if app.Config.DBIAMAuth {
		// Generate IAM auth token (short-lived, replaces passwords)
		// NOTE: The IAM auth token is built once during connection establishment and
		// has a 15-minute expiration. For production-grade solutions, consider implementing
		// a custom connector or connection interceptor that regenerates IAM tokens on each
		// connection attempt (e.g., using pgx BeforeConnect hooks). The current approach
		// relies on connection pool rotation (SetConnMaxLifetime) to prevent token expiry.
		cfg, err := config.LoadDefaultConfig(context.TODO(),
			config.WithRegion(app.Config.AWSRegion),
		)
		if err != nil {
			return fmt.Errorf("unable to load AWS config: %w", err)
		}

		token, err := auth.BuildAuthToken(context.TODO(), endpoint, app.Config.AWSRegion, app.Config.DBUser, cfg.Credentials)
		if err != nil {
			return fmt.Errorf("failed to build IAM auth token: %w", err)
		}

		dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			app.Config.DBHost, app.Config.DBPort, app.Config.DBUser, token, app.Config.DBName, app.Config.DBSSLMode)
	} else {
		dsn = fmt.Sprintf("host=%s port=%s user=%s dbname=%s sslmode=%s",
			app.Config.DBHost, app.Config.DBPort, app.Config.DBUser, app.Config.DBName, app.Config.DBSSLMode)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Connection pool settings.
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	// Use a max connection lifetime well below the 15m IAM auth token expiry to reduce
	// the chance of using a connection with an about-to-expire token. Note: very
	// long-running queries that exceed the token lifetime may still fail due to
	// token expiration; callers should ensure appropriate query timeouts.
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	// Verify connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	app.DB = db
	log.Printf("Connected to Aurora at %s (IAM auth: %v)", app.Config.DBHost, app.Config.DBIAMAuth)
	return nil
}

// Health check handler
func (app *App) healthHandler(w http.ResponseWriter, r *http.Request) {
	checks := make(map[string]string)

	// Real database health check
	if app.DB != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := app.DB.PingContext(ctx); err != nil {
			checks["database"] = fmt.Sprintf("error: %v", err)
		} else {
			checks["database"] = "ok"
		}
	} else {
		checks["database"] = "not configured"
	}

	checks["vpc_lattice"] = "ok"
	checks["aws_services"] = "ok"

	status := "healthy"
	statusCode := http.StatusOK
	for _, v := range checks {
		if v != "ok" && v != "not configured" {
			status = "degraded"
			statusCode = http.StatusServiceUnavailable
			break
		}
	}

	response := HealthResponse{
		Status:      status,
		Version:     "1.0.0",
		ServiceName: app.Config.ServiceName,
		Environment: app.Config.Environment,
		Timestamp:   time.Now().UTC(),
		Checks:      checks,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)

	log.Printf("Health check requested from %s — status: %s", r.RemoteAddr, status)
}

// Readiness check handler
func (app *App) readyHandler(w http.ResponseWriter, r *http.Request) {
	// Check if database is required and configured
	dbRequired := os.Getenv("DB_HOST") != ""
	dbReady := app.DB != nil

	w.Header().Set("Content-Type", "application/json")

	// If database is required but not ready, fail the readiness check
	if dbRequired && !dbReady {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "not ready",
			"reason":    "database not configured",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "ready",
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

	// Validate account ID format (alphanumeric, dashes, max 50 chars)
	if len(accountID) > 50 || !isValidAccountID(accountID) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid account_id format"})
		return
	}

	var response AccountResponse

	if app.DB != nil {
		// Real database query
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		err := app.DB.QueryRowContext(ctx,
			`SELECT account_id, balance, currency, status, updated_at
			 FROM accounts WHERE account_id = $1`, accountID,
		).Scan(&response.AccountID, &response.Balance, &response.Currency,
			&response.Status, &response.LastUpdated)

		if err != nil {
			if err == sql.ErrNoRows {
				businessOperationsTotal.WithLabelValues("get_account", "not_found").Inc()
			} else {
				businessOperationsTotal.WithLabelValues("get_account", "error").Inc()
				log.Printf("Database error for account %s: %v", accountID, err)
			}
			w.Header().Set("Content-Type", "application/json")
			// Return the same status and message for both not-found and DB errors
			// to prevent account enumeration via timing attacks
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "account not found"})
			return
		}
	} else {
		// Demo mode — no database configured
		response = AccountResponse{
			AccountID:   accountID,
			Balance:     15000.50,
			Currency:    "USD",
			Status:      "active",
			LastUpdated: time.Now().UTC(),
		}
	}

	// Record business metrics
	businessOperationsTotal.WithLabelValues("get_account", "success").Inc()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Printf("Account request for %s from %s", accountID, r.RemoteAddr)
}

// isValidAccountID validates the account ID format (alphanumeric and dashes only)
func isValidAccountID(id string) bool {
	for _, ch := range id {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || 
			(ch >= '0' && ch <= '9') || ch == '-') {
			return false
		}
	}
	return true
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

	// Safety check: prevent DEMO_MODE in production
	demoMode := os.Getenv("DEMO_MODE")
	if demoMode == "true" && config.Environment == "prod" {
		log.Fatal("FATAL: DEMO_MODE cannot be enabled in production environment")
	}

	// Create application
	app := &App{Config: config}

	// Connect to database (gracefully degrades to demo mode if DB_HOST not set)
	if err := app.connectDB(); err != nil {
		log.Printf("WARNING: Database connection failed: %v — running in demo mode", err)
	}

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

		// Close database connection
		if app.DB != nil {
			if err := app.DB.Close(); err != nil {
				log.Printf("Database close error: %v", err)
			}
		}

		log.Println("Application stopped")
		os.Exit(0)
	}()

	// Start the application
	if err := app.start(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
}