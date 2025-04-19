package main

import (
	"crypto/tls"
	"crypto/x509"

	// *** Import path updated to use the correct module name ***
	"log/slog" // *** Use slog for logging ***
	"net/http"
	"os"

	webhook "github.com/TheCodeboy12/kandji-step-ca-webhook/internal/webhook"
	// Import internal webhook package
	_ "github.com/joho/godotenv/autoload"
)

// --- Configuration ---
// Read configuration from environment variables
// These remain global in main for setting up dependencies
var (
	kandjiAPIURL     = os.Getenv("KANDJI_API_URL")
	kandjiAPIKey     = os.Getenv("KANDJI_API_KEY")
	listenAddr       = os.Getenv("WEBHOOK_LISTEN_ADDR")
	webhookSecret    = os.Getenv("WEBHOOK_SHARED_SECRET") // Optional
	identifierField  = os.Getenv("IDENTIFIER_FIELD")
	webhookCertFile  = os.Getenv("WEBHOOK_CERT_FILE")
	webhookKeyFile   = os.Getenv("WEBHOOK_KEY_FILE")
	clientCACertFile = os.Getenv("CLIENT_CA_CERT_FILE")
)

func main() {

	// --- slog Logger Setup ---
	// Use JSON handler writing to Stdout. GCP Cloud Logging parses this automatically.
	// Adjust level if needed (e.g., slog.LevelDebug)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger) // Set as default for convenience

	// --- Configuration Validation ---
	if listenAddr == "" {
		listenAddr = ":8443" // Default TLS port
		slog.Warn("WEBHOOK_LISTEN_ADDR not set, defaulting", "address", listenAddr)
	}
	// Use slog.Error and os.Exit for fatal configuration errors
	if kandjiAPIURL == "" || kandjiAPIKey == "" {
		slog.Error("KANDJI_API_URL and KANDJI_API_KEY environment variables must be set.")
		os.Exit(1)
	}
	if identifierField == "" {
		identifierField = "cn" // Default identifier field
		slog.Info("IDENTIFIER_FIELD not set, defaulting", "field", identifierField)
	}
	if webhookCertFile == "" || webhookKeyFile == "" {
		slog.Error("WEBHOOK_CERT_FILE and WEBHOOK_KEY_FILE environment variables must be set for HTTPS/mTLS.")
		os.Exit(1)
	}
	if clientCACertFile == "" {
		slog.Error("CLIENT_CA_CERT_FILE environment variable must be set for mTLS.")
		os.Exit(1)
	}
	if webhookSecret == "" {
		slog.Warn("WEBHOOK_SHARED_SECRET is not set. Consider using it for layered security with mTLS.")
	}

	slog.Info("Starting Kandji Webhook Server for Step CA",
		"address", listenAddr,
		"mtls_enabled", true,
		"subject_override_enabled", true,
	)
	slog.Info("Configuration loaded",
		"kandji_api_url", kandjiAPIURL,
		"identifier_field", identifierField,
		"webhook_cert_file", webhookCertFile,
		"webhook_key_file", "[REDACTED]", // Don't log key file path directly if sensitive
		"client_ca_cert_file", clientCACertFile,
	)

	// --- mTLS Configuration ---
	caCert, err := os.ReadFile(clientCACertFile)
	if err != nil {
		slog.Error("Error reading client CA certificate file", "path", clientCACertFile, "error", err)
		os.Exit(1)
	}
	clientCAPool := x509.NewCertPool()
	if ok := clientCAPool.AppendCertsFromPEM(caCert); !ok {
		slog.Error("Failed to append client CA certificate", "path", clientCACertFile)
		os.Exit(1)
	}
	tlsConfig := &tls.Config{
		ClientCAs:  clientCAPool,
		ClientAuth: tls.RequireAndVerifyClientCert, // Require and verify client certs
		MinVersion: tls.VersionTLS12,               // Example: Enforce minimum TLS version
	}

	// --- Server Setup ---

	// Create handler instance, passing dependencies (config)
	// Pass the logger instance to the handler if needed, or use the default logger
	webhookHandler := webhook.NewHandler(
		kandjiAPIURL,
		kandjiAPIKey,
		identifierField,
		webhookSecret,
	)

	// Create a mux and register handler
	mux := http.NewServeMux()
	mux.Handle("/webhook", webhookHandler) // Use Handle for http.Handler interface

	// Create a Server instance to apply TLS configuration
	server := &http.Server{
		Addr:      listenAddr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	slog.Info("Server listening", "address", listenAddr)
	// Start the HTTPS server with mTLS
	err = server.ListenAndServeTLS(webhookCertFile, webhookKeyFile)
	if err != nil {
		// Use slog for the final fatal error
		slog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}
