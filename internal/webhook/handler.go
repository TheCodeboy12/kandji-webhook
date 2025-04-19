package webhook

import (
	"context"
	"encoding/json"
	"fmt"

	// *** Import path updated to use the correct module name ***
	"log/slog" // *** Use slog for logging ***
	"net/http"
	"os" // Need os package to access clientCACertFile global from main (workaround)
	"strings"
	"time"

	"github.com/TheCodeboy12/kandji-step-ca-webhook/internal/kandji" // Import internal kandji package
)

// StepWebhookRequest represents the JSON body sent by step-ca
type StepWebhookRequest struct {
	CSR         string   `json:"csr"`
	Type        string   `json:"type"`
	CommonName  string   `json:"commonName"`
	DNSNames    []string `json:"dnsNames"`
	IPAddresses []string `json:"ipAddresses"`
	URIs        []string `json:"uris"`
	Emails      []string `json:"emails"`
}

// Handler holds dependencies for the webhook handler
type Handler struct {
	kandjiAPIURL    string
	kandjiAPIKey    string
	identifierField string
	webhookSecret   string // Optional shared secret
}

// NewHandler creates a new webhook Handler with dependencies
func NewHandler(kandjiURL, kandjiKey, idField, secret string) *Handler {
	return &Handler{
		kandjiAPIURL:    kandjiURL,
		kandjiAPIKey:    kandjiKey,
		identifierField: idField,
		webhookSecret:   secret,
	}
}

// ServeHTTP implements the http.Handler interface
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Create logger with request context attributes
	requestLogger := slog.With(
		"method", r.Method,
		"path", r.URL.Path,
		"remote_addr", r.RemoteAddr,
	)
	requestLogger.Info("Received request") // Use slog

	// Log client cert info if present
	// Accessing global variable from main package - not ideal but works for this structure
	// A better approach involves passing the required config/state via the handler struct
	clientCACertFile := os.Getenv("CLIENT_CA_CERT_FILE") // Re-read env var here or pass via Handler struct
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		requestLogger.Info("Client certificate presented", "subject", r.TLS.PeerCertificates[0].Subject)
	} else if clientCACertFile != "" {
		requestLogger.Warn("mTLS configured but no peer certificate presented.") // Use slog
	}

	// Check Method
	if r.Method != http.MethodPost {
		requestLogger.Warn("Invalid method received", "method", r.Method) // Use slog
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Optional: Check Shared Secret
	if h.webhookSecret != "" {
		secretFromHeader := r.Header.Get("X-Step-Webhook-Secret") // Standard header, adjust if needed
		if secretFromHeader != h.webhookSecret {
			requestLogger.Warn("Invalid shared secret received") // Use slog
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		requestLogger.Info("Shared secret validated successfully.") // Use slog
	}

	// Decode Request Body
	var reqPayload StepWebhookRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&reqPayload); err != nil {
		requestLogger.Error("Error decoding request body", "error", err) // Use slog
		http.Error(w, "Bad request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Log decoded payload details (consider logging level - maybe Debug)
	requestLogger.Info("Decoded request payload", // Use slog
		"common_name", reqPayload.CommonName,
		"dns_sans", strings.Join(reqPayload.DNSNames, ","), // Join slices for logging
		"uri_sans", strings.Join(reqPayload.URIs, ","),
	)

	// Extract Device Identifier
	deviceID, err := h.extractDeviceIdentifier(reqPayload) // Call as method
	if err != nil {
		requestLogger.Error("Error extracting device identifier", "error", err) // Use slog
		SendResponseWithData(w, false, nil)                                     // Use exported function
		return
	}
	if deviceID == "" {
		requestLogger.Error("No suitable device identifier found in request") // Use slog
		SendResponseWithData(w, false, nil)                                   // Use exported function
		return
	}
	// Add deviceID to logger context for subsequent logs in this request
	requestLogger = requestLogger.With("device_id", deviceID, "identifier_field", h.identifierField)
	requestLogger.Info("Extracted device identifier") // Use slog

	// Check Kandji API
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Call Kandji check function from the kandji package, passing config
	found, err := kandji.CheckKandjiDevice(ctx, deviceID, h.kandjiAPIURL, h.kandjiAPIKey)
	if err != nil {
		// Error already logged within CheckKandjiDevice using slog
		requestLogger.Error("Kandji API check failed", "error", err) // Log context here too
		SendResponseWithData(w, false, nil)                          // Use exported function
		return
	}

	// --- Response Logic ---
	if found {
		requestLogger.Info("Device identifier FOUND in Kandji. Allowing and overriding subject.") // Use slog

		// Construct Subject Override Data
		newSubject := map[string]interface{}{
			"commonName":         fmt.Sprintf("kandji-device-%s", deviceID),
			"organization":       []string{"BizzaIT Managed Devices"},
			"organizationalUnit": []string{"Managed By Kandji"},
		}
		responseData := map[string]interface{}{
			"subject": newSubject,
		}
		SendResponseWithData(w, true, responseData) // Use exported function

	} else {
		requestLogger.Info("Device identifier NOT FOUND in Kandji. Denying.") // Use slog
		SendResponseWithData(w, false, nil)                                   // Use exported function
	}
}

// extractDeviceIdentifier extracts the identifier based on identifierField config
// Now a method of the Handler struct to access h.identifierField
func (h *Handler) extractDeviceIdentifier(payload StepWebhookRequest) (string, error) {
	// Using logger passed via context would be better, but sticking to default for now
	logger := slog.With("identifier_logic_field", h.identifierField) // Use slog
	switch strings.ToLower(h.identifierField) {
	case "cn":
		if payload.CommonName == "" {
			return "", fmt.Errorf("identifier field set to 'cn' but CommonName is empty")
		}
		logger.Debug("Using CommonName as identifier", "cn", payload.CommonName) // Use slog
		return payload.CommonName, nil
	case "san:dns":
		if len(payload.DNSNames) == 0 {
			return "", fmt.Errorf("identifier field set to 'san:dns' but DNSNames SAN is empty")
		}
		logger.Debug("Using first DNS SAN as identifier", "dns_san", payload.DNSNames[0]) // Use slog
		return payload.DNSNames[0], nil
	case "san:uri":
		if len(payload.URIs) == 0 {
			return "", fmt.Errorf("identifier field set to 'san:uri' but URIs SAN is empty")
		}
		logger.Debug("Using first URI SAN as identifier", "uri_san", payload.URIs[0]) // Use slog
		return payload.URIs[0], nil
	default:
		return "", fmt.Errorf("invalid or unsupported IDENTIFIER_FIELD: %s (use 'cn', 'san:dns', 'san:uri', etc.)", h.identifierField)
	}
}
