package webhook

import (
	"encoding/json"
	"log/slog" // *** Use slog for logging ***
	"net/http"
)

// StepWebhookResponse modified to include optional Data field
type StepWebhookResponse struct {
	Allow bool                   `json:"allow"`
	Data  map[string]interface{} `json:"data,omitempty"` // Data to merge into certificate template
}

// SendResponseWithData sends the JSON response (potentially with data) back to step-ca
// Exported function (starts with uppercase 'S')
func SendResponseWithData(w http.ResponseWriter, allow bool, data map[string]interface{}) {
	// Only include data field if data is not nil
	response := StepWebhookResponse{Allow: allow}
	if data != nil {
		response.Data = data
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // step-ca typically expects 200 OK

	encoder := json.NewEncoder(w)
	if err := encoder.Encode(response); err != nil {
		// Log error using slog
		slog.Error("Error encoding response", "error", err) // Use slog
		// Avoid writing partial response, try sending plain error if possible
		// http.Error might write headers again, which is bad. Best effort:
		// w.WriteHeader(http.StatusInternalServerError) // Already set headers, might panic
		// w.Write([]byte("Internal Server Error"))
		return // Stop processing after logging
	}
	// Use structured logging for the response sent
	slog.Info("Sent response", "allow", response.Allow, "data_present", response.Data != nil) // Use slog
	// Avoid logging potentially large/sensitive data by default, log specific fields if needed at Debug level
	// if response.Data != nil {
	//     slog.Debug("Response data details", "data", response.Data)
	// }
}
