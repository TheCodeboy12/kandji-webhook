package kandji

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	kandji "github.com/TheCodeboy12/kandji-step-ca-webhook/internal/kandji/structs"
)

func CheckKandjiDevice(ctx context.Context, deviceIdentifier string, apiURL string, apiKey string) (bool, error) {
	var kandjiResp kandji.KandjiListAdeDeviceRes

	if apiKey == "" || apiURL == "" {
		return false, nil
	}

	endpoint := "/integrations/apple/ade/devices"
	queryParam := "serial_number"
	fullURL, err := url.Parse(apiURL)
	if err != nil {
		return false, fmt.Errorf("invalid Kandji API URL configured: %w", err)
	}
	fullURL = fullURL.JoinPath(endpoint)
	query := fullURL.Query()
	query.Set(queryParam, deviceIdentifier)
	fullURL.RawQuery = query.Encode()
	slog.Debug("Querying Kandji API", "url", fullURL.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL.String(), nil)
	if err != nil {
		// Use slog.Error for errors
		slog.Error("Failed to create Kandji API request", "url", fullURL.String(), "error", err)
		return false, fmt.Errorf("failed to create Kandji API request: %w", err)
	}
	// Set Headers
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")
	// Make Request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Failed to execute Kandji API request", "url", fullURL.String(), "error", err)
		return false, fmt.Errorf("failed to execute Kandji API request: %w", err)
	}
	defer resp.Body.Close()
	// Check Status Code
	if resp.StatusCode != http.StatusOK {
		// Attempt to read body for more info, but don't fail if reading fails
		bodyBytes, _ := io.ReadAll(resp.Body)
		// Use slog.Warn for non-200 responses
		slog.Warn("Kandji API returned non-OK status",
			"url", fullURL.String(),
			"status_code", resp.StatusCode,
			"response_body", string(bodyBytes), // Be careful logging full bodies, maybe trim or log at Debug
		)
		return false, fmt.Errorf("kandji API returned status %d", resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("Failed to read Kandji API response body", "url", fullURL.String(), "error", err)
		return false, fmt.Errorf("failed to read Kandji API response body: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(bodyBytes))
	if err := decoder.Decode(&kandjiResp); err != nil {
		slog.Error("Failed to decode Kandji API response",
			"url", fullURL.String(),
			"response_body", string(bodyBytes), // Log raw body on decode error
			"error", err,
		)
		return false, fmt.Errorf("failed to decode Kandji API response: %w", err)
	}
	// Check if any devices were found matching the identifier
	if kandjiResp.Count == 1 && kandjiResp.Results[0].SerialNumber == deviceIdentifier {
		slog.Info("Found device(s) in Kandji",
			"identifier", deviceIdentifier,
			"depId", kandjiResp.Results[0].Id,
		)
		return true, nil // Device found
	}
	slog.Info("No devices found in Kandji", "identifier", deviceIdentifier)
	return false, nil // Device not found
}
