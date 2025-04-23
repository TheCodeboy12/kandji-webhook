package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

type KandjiListAdeDeviceRes struct {
	Count    int               `json:"count"`
	Next     string            `json:"next"`
	Previous string            `json:"previous"`
	Results  []kandjiAdeDevice `json:"results"`
}
type depAccount struct {
	Id         string `json:"id"`
	ServerName string `json:"server_name"`
}
type kandjiAdeDevice struct {
	SerialNumber string     `json:"serial_number"`
	Dep_account  depAccount `json:"dep_account"`
	BlueprintId  string     `json:"blueprint_id"`
	Id           string     `json:"id"`
}

func FindKandjiDevice(deviceKey string, apiKey string, apiBaseURL string) (kandjiAdeDevice, bool, error) {

	if apiKey == "" || apiBaseURL == "" {
		return kandjiAdeDevice{}, false, fmt.Errorf("apiKey or apiBaseURL missing")
	}
	endpoint := "/integrations/apple/ade/devices"
	queryParam := "serial_number"
	fullURL, err := url.Parse(apiBaseURL)
	if err != nil {
		return kandjiAdeDevice{}, false, fmt.Errorf("invalid Kandji API URL configured: %w", err)
	}
	fullURL = fullURL.JoinPath(endpoint)
	query := fullURL.Query()
	query.Set(queryParam, deviceKey)
	fullURL.RawQuery = query.Encode()
	req, err := http.NewRequest(http.MethodGet, fullURL.String(), nil)
	if err != nil {
		// Use slog.Error for errors
		slog.Error("Failed to create Kandji API request", "url", fullURL.String(), "error", err)
		return kandjiAdeDevice{}, false, fmt.Errorf("failed to create Kandji API request: %w", err)
	}
	// Set Headers
	req.Header.Set("Authorization", "Bearer "+apiKey)
	// req.Header.Set("Accept", "application/json")
	// Make Request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Failed to execute Kandji API request", "url", fullURL.String(), "error", err)
		return kandjiAdeDevice{}, false, fmt.Errorf("failed to execute Kandji API request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Attempt to read body for more info, but don't fail if reading fails
		bodyBytes, _ := io.ReadAll(resp.Body)
		// Use slog.Warn for non-200 responses
		slog.Warn("Kandji API returned non-OK status",
			"url", fullURL.String(),
			"status_code", resp.StatusCode,
			"response_body", string(bodyBytes), // Be careful logging full bodies, maybe trim or log at Debug
		)
		return kandjiAdeDevice{}, false, fmt.Errorf("kandji API returned status %d", resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("Failed to read Kandji API response body", "url", fullURL.String(), "error", err)
		return kandjiAdeDevice{}, false, fmt.Errorf("failed to read Kandji API response body: %w", err)
	}
	var kandjiResp KandjiListAdeDeviceRes
	decoder := json.NewDecoder(bytes.NewReader(bodyBytes))
	if err := decoder.Decode(&kandjiResp); err != nil {
		slog.Error("Failed to decode Kandji API response",
			"url", fullURL.String(),
			"response_body", string(bodyBytes), // Log raw body on decode error
			"error", err,
		)
		return kandjiAdeDevice{}, false, fmt.Errorf("failed to decode Kandji API response: %w", err)
	}
	if kandjiResp.Count == 1 && kandjiResp.Results[0].SerialNumber == deviceKey {
		slog.Info("Found device(s) in Kandji",
			"identifier", deviceKey,
			"depId", kandjiResp.Results[0].Id,
		)
		return kandjiResp.Results[0], true, nil // Device found
	}
	slog.Info("No devices found in Kandji", "identifier", deviceKey)
	return kandjiAdeDevice{}, false, fmt.Errorf("device not found") // Device not found

}
