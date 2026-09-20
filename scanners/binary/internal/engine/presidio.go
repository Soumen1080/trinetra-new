package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/trinetra/cbom-go/cbom"
)

// PresidioEngine wraps Microsoft Presidio for NER-based PII/sensitive data
// detection.
//
// This strengthens the X evidence tier (data-at-risk classification) beyond
// regex patterns. Presidio uses NLP to detect names, addresses, credit cards,
// SSNs, etc., which helps determine what data would be at risk if encryption
// is broken.
//
// The engine expects Presidio Analyzer to be running as a service
// (typically http://localhost:5002).
type PresidioEngine struct {
	analyzerURL string
	httpClient  *http.Client
}

// NewPresidioEngine creates a Presidio PII detection engine.
func NewPresidioEngine() *PresidioEngine {
	url := os.Getenv("TRINETRA_PRESIDIO_URL")
	if url == "" {
		url = "http://localhost:5002"
	}
	return &PresidioEngine{
		analyzerURL: url,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (e *PresidioEngine) Name() string { return "Presidio" }

func (e *PresidioEngine) Tool() cbom.Tool {
	return cbom.Tool{
		Vendor:  "Microsoft",
		Name:    "presidio-analyzer",
		Version: e.detectVersion(),
	}
}

func (e *PresidioEngine) Available(ctx context.Context) error {
	// Check if Presidio service is reachable
	req, err := http.NewRequestWithContext(ctx, "GET", e.analyzerURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("create health check request: %w", err)
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Presidio not available at %s (set TRINETRA_PRESIDIO_URL): %w", e.analyzerURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Presidio health check failed: status %d", resp.StatusCode)
	}

	return nil
}

func (e *PresidioEngine) Languages() []string {
	return []string{"text", "config", "logs"}
}

func (e *PresidioEngine) Scan(ctx context.Context, root string) (Result, error) {
	var result Result

	// Find text files and configuration files that might contain PII
	textFiles, err := findTextFiles(root)
	if err != nil {
		return result, fmt.Errorf("find text files: %w", err)
	}

	if len(textFiles) == 0 {
		result.Gaps = append(result.Gaps, Gap{
			Kind:   "no_text_files",
			Reason: "No text files found for PII scanning",
			Count:  1,
		})
		return result, nil
	}

	// Analyze each file
	for _, file := range textFiles {
		findings, gaps := e.analyzeFile(ctx, file, root)
		result.Findings = append(result.Findings, findings...)
		result.Gaps = append(result.Gaps, gaps...)
		result.FilesScanned++
	}

	return result, nil
}

func (e *PresidioEngine) analyzeFile(ctx context.Context, filePath, root string) ([]cbom.Finding, []Gap) {
	// Read file content (with size limit to avoid huge files)
	const maxFileSize = 1024 * 1024 // 1MB limit
	stat, err := os.Stat(filePath)
	if err != nil {
		return nil, []Gap{{
			Path:   filePath,
			Kind:   "read_failed",
			Reason: fmt.Sprintf("Failed to stat file: %v", err),
			Count:  1,
		}}
	}

	if stat.Size() > maxFileSize {
		return nil, []Gap{{
			Path:   filePath,
			Kind:   "file_too_large",
			Reason: fmt.Sprintf("File size %d exceeds limit %d", stat.Size(), maxFileSize),
			Count:  1,
		}}
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, []Gap{{
			Path:   filePath,
			Kind:   "read_failed",
			Reason: fmt.Sprintf("Failed to read file: %v", err),
			Count:  1,
		}}
	}

	// Skip binary files
	if isBinaryContent(content) {
		return nil, nil
	}

	// Call Presidio API
	entities, err := e.analyzeText(ctx, string(content))
	if err != nil {
		return nil, []Gap{{
			Path:   filePath,
			Kind:   "presidio_failed",
			Reason: fmt.Sprintf("Presidio analysis failed: %v", err),
			Count:  1,
		}}
	}

	if len(entities) == 0 {
		return nil, nil
	}

	// Convert to findings
	relPath := filePath
	if rel, err := filepath.Rel(root, filePath); err == nil {
		relPath = rel
	}

	var findings []cbom.Finding
	entityCounts := make(map[string]int)

	for _, entity := range entities {
		entityCounts[entity.Type]++
	}

	// Create one finding per entity type found in the file
	for entityType, count := range entityCounts {
		findings = append(findings, cbom.Finding{
			AssetType: cbom.AssetData, // Custom type for data-at-risk
			Name:      fmt.Sprintf("PII-%s", entityType),
			Location:  relPath,
			Snippet:   fmt.Sprintf("%d instance(s) of %s detected", count, entityType),
			Note: fmt.Sprintf(
				"Sensitive data detected by NER: %s. This data would be at risk if encryption protecting this file is compromised.",
				entityType),
			Confidence: confidenceFromScore(averageScore(entities, entityType)),
		})
	}

	return findings, nil
}

type presidioRequest struct {
	Text     string   `json:"text"`
	Language string   `json:"language"`
	Entities []string `json:"entities,omitempty"`
}

type presidioResponse []presidioEntity

type presidioEntity struct {
	Type           string  `json:"entity_type"`
	Start          int     `json:"start"`
	End            int     `json:"end"`
	Score          float64 `json:"score"`
	RecognizerName string  `json:"recognition_metadata"`
}

func (e *PresidioEngine) analyzeText(ctx context.Context, text string) ([]presidioEntity, error) {
	reqBody := presidioRequest{
		Text:     text,
		Language: "en",
		// Request all entity types
		Entities: []string{
			"CREDIT_CARD", "CRYPTO", "EMAIL_ADDRESS", "IBAN_CODE",
			"IP_ADDRESS", "NRP", "LOCATION", "PERSON", "PHONE_NUMBER",
			"MEDICAL_LICENSE", "URL", "US_SSN", "US_BANK_NUMBER",
			"US_DRIVER_LICENSE", "US_ITIN", "US_PASSPORT",
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		e.analyzerURL+"/analyze",
		bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("presidio returned status %d: %s", resp.StatusCode, body)
	}

	var entities presidioResponse
	if err := json.NewDecoder(resp.Body).Decode(&entities); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return entities, nil
}

func (e *PresidioEngine) detectVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", e.analyzerURL+"/health", nil)
	if err != nil {
		return "unknown"
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()

	// Try to extract version from response headers or body
	if version := resp.Header.Get("X-Presidio-Version"); version != "" {
		return version
	}

	return "latest" // Presidio doesn't expose version easily
}

func findTextFiles(root string) ([]string, error) {
	var textFiles []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Check if it's a text file by extension or content
		if isTextFile(path, info) {
			textFiles = append(textFiles, path)
		}

		return nil
	})

	return textFiles, err
}

func isTextFile(path string, info os.FileInfo) bool {
	// Skip very large files
	if info.Size() > 1024*1024 {
		return false
	}

	ext := strings.ToLower(filepath.Ext(path))
	textExtensions := map[string]bool{
		".txt":    true,
		".md":     true,
		".json":   true,
		".xml":    true,
		".yaml":   true,
		".yml":    true,
		".conf":   true,
		".config": true,
		".ini":    true,
		".log":    true,
		".csv":    true,
		".env":    true,
		".sql":    true,
	}

	return textExtensions[ext]
}

func isBinaryContent(content []byte) bool {
	if len(content) == 0 {
		return false
	}

	// Check for null bytes (common in binary files)
	sampleSize := 512
	if len(content) < sampleSize {
		sampleSize = len(content)
	}

	nullCount := 0
	for i := 0; i < sampleSize; i++ {
		if content[i] == 0 {
			nullCount++
		}
	}

	// If more than 1% are null bytes, it's likely binary
	return float64(nullCount)/float64(sampleSize) > 0.01
}

func averageScore(entities []presidioEntity, entityType string) float64 {
	var sum float64
	var count int
	for _, e := range entities {
		if e.Type == entityType {
			sum += e.Score
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return sum / float64(count)
}

func confidenceFromScore(score float64) cbom.Confidence {
	switch {
	case score >= 0.9:
		return cbom.ConfidenceHigh
	case score >= 0.7:
		return cbom.ConfidenceMedium
	default:
		return cbom.ConfidenceLow
	}
}
