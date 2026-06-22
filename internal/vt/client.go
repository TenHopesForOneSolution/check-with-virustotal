package vt

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"

	vt "github.com/VirusTotal/vt-go"
)

// EngineResult describes a single engine's verdict.
type EngineResult struct {
	Category   string
	EngineName string
	Result     string
}

// Result is a normalized scan report.
type Result struct {
	Status  string
	Stats   map[string]int
	Results map[string]EngineResult
}

// Total returns the total number of engines that reported.
func (r *Result) Total() int {
	total := 0
	for _, v := range r.Stats {
		total += v
	}
	return total
}

// Detections returns the number of malicious + suspicious reports.
func (r *Result) Detections() int {
	return r.Stats["malicious"] + r.Stats["suspicious"]
}

// Client wraps the official VirusTotal Go client.
type Client struct {
	client *vt.Client
}

// NewClient creates a new VirusTotal client.
func NewClient(apiKey string) *Client {
	return &Client{client: vt.NewClient(apiKey)}
}

// LookupFile checks whether a file has already been analyzed by its SHA-256 hash.
// Returns nil, nil when the file is unknown to VirusTotal.
func (c *Client) LookupFile(hash string) (*Result, error) {
	obj, err := c.client.GetObject(vt.URL("files/%s", hash))
	if err != nil {
		if apiErr, ok := err.(vt.Error); ok && apiErr.Code == "NotFoundError" {
			return nil, nil
		}
		return nil, err
	}
	return parseResult(obj, "last_analysis_stats", "last_analysis_results", "completed")
}

// UploadFile uploads a file to VirusTotal and returns the analysis ID.
func (c *Client) UploadFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	analysis, err := c.client.NewFileScanner().ScanFile(f, nil)
	if err != nil {
		return "", err
	}
	return analysis.ID(), nil
}

// GetAnalysis retrieves the current state of an analysis by ID.
func (c *Client) GetAnalysis(id string) (*Result, error) {
	obj, err := c.client.GetObject(vt.URL("analyses/%s", id))
	if err != nil {
		return nil, err
	}
	return parseResult(obj, "stats", "results", "")
}

func parseResult(obj *vt.Object, statsAttr, resultsAttr, status string) (*Result, error) {
	if status == "" {
		s, err := obj.GetString("status")
		if err != nil {
			return nil, err
		}
		status = s
	}

	statsVal, err := obj.Get(statsAttr)
	if err != nil {
		return nil, err
	}
	statsMap, ok := statsVal.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected type for %s", statsAttr)
	}
	stats := make(map[string]int, len(statsMap))
	for k, v := range statsMap {
		switch n := v.(type) {
		case json.Number:
			i, _ := n.Int64()
			stats[k] = int(i)
		case float64:
			stats[k] = int(n)
		}
	}

	resultsVal, err := obj.Get(resultsAttr)
	if err != nil {
		return nil, err
	}
	resultsMap, ok := resultsVal.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected type for %s", resultsAttr)
	}
	results := make(map[string]EngineResult, len(resultsMap))
	for name, v := range resultsMap {
		engine, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		er := EngineResult{}
		if s, ok := engine["category"].(string); ok {
			er.Category = s
		}
		if s, ok := engine["engine_name"].(string); ok {
			er.EngineName = s
		}
		if s, ok := engine["result"].(string); ok {
			er.Result = s
		}
		results[name] = er
	}

	return &Result{
		Status:  status,
		Stats:   stats,
		Results: results,
	}, nil
}

// HashFile returns the SHA-256 hash of a file.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
