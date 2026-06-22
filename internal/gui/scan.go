package gui

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/lxn/walk"
	"github.com/TenHopesForOneSolution/check-with-virustotal/internal/config"
	"github.com/TenHopesForOneSolution/check-with-virustotal/internal/vt"
)

// ShowScan opens the scan window and processes the file.
func ShowScan(filePath string) {
	mw, err := walk.NewMainWindow()
	if err != nil {
		log.Fatal(err)
	}
	mw.SetTitle("Check with VirusTotal - " + filepath.Base(filePath))
	mw.SetMinMaxSize(walk.Size{Width: 520, Height: 420}, walk.Size{})
	if err := mw.SetLayout(walk.NewVBoxLayout()); err != nil {
		log.Fatal(err)
	}

	statusLabel, err := walk.NewLabel(mw)
	if err != nil {
		log.Fatal(err)
	}
	statusLabel.SetText("Reading API key...")

	progress, err := walk.NewProgressBar(mw)
	if err != nil {
		log.Fatal(err)
	}
	progress.SetMarqueeMode(true)

	resultEdit, err := walk.NewTextEdit(mw)
	if err != nil {
		log.Fatal(err)
	}
	resultEdit.SetReadOnly(true)
	resultEdit.SetMinMaxSize(walk.Size{Height: 200}, walk.Size{})

	closeBtn, err := walk.NewPushButton(mw)
	if err != nil {
		log.Fatal(err)
	}
	closeBtn.SetText("Close")
	closeBtn.Clicked().Attach(func() { mw.Close() })

	go scan(mw, statusLabel, progress, resultEdit, filePath)

	mw.Show()
	mw.Run()
}

func scan(mw *walk.MainWindow, status *walk.Label, progress *walk.ProgressBar, result *walk.TextEdit, path string) {
	apiKey, err := config.GetAPIKey()
	if err != nil || apiKey == "" {
		mw.Synchronize(func() {
			status.SetText("API key is not set. Open Settings from the Start Menu.")
			progress.SetMarqueeMode(false)
			progress.SetVisible(false)
			progress.SetVisible(false)
		})
		return
	}

	client := vt.NewClient(apiKey)

	mw.Synchronize(func() { status.SetText("Calculating file hash...") })
	hash, err := vt.HashFile(path)
	if err != nil {
		mw.Synchronize(func() {
			status.SetText("Hash error: " + err.Error())
			progress.SetMarqueeMode(false)
			progress.SetVisible(false)
		})
		return
	}

	mw.Synchronize(func() { status.SetText("Looking up file on VirusTotal...") })
	res, err := client.LookupFile(hash)
	if err != nil {
		mw.Synchronize(func() {
			status.SetText("Lookup error: " + err.Error())
			progress.SetMarqueeMode(false)
			progress.SetVisible(false)
		})
		return
	}

	if res != nil {
		mw.Synchronize(func() {
			status.SetText("Report found by hash.")
			progress.SetMarqueeMode(false)
			progress.SetVisible(false)
			result.SetText(formatResult(res))
		})
		return
	}

	mw.Synchronize(func() { status.SetText("Uploading file to VirusTotal...") })
	analysisID, err := client.UploadFile(path)
	if err != nil {
		mw.Synchronize(func() {
			status.SetText("Upload error: " + err.Error())
			progress.SetMarqueeMode(false)
			progress.SetVisible(false)
		})
		return
	}

	mw.Synchronize(func() { status.SetText("Waiting for analysis to complete...") })
	for {
		time.Sleep(5 * time.Second)
		res, err := client.GetAnalysis(analysisID)
		if err != nil {
			mw.Synchronize(func() {
				status.SetText("Analysis error: " + err.Error())
				progress.SetMarqueeMode(false)
			progress.SetVisible(false)
			})
			return
		}
		if res.Status == "completed" {
			mw.Synchronize(func() {
				status.SetText("Analysis completed.")
				progress.SetMarqueeMode(false)
			progress.SetVisible(false)
				result.SetText(formatResult(res))
			})
			return
		}
	}
}

func formatResult(r *vt.Result) string {
	const nl = "\r\n"
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Status: %s%s", r.Status, nl))
	b.WriteString(fmt.Sprintf("Detections: %d / %d%s%s", r.Detections(), r.Total(), nl, nl))

	if len(r.Results) == 0 {
		b.WriteString("No engine results available yet.")
		return b.String()
	}

	b.WriteString("Detected engines:" + nl)
	found := false
	for name, er := range r.Results {
		if er.Category == "malicious" || er.Category == "suspicious" {
			found = true
			desc := er.Result
			if desc == "" {
				desc = er.Category
			}
			b.WriteString(fmt.Sprintf("  %s: %s%s", name, desc, nl))
		}
	}
	if !found {
		b.WriteString("  No detections." + nl)
	}

	b.WriteString(nl + "All engine categories:" + nl)
	for cat, count := range r.Stats {
		if count > 0 {
			b.WriteString(fmt.Sprintf("  %s: %d%s", cat, count, nl))
		}
	}
	return b.String()
}
