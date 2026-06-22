package gui

import (
	"log"
	"os"

	"github.com/lxn/walk"
	"github.com/TenHopesForOneSolution/check-with-virustotal/internal/config"
	"github.com/TenHopesForOneSolution/check-with-virustotal/internal/install"
)

// ShowSettings opens the settings window.
func ShowSettings() {
	mw, err := walk.NewMainWindow()
	if err != nil {
		log.Fatal(err)
	}
	mw.SetTitle("Check with VirusTotal - Settings")
	mw.SetMinMaxSize(walk.Size{Width: 450, Height: 180}, walk.Size{})

	if err := mw.SetLayout(walk.NewVBoxLayout()); err != nil {
		log.Fatal(err)
	}

	label, err := walk.NewLabel(mw)
	if err != nil {
		log.Fatal(err)
	}
	label.SetText("VirusTotal API key:")

	apiKeyEdit, err := walk.NewLineEdit(mw)
	if err != nil {
		log.Fatal(err)
	}
	apiKeyEdit.SetText(mustGetAPIKey())
	apiKeyEdit.SetPasswordMode(true)

	buttons, err := walk.NewComposite(mw)
	if err != nil {
		log.Fatal(err)
	}
	buttons.SetLayout(walk.NewHBoxLayout())

	saveBtn, err := walk.NewPushButton(buttons)
	if err != nil {
		log.Fatal(err)
	}
	saveBtn.SetText("Save key")
	saveBtn.Clicked().Attach(func() {
		if err := config.SetAPIKey(apiKeyEdit.Text()); err != nil {
			walk.MsgBox(mw, "Error", "Failed to save API key: "+err.Error(), walk.MsgBoxIconError)
			return
		}
		walk.MsgBox(mw, "Saved", "API key saved.", walk.MsgBoxIconInformation)
	})

	installBtn, err := walk.NewPushButton(buttons)
	if err != nil {
		log.Fatal(err)
	}
	installBtn.SetText("Install to context menu")
	installBtn.Clicked().Attach(func() {
		exe, err := os.Executable()
		if err != nil {
			walk.MsgBox(mw, "Error", err.Error(), walk.MsgBoxIconError)
			return
		}
		if err := install.Install(exe); err != nil {
			walk.MsgBox(mw, "Error", err.Error(), walk.MsgBoxIconError)
			return
		}
		walk.MsgBox(mw, "Installed", "Context menu item and Start Menu shortcut created.", walk.MsgBoxIconInformation)
	})

	mw.Show()
	mw.Run()
}

func mustGetAPIKey() string {
	key, _ := config.GetAPIKey()
	return key
}
