# Check with VirusTotal

A small Windows utility that adds a **Check with VirusTotal** item to the File Explorer context menu. Right-click any file, select the item, and the program will scan it through [VirusTotal](https://www.virustotal.com) and show the result in a simple window.

## Features

- Context-menu item for any file.
- SHA-256 lookup: instant results if the file is already known to VirusTotal.
- Automatic upload and analysis polling for unknown files.
- Settings window for entering your VirusTotal API key.
- Native Windows GUI built with [walk](https://github.com/lxn/walk).
- VirusTotal API client powered by the official [`vt-go`](https://github.com/VirusTotal/vt-go) library.

## Requirements

- Windows 10/11
- [Go 1.22+](https://go.dev/dl/) (only for building from source)
- A [VirusTotal API key](https://www.virustotal.com/gui/my-apikey)

## Build locally

Open a terminal in the project folder and run:

```bat
build.bat
```

Or manually:

```bat
cd cmd\check-with-virustotal
go generate
go build -ldflags="-H windowsgui" -o ..\..\check-with-virustotal.exe .
```

The resulting `check-with-virustotal.exe` will be placed in the repository root.

## Build with GitHub Actions

The repository includes a GitHub Actions workflow (`.github/workflows/build.yml`) that builds the Windows binary on every push and pull request. You can download the compiled `.exe` from the workflow artifacts.

## Installation

1. Copy `check-with-virustotal.exe` to a permanent location (for example, `C:\Tools\`).
2. Double-click the executable to open the settings window.
3. Paste your VirusTotal API key and click **Save key**.
4. Click **Install to context menu** to create the right-click menu item and a Start Menu shortcut.

> No administrator rights are required: the context-menu entry is written to `HKEY_CURRENT_USER\Software\Classes`.

## Usage

1. In File Explorer, right-click any file.
2. Select **Check with VirusTotal**.
3. Wait for the scan result window to appear.

## Command-line arguments

| Argument | Description |
|----------|-------------|
| *(no arguments)* | Open the settings window. |
| `"C:\path\to\file.ext"` | Scan the specified file. |
| `--install` | Add the context-menu item and Start Menu shortcut. |
| `--uninstall` | Remove the context-menu item and Start Menu shortcut. |

## License

[MIT](LICENSE)
