package install

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows/registry"
)

const menuName = "Check with VirusTotal"

// Install registers the context-menu item and creates a Start Menu shortcut.
func Install(exePath string) error {
	if err := registerContextMenu(exePath); err != nil {
		return err
	}
	if err := createStartMenuShortcut(exePath); err != nil {
		return err
	}
	return nil
}

func registerContextMenu(exePath string) error {
	keyPath := `*\shell\` + menuName

	k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Classes\`+keyPath, registry.WRITE)
	if err != nil {
		return fmt.Errorf("create context-menu key: %w", err)
	}
	if err := k.SetStringValue("", menuName); err != nil {
		k.Close()
		return err
	}
	if err := k.SetStringValue("Icon", exePath); err != nil {
		k.Close()
		return err
	}
	k.Close()

	cmdPath := keyPath + `\command`
	k2, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Classes\`+cmdPath, registry.WRITE)
	if err != nil {
		return fmt.Errorf("create command key: %w", err)
	}
	defer k2.Close()

	// "%1" is replaced by Windows with the selected file path.
	command := fmt.Sprintf(`"%s" "%%1"`, exePath)
	return k2.SetStringValue("", command)
}

// Uninstall removes the context-menu item and the Start Menu shortcut.
func Uninstall() error {
	keyPath := `Software\Classes\*\shell\` + menuName
	if err := registry.DeleteKey(registry.CURRENT_USER, keyPath+`\command`); err != nil && err != registry.ErrNotExist {
		return fmt.Errorf("remove command key: %w", err)
	}
	if err := registry.DeleteKey(registry.CURRENT_USER, keyPath); err != nil && err != registry.ErrNotExist {
		return fmt.Errorf("remove context-menu key: %w", err)
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	shortcutPath := filepath.Join(configDir, `Microsoft\Windows\Start Menu\Programs`, menuName+".lnk")
	if err := os.Remove(shortcutPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func createStartMenuShortcut(exePath string) error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	shortcutPath := filepath.Join(configDir, `Microsoft\Windows\Start Menu\Programs`, menuName+".lnk")

	if err := os.MkdirAll(filepath.Dir(shortcutPath), 0755); err != nil {
		return err
	}

	ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED)
	defer ole.CoUninitialize()

	shell, err := oleutil.CreateObject("WScript.Shell")
	if err != nil {
		return fmt.Errorf("create WScript.Shell: %w", err)
	}
	defer shell.Release()

	idispatch, err := shell.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return err
	}
	defer idispatch.Release()

	shortcut, err := oleutil.CallMethod(idispatch, "CreateShortcut", shortcutPath)
	if err != nil {
		return fmt.Errorf("create shortcut: %w", err)
	}
	sc := shortcut.ToIDispatch()
	defer sc.Release()

	if _, err := oleutil.PutProperty(sc, "TargetPath", exePath); err != nil {
		return err
	}
	if _, err := oleutil.PutProperty(sc, "WorkingDirectory", filepath.Dir(exePath)); err != nil {
		return err
	}
	if _, err := oleutil.PutProperty(sc, "Description", menuName+" settings"); err != nil {
		return err
	}
	if _, err := oleutil.PutProperty(sc, "Arguments", ""); err != nil {
		return err
	}
	if _, err := oleutil.CallMethod(sc, "Save"); err != nil {
		return fmt.Errorf("save shortcut: %w", err)
	}
	return nil
}
