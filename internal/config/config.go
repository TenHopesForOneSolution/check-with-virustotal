package config

import (
	"golang.org/x/sys/windows/registry"
)

const (
	regPath = `Software\CheckWithVirusTotal`
	regKey  = "ApiKey"
)

// GetAPIKey reads the VirusTotal API key from the registry.
func GetAPIKey() (string, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	val, _, err := k.GetStringValue(regKey)
	return val, err
}

// SetAPIKey stores the VirusTotal API key in the registry.
func SetAPIKey(key string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, regPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(regKey, key)
}
