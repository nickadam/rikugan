//go:build !windows
// +build !windows

package main

// isWindowsService returns false on non-Windows platforms
func isWindowsService() bool {
	return false
}

// runService is a no-op on non-Windows platforms
func runService(name string, serverURL, agentToken, agentID, agentDataDir string) {
	// Not supported on this platform
}
