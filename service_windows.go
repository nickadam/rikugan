//go:build windows
// +build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

var elog debug.Log

type rikuganService struct {
	serverURL    string
	agentToken   string
	agentID      string
	agentDataDir string
}

func (m *rikuganService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// Clean up the data directory path - remove trailing slashes and quotes
	// that can occur from Windows command-line escaping issues
	dataDir := strings.TrimSpace(m.agentDataDir)
	dataDir = strings.TrimRight(dataDir, `/\"'`)
	if dataDir == "" {
		dataDir = "C:\\ProgramData\\Rikugan"
	}

	// Set up logging to file since we can't use stdout as a service
	logDir := filepath.Join(dataDir, "logs")
	os.MkdirAll(logDir, 0755)
	logFile, err := os.OpenFile(
		filepath.Join(logDir, "agent.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err == nil {
		log.SetOutput(logFile)
		defer logFile.Close()
	}

	elog.Info(1, fmt.Sprintf("Starting Rikugan agent service, connecting to %s", m.serverURL))
	log.Printf("Starting Rikugan agent service, connecting to %s", m.serverURL)
	log.Printf("Data directory: %s", dataDir)

	// Create and start agent (pass cleaned dataDir)
	agent := NewAgent(m.serverURL, m.agentToken, m.agentID, dataDir)

	// Run agent in background
	done := make(chan struct{})
	go func() {
		agent.Run()
		close(done)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				elog.Info(1, "Service stop requested")
				log.Println("Service stop requested")
				changes <- svc.Status{State: svc.StopPending}
				// Agent doesn't have graceful shutdown, just exit
				return
			default:
				elog.Error(1, fmt.Sprintf("Unexpected control request #%d", c))
			}
		case <-done:
			// Agent exited unexpectedly
			elog.Error(1, "Agent exited unexpectedly")
			return
		}
	}
}

func runService(name string, serverURL, agentToken, agentID, agentDataDir string) {
	var err error
	elog, err = eventlog.Open(name)
	if err != nil {
		return
	}
	defer elog.Close()

	elog.Info(1, fmt.Sprintf("Starting %s service", name))

	run := svc.Run
	if isDebug() {
		run = debug.Run
	}

	err = run(name, &rikuganService{
		serverURL:    serverURL,
		agentToken:   agentToken,
		agentID:      agentID,
		agentDataDir: agentDataDir,
	})
	if err != nil {
		elog.Error(1, fmt.Sprintf("%s service failed: %v", name, err))
		return
	}
	elog.Info(1, fmt.Sprintf("%s service stopped", name))
}

func isDebug() bool {
	return os.Getenv("RIKUGAN_DEBUG") == "1"
}

// isWindowsService checks if we're running as a Windows service
func isWindowsService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isService
}
