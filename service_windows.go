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

// openLogFile opens or rotates the log file. Returns the file and current month.
func openLogFile(logDir string) (*os.File, int) {
	os.MkdirAll(logDir, 0755)

	logPath := filepath.Join(logDir, "agent.log")
	currentMonth := time.Now().Month()

	// Check if we need to rotate (file exists and is from a different month)
	if info, err := os.Stat(logPath); err == nil {
		if info.ModTime().Month() != currentMonth {
			// Rotate the old log
			rotatedName := fmt.Sprintf("agent-%s.log", info.ModTime().Format("2006-01"))
			rotatedPath := filepath.Join(logDir, rotatedName)
			os.Rename(logPath, rotatedPath)
		}
	}

	logFile, err := os.OpenFile(
		logPath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		return nil, int(currentMonth)
	}

	return logFile, int(currentMonth)
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
	logFile, currentMonth := openLogFile(logDir)
	if logFile != nil {
		log.SetOutput(logFile)
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

	// Ticker to check for monthly log rotation
	rotationTicker := time.NewTicker(1 * time.Hour)
	defer rotationTicker.Stop()

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
				if logFile != nil {
					logFile.Close()
				}
				changes <- svc.Status{State: svc.StopPending}
				return
			default:
				elog.Error(1, fmt.Sprintf("Unexpected control request #%d", c))
			}
		case <-rotationTicker.C:
			// Check if month changed and rotate log if needed
			if int(time.Now().Month()) != currentMonth {
				log.Println("Rotating log file for new month")
				if logFile != nil {
					logFile.Close()
				}
				logFile, currentMonth = openLogFile(logDir)
				if logFile != nil {
					log.SetOutput(logFile)
					log.Println("Log rotation complete")
				}
			}
		case <-done:
			// Agent exited unexpectedly
			elog.Error(1, "Agent exited unexpectedly")
			if logFile != nil {
				logFile.Close()
			}
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
