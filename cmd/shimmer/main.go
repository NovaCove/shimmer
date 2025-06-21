package main

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/ztrue/shutdown"

	"github.com/NovaCove/shimmer/lib/server/mount"
	"github.com/NovaCove/shimmer/lib/server/rpc"
)

// mount -o port=63289,mountport=63289 -t nfs localhost:/foo ~/.yolo

var (
	lgr      *slog.Logger
	logLevel = new(slog.LevelVar)
)

func getLogger() *slog.Logger {
	if lgr == nil {
		logDir := filepath.Join(
			os.Getenv("HOME"),
			".shimmer",
			"logs",
		)

		if err := os.MkdirAll(logDir, 0755); err != nil {
			fmt.Println("failed to create log directory: ", err)
			os.Exit(1)
		}

		logPath := filepath.Join(logDir, "info.log")
		logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("failed to open log file: %v", err)
		}
		lgr = slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{
			Level: logLevel,
		}))
	}
	return lgr
}

func server(lgr *slog.Logger) {
	lgr.Debug("Creating mount server...")
	srvr := mount.NewMountServer("/tmp/shimmer.sock", os.Getpid(), lgr)

	lgr.Debug("Registering handlers...")
	shutdown.Add(func() {
		lgr.Info("shutdown hook triggered, stopping server...")
		if err := srvr.Stop(); err != nil {
			lgr.Error("Error stopping server", slog.Any("err", err))
		}
	})

	lgr.Info("Kicking off server go routine...")
	go func() {
		if err := srvr.Start(); err != nil {
			lgr.Error("Error stopping server", slog.Any("err", err))
			return
		}
	}()

	lgr.Info("Server started, waiting for shutdown...")
	shutdown.Listen(syscall.SIGINT, syscall.SIGTERM)
	lgr.Info("Shutdown signal received, stopping server...")
}

func resolvePathToAbsolute(str string) (string, error) {
	str, _ = strings.CutPrefix(str, "file://")
	if !strings.HasPrefix(str, "/") {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get current working directory: %w", err)
		}
		str = cwd + "/" + str
	}
	return str, nil
}

func main() {

	lgr := getLogger()

	lgr.Debug("Setting up commands")

	rootCmd := &cobra.Command{
		Use:   "shimmer",
		Short: "shimmer",
		Long:  ``,
	}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "server",
		Short: "Start the shimmer server",
		Run: func(cmd *cobra.Command, args []string) {
			server(lgr)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "unlock",
		Short: "Unlock the shimmer server",
		Run: func(cmd *cobra.Command, args []string) {
			method, err := cmd.Flags().GetString("method")
			if err != nil {
				// If we can't get the method flag, it's because we want a default value.
				method = "touchid"
			} else if len(method) == 0 {
				method = "touchid"
			}

			client := rpc.NewClient("/tmp/shimmer.sock", os.Getpid())
			resp, err := client.Send("/unlock", mount.AuthRequest{
				Method: method,
			})
			if err != nil {
				fmt.Printf("Error unlocking: %v\n", err)
				os.Exit(1)
			}

			var result struct {
				Status string `json:"status"`
			}
			if err := json.Unmarshal(resp, &result); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}
			if result.Status == "not_bootstrapped" {
				fmt.Println("Shimmer server is not bootstrapped. Please run `shimmer init` first.")
				os.Exit(1)
			}
			lgr.Info("Unlocked shimmer server successfully:\n", result)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "Initialize the shimmer server",
		Run: func(cmd *cobra.Command, args []string) {
			client := rpc.NewClient("/tmp/shimmer.sock", os.Getpid())
			resp, err := client.Send("/init", nil)
			if err != nil {
				fmt.Printf("Error unlocking: %v\n", err)
				os.Exit(1)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(resp, &result); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}
			lgr.Info("Unlocked shimmer server successfully:\n", result)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "doctor",
		Short: "Run a health check on the shimmer server",
		Run: func(cmd *cobra.Command, args []string) {
			client := rpc.NewClient("/tmp/shimmer.sock", os.Getpid())
			resp, err := client.Send("/doctor", nil)
			if err != nil {
				fmt.Printf("Error unlocking: %v\n", err)
				os.Exit(1)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(resp, &result); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}
			lgr.Info("Unlocked shimmer server successfully:\n", result)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "mount",
		Short: "mount a new volume",
		Run: func(cmd *cobra.Command, args []string) {
			client := rpc.NewClient("/tmp/shimmer.sock", os.Getpid())
			if len(args) < 2 {
				fmt.Println("Usage: shimmer mount <path> <mount_point>")
				os.Exit(1)
			}
			path, err := resolvePathToAbsolute(args[0])
			if err != nil {
				fmt.Printf("Error resolving path: %v\n", err)
				os.Exit(1)
			}
			mountPoint, err := resolvePathToAbsolute(args[1])
			if err != nil {
				fmt.Printf("Error resolving mount point: %v\n", err)
				os.Exit(1)
			}

			resp, err := client.Send("/mount/start", map[string]interface{}{
				"path":        path,
				"mount_point": mountPoint,
			})
			if err != nil {
				fmt.Printf("Error mounting: %v\n", err)
				os.Exit(1)
			}
			var result map[string]interface{}
			if err := json.Unmarshal(resp, &result); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}
			lgr.Info("Mounted %s at %s (port: %v)\n", result["mount_point"], mountPoint, result["port"])
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "mount-single",
		Short: "Mount a single file",
		Run: func(cmd *cobra.Command, args []string) {
			client := rpc.NewClient("/tmp/shimmer.sock", os.Getpid())
			if len(args) < 2 {
				fmt.Println("Usage: shimmer mount-single <path> <mount_point>")
				os.Exit(1)
			}
			sourceFile, err := resolvePathToAbsolute(args[0])
			if err != nil {
				fmt.Printf("Error resolving path: %v\n", err)
				os.Exit(1)
			}
			mountPoint, err := resolvePathToAbsolute(args[1])
			if err != nil {
				fmt.Printf("Error resolving mount point: %v\n", err)
				os.Exit(1)
			}
			resp, err := client.Send("/mount/single", map[string]interface{}{
				"source_file": sourceFile,
				"mount_point": mountPoint,
			})
			if err != nil {
				fmt.Printf("Error mounting single file: %v\n", err)
				os.Exit(1)
			}
			var result map[string]interface{}
			if err := json.Unmarshal(resp, &result); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}
			lgr.Info("Mounted single file %s at %s (port: %v)\n", result["source_file"], mountPoint, result["port"])
		},
	})

	// Add root level flag for seting the log level
	rootCmd.PersistentFlags().String("log-level", "info", "Set the log level (debug, info, warn, error)")

	// Set the log level based on the flag
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		logLevelVal, err := cmd.Flags().GetString("log-level")
		if err != nil {
			fmt.Printf("Error getting log level: %v\n", err)
			os.Exit(1)
		}
		var level slog.Level
		switch logLevelVal {
		case "debug":
			level = slog.LevelDebug
		case "info":
			level = slog.LevelInfo
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		default:
			fmt.Printf("Invalid log level: %s\n", logLevel)
			os.Exit(1)
		}

		logLevel.Set(level)
	}

	// Execute root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
