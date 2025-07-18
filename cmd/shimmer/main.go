package main

import (
	"encoding/json"
	"errors"
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

func handleAuthCliError(resp rpc.DataResponse) {
	if resp.Error == "" {
		return
	}

	if resp.Error == mount.ErrServerIsLocked.Error() {
		fmt.Println("Shimmer server is currently locked. Please run `shimmer unlock` first.")
	} else {
		fmt.Printf("Error: %s\n", resp.Error)
	}
	os.Exit(1)
}

func newClient(socketPath string, pid int) *rpc.Client {
	client := rpc.NewClient(socketPath, pid, logLevel.Level())
	return client
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

func sendCommand(endpoint string, data interface{}) (*rpc.DataResponse, error) {
	client := newClient("/tmp/shimmer.sock", os.Getpid())
	return sendCommandViaClient(client, endpoint, data)
}

func sendCommandT[T any](endpoint string, data interface{}) (*T, error, error) {
	client := newClient("/tmp/shimmer.sock", os.Getpid())
	resp, err := client.Send(endpoint, data)
	if err != nil {
		return nil, nil, fmt.Errorf("error sending command to server: %w", err)
	}

	var dResp rpc.DataResponse
	if err := json.Unmarshal(resp, &dResp); err != nil {
		return nil, nil, fmt.Errorf("error unmarshalling response: %w", err)
	}

	handleAuthCliError(dResp)

	if dResp.Error != "" {
		return nil, errors.New(dResp.Error), nil
	}

	var result T
	if err := json.Unmarshal(dResp.Data, &result); err != nil {
		return nil, nil, err
	}

	return &result, nil, nil
}

func porcelainSendCommandT[T any](endpoint string, data interface{}) *T {
	resp, srvrErr, err := sendCommandT[T](endpoint, data)
	if err != nil {
		fmt.Printf("shimmer communication error: %v\n", err)
		os.Exit(1)
	} else if srvrErr != nil {
		fmt.Printf("Server error: %v\n", srvrErr)
		os.Exit(1)
	} else if resp == nil {
		fmt.Println("No response received from server.")
		os.Exit(1)
	}
	return resp
}

func sendCommandViaClient(client *rpc.Client, endpoint string, data interface{}) (*rpc.DataResponse, error) {
	resp, err := client.Send(endpoint, data)
	if err != nil {
		return nil, fmt.Errorf("error sending command to server: %w", err)
	}

	var dResp rpc.DataResponse
	if err := json.Unmarshal(resp, &dResp); err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %w", err)
	}

	handleAuthCliError(dResp)

	return &dResp, nil
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

			client := newClient("/tmp/shimmer.sock", os.Getpid())
			resp, err := client.Send("/unlock", mount.AuthRequest{
				Method: method,
			})
			if err != nil {
				fmt.Printf("Error unlocking: %v\n", err)
				os.Exit(1)
			}

			var dResp rpc.DataResponse
			if err := json.Unmarshal(resp, &dResp); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}

			var result struct {
				Status string `json:"status"`
			}
			if err := json.Unmarshal(dResp.Data, &result); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}
			if result.Status == "not_bootstrapped" {
				fmt.Println("Shimmer server is not bootstrapped. Please run `shimmer init` first.")
				os.Exit(1)
			}
			lgr.Info("Unlocked shimmer server successfully:", slog.Any("result", result))
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "Initialize the shimmer server",
		Run: func(cmd *cobra.Command, args []string) {
			client := newClient("/tmp/shimmer.sock", os.Getpid())
			resp, err := client.Send("/init", nil)
			if err != nil {
				fmt.Printf("Error unlocking: %v\n", err)
				os.Exit(1)
			}

			var dResp rpc.DataResponse
			if err := json.Unmarshal(resp, &dResp); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(dResp.Data, &result); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}
			lgr.Info("Initialized shimmer server successfully:\n", slog.Any("result", result))
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "doctor",
		Short: "Run a health check on the shimmer server",
		Run: func(cmd *cobra.Command, args []string) {
			client := newClient("/tmp/shimmer.sock", os.Getpid())
			resp, err := client.Send("/doctor", nil)
			if err != nil {
				fmt.Printf("Error unlocking: %v\n", err)
				os.Exit(1)
			}

			var dResp rpc.DataResponse
			if err := json.Unmarshal(resp, &dResp); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(dResp.Data, &result); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}
			lgr.Info("Unlocked shimmer server successfully", slog.Any("result", result))
		},
	})

	mountCmd := &cobra.Command{
		Use:   "mount",
		Short: "mount a new volume",
		Run: func(cmd *cobra.Command, args []string) {
			client := newClient("/tmp/shimmer.sock", os.Getpid())
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

			ttl, err := cmd.Flags().GetString("ttl")
			if err != nil {
				fmt.Printf("Error getting ttl flag: %v\n", err)
				os.Exit(1)
			}
			lgr.Debug("Mounting with TTL: ", slog.String("ttl", ttl))

			resp, err := client.Send("/mount/start", map[string]interface{}{
				"path":        path,
				"mount_point": mountPoint,
				"ttl":         ttl,
			})
			if err != nil {
				fmt.Printf("Error mounting: %v\n", err)
				os.Exit(1)
			}

			var dResp rpc.DataResponse
			if err := json.Unmarshal(resp, &dResp); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(dResp.Data, &result); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}
			lgr.Info("Mounted %s at %s (port: %v)\n", result["mount_point"], mountPoint, result["port"])
		},
	}
	mountCmd.Flags().String("ttl", "8h", "Time to live for the mount (default: 8h)")
	rootCmd.AddCommand(mountCmd)

	rootCmd.AddCommand(&cobra.Command{
		Use:   "mount-single",
		Short: "Mount a single file",
		Run: func(cmd *cobra.Command, args []string) {
			client := newClient("/tmp/shimmer.sock", os.Getpid())
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

			// Get TTL option which is a number
			ttl, err := cmd.Flags().GetString("ttl")
			if err != nil {
				fmt.Printf("Error getting ttl flag: %v\n", err)
				os.Exit(1)
			}
			if len(ttl) == 0 {
				ttl = "8h"
			}
			lgr.Debug("Mounting with TTL: ", slog.String("ttl", ttl))

			resp, err := client.Send("/mount/single", map[string]interface{}{
				"source_file": sourceFile,
				"mount_point": mountPoint,
				"ttl":         ttl,
			})
			if err != nil {
				fmt.Printf("Error mounting single file: %v\n", err)
				os.Exit(1)
			}

			var dResp rpc.DataResponse
			if err := json.Unmarshal(resp, &dResp); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(dResp.Data, &result); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}
			lgr.Info("Mounted single file %s at %s (port: %v)\n", result["source_file"], mountPoint, result["port"])
		},
	})

	mountsCmd := &cobra.Command{
		Use:   "mounts",
		Short: "Jump into the mounts subcommand",
		Long:  `This command allows you to manage mounts in the shimmer server.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Please use 'shimmer mounts list' to list all mounts.")
			fmt.Println("Use 'shimmer mounts <subcommand>' for more options.")
			os.Exit(0)
		},
	}
	mountsCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List all mounts",
		Run: func(cmd *cobra.Command, args []string) {
			client := newClient("/tmp/shimmer.sock", os.Getpid())
			resp, err := client.Send("/mount/list", nil)
			if err != nil {
				fmt.Printf("Error listing mounts: %v\n", err)
				os.Exit(1)
			}

			var dResp rpc.DataResponse
			if err := json.Unmarshal(resp, &dResp); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}
			handleAuthCliError(dResp)

			var mounts mount.ListKnownMountsResponse
			if err := json.Unmarshal(dResp.Data, &mounts); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}

			if len(mounts.Mounts) == 0 {
				fmt.Println("No mounts found.")
				return
			}
			fmt.Println("Known mounts:")
			for _, m := range mounts.Mounts {
				fmt.Println(m.Name, "->", m.MountPath)
			}
		},
	})
	rootCmd.AddCommand(mountsCmd)

	fsCmd := &cobra.Command{
		Use:   "fs",
		Short: "Jump into the fs subcommand",
		Long:  `This command allows you to manage filesystems in the shimmer server.`,
	}

	fsRegisterCmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new filesystem",
		Run: func(cmd *cobra.Command, args []string) {
			name, _ := cmd.Flags().GetString("name")
			src, _ := cmd.Flags().GetString("src")
			removeOnImport, _ := cmd.Flags().GetBool("remove-on-import")
			if len(name) == 0 || len(src) == 0 {
				fmt.Println("Usage: shimmer fs register --name <name> --src <source_path> [--remove-on-import]")
				os.Exit(1)
			}

			// Process server will need to implement:
			path, err := resolvePathToAbsolute(src)
			if err != nil {
				fmt.Printf("Error resolving source path: %v\n", err)
				os.Exit(1)
			}

			resp, err := sendCommand("/fs/register", mount.FSRegisterRequest{
				Name:           name,
				SourcePath:     path,
				RemoveOnImport: removeOnImport,
			})
			if err != nil {
				fmt.Printf("Error registering filesystem: %v\n", err)
				os.Exit(1)
			}

			var dResp mount.FSRegisterResponse
			if err := json.Unmarshal(resp.Data, &dResp); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("Mounted filesystem successfully:", dResp.Success)
		},
	}
	fsRegisterCmd.Flags().String("name", "", "Name to register the filesystem with")
	fsRegisterCmd.Flags().String("src", "", "Source of path to register")
	fsRegisterCmd.Flags().Bool("remove-on-import", false, "Remove the source path after import")

	fsCmd.AddCommand(fsRegisterCmd)

	fsMountCmd := &cobra.Command{
		Use:   "mount",
		Short: "Mount a registered filesystem",
		Run: func(cmd *cobra.Command, args []string) {
			name, _ := cmd.Flags().GetString("name")
			if len(name) == 0 {
				fmt.Println("Usage: shimmer fs mount --name <name> --mount <mount_point>")
				os.Exit(1)
			}
			mountPoint, _ := cmd.Flags().GetString("mount")
			if len(mountPoint) == 0 {
				fmt.Println("Usage: shimmer fs mount --name <name> --mount <mount_point>")
				os.Exit(1)
			}
			resp, err := sendCommand("/fs/mount", mount.FSMountKnownFSRequest{
				Name:       name,
				MountPoint: mountPoint,
			})
			if err != nil {
				fmt.Printf("Error mounting filesystem: %v\n", err)
				os.Exit(1)
			} else if resp.Error != "" {
				fmt.Printf("Error mounting filesystem: %s\n", resp.Error)
				os.Exit(1)
			}

			var result mount.FSMountKnownFSResponse
			if err := json.Unmarshal(resp.Data, &result); err != nil {
				fmt.Printf("Error unmarshalling response: %v\n", err)
				os.Exit(1)
			}

			if !result.Success {
				fmt.Println("Failed to mount filesystem")
				os.Exit(1)
			}

			fmt.Printf("Mounted filesystem '%s' at '%s' successfully.\n", name, mountPoint)
		},
	}
	fsMountCmd.Flags().String("name", "", "Name of the filesystem to mount")
	fsMountCmd.Flags().String("mount", "", "Mount point to mount the filesystem at")
	fsCmd.AddCommand(fsMountCmd)

	fsInvalidateCmd := &cobra.Command{
		Use:   "invalidate",
		Short: "Invalidate a registered filesystem",
		Run: func(cmd *cobra.Command, args []string) {
			name, _ := cmd.Flags().GetString("name")
			if len(name) == 0 {
				fmt.Println("Usage: shimmer fs invalidate --name <name>")
				os.Exit(1)
			}
			resp := porcelainSendCommandT[mount.FSDeleteKnownMountResponse]("/fs/invalidate", mount.FSDeleteKnownMountRequest{
				Name: name,
			})

			fmt.Println("Invalidated filesystem successfully:", resp.Success)
		},
	}
	fsInvalidateCmd.Flags().String("name", "", "Name of the filesystem to invalidate")
	fsCmd.AddCommand(fsInvalidateCmd)

	fsDeleteCmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a registered filesystem",
		Run: func(cmd *cobra.Command, args []string) {
			name, _ := cmd.Flags().GetString("name")
			if len(name) == 0 {
				fmt.Println("Usage: shimmer fs delete --name <name>")
				os.Exit(1)
			}
			resp := porcelainSendCommandT[mount.FSDeleteKnownMountResponse]("/fs/delete", mount.FSDeleteKnownMountRequest{
				Name: name,
			})

			fmt.Println("Deleted filesystem successfully:", resp.Success)
		},
	}
	fsDeleteCmd.Flags().String("name", "", "Name of the filesystem to delete")
	fsCmd.AddCommand(fsDeleteCmd)

	fsEjectCmd := &cobra.Command{
		Use:   "eject",
		Short: "Eject a registered filesystem",
		Run: func(cmd *cobra.Command, args []string) {
			name, _ := cmd.Flags().GetString("name")
			if len(name) == 0 {
				fmt.Println("Usage: shimmer fs eject --name <name>")
				os.Exit(1)
			}
			resp := porcelainSendCommandT[mount.FSSuccessResponse]("/fs/eject", mount.FSKnownMountNameRequest{
				Name: name,
			})
			fmt.Println("Ejected filesystem successfully:", resp.Success)
		},
	}
	fsEjectCmd.Flags().String("name", "", "Name of the filesystem to eject")
	fsCmd.AddCommand(fsEjectCmd)

	fsUnmountCmd := &cobra.Command{
		Use:   "unmount",
		Short: "Unmount a registered filesystem",
		Run: func(cmd *cobra.Command, args []string) {
			name, _ := cmd.Flags().GetString("name")
			if len(name) == 0 {
				fmt.Println("Usage: shimmer fs unmount --name <name> --mount <mount_point>")
				os.Exit(1)
			}
			mountPoint, _ := cmd.Flags().GetString("mount")
			if len(mountPoint) == 0 {
				fmt.Println("Usage: shimmer fs unmount --name <name> --mount <mount_point>")
				os.Exit(1)
			}
			resp := porcelainSendCommandT[mount.FSSuccessResponse]("/fs/unmount", mount.FSUnmountKnownMountRequest{
				Name:       name,
				MountPoint: mountPoint,
			})
			if !resp.Success {
				fmt.Println("Failed to unmount filesystem")
				os.Exit(1)
			}
			fmt.Printf("Unmounted filesystem '%s' at '%s' successfully.\n", name, mountPoint)
		},
	}
	fsUnmountCmd.Flags().String("name", "", "Name of the filesystem to unmount")
	fsUnmountCmd.Flags().String("mount", "", "Mount point to unmount the filesystem from")
	fsCmd.AddCommand(fsUnmountCmd)

	rootCmd.AddCommand(fsCmd)

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
