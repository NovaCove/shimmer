package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/ztrue/shutdown"

	"github.com/NovaCove/shimmer/lib/server/mount"
	"github.com/NovaCove/shimmer/lib/server/rpc"
)

// mount -o port=63289,mountport=63289 -t nfs localhost:/foo ~/.yolo

func server() {
	// if len(os.Args) < 2 {
	// 	fmt.Printf("Usage: osview </path/to/folder> [port]\n")
	// 	return
	// } else if len(os.Args) == 3 {
	// 	port = os.Args[2]
	// }

	// listener, err := net.Listen("tcp", ":"+port)
	// if err != nil {
	// 	fmt.Printf("Failed to listen: %v\n", err)
	// 	return
	// }
	// fmt.Printf("Server running at %s\n", listener.Addr())

	// fs := memphis.FromOS(os.Args[1])
	// bfs := fs.AsBillyFS(0, 0)

	fmt.Println("Creating mount server...")
	srvr := mount.NewMountServer("/tmp/shimmer.sock", os.Getpid())

	fmt.Println("Registering handlers...")
	shutdown.Add(func() {
		fmt.Println("shutdown hook triggered, stopping server...")
		if err := srvr.Stop(); err != nil {
			fmt.Printf("Error stopping server: %v\n", err)
		}
	})

	// handler := nfshelper.NewNullAuthHandler(bfs)
	// cacheHelper := nfshelper.NewCachingHandler(handler, 1024)
	fmt.Println("Kicking off server go routine...")
	go func() {
		// fmt.Printf("%v", nfs.Serve(listener, cacheHelper))
		if err := srvr.Start(); err != nil {
			fmt.Printf("Error starting server: %v\n", err)
			return
		}
	}()

	fmt.Println("Server started, waiting for shutdown...")
	shutdown.Listen(syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Shutdown signal received, stopping server...")
}

func resolvePathToAbsolute(str string) (string, error) {
	if strings.HasPrefix(str, "file://") {
		str = strings.TrimPrefix(str, "file://")
	}
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
	rootCmd := &cobra.Command{
		Use:   "shimmer",
		Short: "shimmer",
		Long:  ``,
	}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "server",
		Short: "Start the shimmer server",
		Run: func(cmd *cobra.Command, args []string) {
			server()
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
			fmt.Printf("Mounted %s at %s (port: %v)\n", result["mount_point"], mountPoint, result["port"])
		},
	})

	// Execute root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
