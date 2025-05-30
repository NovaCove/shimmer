package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/willscott/memphis"
	"github.com/ztrue/shutdown"

	"github.com/NovaCove/shimmer/lib"
	nfs "github.com/willscott/go-nfs"
	nfshelper "github.com/willscott/go-nfs/helpers"
)

// mount -o port=63289,mountport=63289 -t nfs localhost:/foo ~/.yolo

type MountServer struct {
	*lib.Server
	PID int

	listeners []struct {
		listener   net.Listener
		mountPoint string
	}
}

// NewMountServer creates a new MountServer instance with the specified Unix socket path.
func NewMountServer(unixSocket string, pid int) *MountServer {
	return &MountServer{
		Server: lib.NewServer(unixSocket),
		PID:    pid,
		listeners: []struct {
			listener   net.Listener
			mountPoint string
		}{},
	}
}

func (s *MountServer) IsPIDAuthenticatedHandler(ctxt context.Context, request []byte) ([]byte, error) {
	var req lib.Request
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}

	server := ctxt.Value("server").(*MountServer)
	if server.IsPIDAuthenticated(req.PID) {
		return json.Marshal(true)
	}
	return json.Marshal(false)
}

func (s *MountServer) StartMountHandler(ctxt context.Context, request []byte) ([]byte, error) {

	fmt.Println("Received mount request")
	fmt.Printf("Request: %s\n", string(request))
	var req struct {
		Path       string `json:"path"`
		MountPoint string `json:"mount_point"`
	}
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}

	fmt.Printf("Mounting path: %s at mount point: %s\n", req.Path, req.MountPoint)
	if req.Path == "" || req.MountPoint == "" {
		return nil, fmt.Errorf("path and mount_point must be provided")
	}

	// Logic here to load the filesystem into the handler for NFS
	if strings.HasPrefix(req.Path, "file://") {
		return nil, fmt.Errorf("path must be relative, not absolute")
	}
	var path = strings.TrimPrefix(req.Path, "file://")
	fs := memphis.FromOS(req.Path)
	bfs := fs.AsBillyFS(0, 0)
	handler := nfshelper.NewNullAuthHandler(bfs)
	cacheHelper := nfshelper.NewCachingHandler(handler, 1024)

	// For now, do some port mapping, later we'll prefix in the nfs paths for mounting
	port := randomPort()
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("failed to listen on port %d: %w", port, err)
	}
	fmt.Printf("Mount server running at %s\n", listener.Addr())
	go func() {
		if err := nfs.Serve(listener, cacheHelper); err != nil {
			fmt.Printf("Error serving NFS: %v\n", err)
			return
		}
	}()

	// Now run the os exec command to mount the NFS share
	fmt.Println("Mounting NFS share at", req.MountPoint)
	if err := os.MkdirAll(req.MountPoint, 0755); err != nil {
		return nil, fmt.Errorf("failed to create mount point %s: %w", req.MountPoint, err)
	}

	fmt.Println("Setting permissions on mount point", req.MountPoint)
	if err := os.Chmod(req.MountPoint, 0755); err != nil {
		return nil, fmt.Errorf("failed to set permissions on mount point %s: %w", req.MountPoint, err)
	}

	fmt.Println("Mounting NFS share from", fmt.Sprintf("localhost:%s", path), "to", req.MountPoint)
	cmd := exec.Command("mount", "-o", fmt.Sprintf("port=%d,mountport=%d", port, port), "-t", "nfs", fmt.Sprintf("localhost:%s", path), req.MountPoint)
	if err := cmd.Run(); err != nil {
		fmt.Println("Failed to mount NFS share:", err)
		return nil, fmt.Errorf("failed to mount NFS share: %w", err)
	}

	fmt.Println("Mounted NFS share successfully at", req.MountPoint)
	s.listeners = append(s.listeners, struct {
		listener   net.Listener
		mountPoint string
	}{
		listener:   listener,
		mountPoint: req.MountPoint,
	})

	return json.Marshal(map[string]any{
		"mount_point": req.MountPoint,
		"port":        port,
	})
}

func randomPort() int {
	return 10000 + rand.Intn(10000) // Random port between 10000 and 20000
}

func (s *MountServer) Start() error {
	s.Server.RegisterHandler("/auth/check", s.IsPIDAuthenticatedHandler)
	s.Server.RegisterHandler("/mount/start", s.StartMountHandler)

	if err := s.Server.Start(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	fmt.Printf("Mount server running at %s\n", s.Server.UnixSocket)
	return nil
}

func (s *MountServer) Stop() error {
	fmt.Println("Stopping mount server...")
	if err := s.Server.Stop(); err != nil {
		return fmt.Errorf("failed to stop server: %w", err)
	}

	fmt.Println("Server stopped, unmounting all mount points...")
	for _, listener := range s.listeners {
		fmt.Println("Unmounting mount point:", listener.mountPoint)

		if err := listener.listener.Close(); err != nil {
			return fmt.Errorf("failed to close listener for mount point %s: %w", listener.mountPoint, err)
		}

		cmd := exec.Command("umount", listener.mountPoint)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to unmount %s: %w", listener.mountPoint, err)
		}
		fmt.Printf("Unmounted %s\n", listener.mountPoint)
		if err := os.RemoveAll(listener.mountPoint); err != nil {
			return fmt.Errorf("failed to remove mount point %s: %w", listener.mountPoint, err)
		}
		fmt.Printf("Removed mount point %s\n", listener.mountPoint)
	}
	s.listeners = nil
	return nil
}

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
	srvr := NewMountServer("/tmp/shimmer.sock", os.Getpid())

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
			client := lib.NewClient("/tmp/shimmer.sock", os.Getpid())
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
