package mount

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"

	nfs "github.com/willscott/go-nfs"
	nfshelper "github.com/willscott/go-nfs/helpers"

	"github.com/willscott/memphis"

	"github.com/NovaCove/shimmer/lib/server/rpc"
)

type MountServer struct {
	*rpc.Server
	PID int

	lgr *slog.Logger

	listeners []struct {
		listener   net.Listener
		mountPoint string
	}
}

// NewMountServer creates a new MountServer instance with the specified Unix socket path.
func NewMountServer(unixSocket string, pid int, lgr *slog.Logger) *MountServer {
	return &MountServer{
		Server: rpc.NewServer(unixSocket, lgr),
		PID:    pid,
		lgr:    lgr,
		listeners: []struct {
			listener   net.Listener
			mountPoint string
		}{},
	}
}

func (s *MountServer) IsPIDAuthenticatedHandler(ctxt context.Context, request []byte) ([]byte, error) {
	var req rpc.Request
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}

	s.lgr.Debug("Checking if pid is authenticated:", slog.Int("pid", req.PID))
	server := ctxt.Value("server").(*MountServer)
	if server.IsPIDAuthenticated(req.PID) {
		return json.Marshal(true)
	}
	return json.Marshal(false)
}

func (s *MountServer) StartMountHandler(ctxt context.Context, request []byte) ([]byte, error) {

	s.lgr.Debug("Received mount request")
	s.lgr.Debug("Request:\n", slog.Any("request", request))
	var req struct {
		Path       string `json:"path"`
		MountPoint string `json:"mount_point"`
	}
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}

	s.lgr.Info("Mounting path", slog.String("source", req.Path), slog.String("mountPath", req.MountPoint))
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
	s.lgr.Info("Mount server running at", slog.Any("addr", listener.Addr()))
	go func() {
		if err := nfs.Serve(listener, cacheHelper); err != nil {
			s.lgr.Error("Error serving NFS", slog.Any("err", err))
			return
		}
	}()

	// Now run the os exec command to mount the NFS share
	s.lgr.Debug("Mounting NFS share at", slog.String("mountPath", req.MountPoint))
	if err := os.MkdirAll(req.MountPoint, 0755); err != nil {
		return nil, fmt.Errorf("failed to create mount point %s: %w", req.MountPoint, err)
	}

	s.lgr.Debug("Setting permissions on mount point", slog.String("mountPath", req.MountPoint))
	if err := os.Chmod(req.MountPoint, 0755); err != nil {
		return nil, fmt.Errorf("failed to set permissions on mount point %s: %w", req.MountPoint, err)
	}

	s.lgr.Debug(
		"Mounting NFS share from",
		slog.String("source", fmt.Sprintf("localhost:%s", path)),
		slog.String("mountPath", req.MountPoint),
	)
	cmd := exec.Command("mount", "-o", fmt.Sprintf("port=%d,mountport=%d", port, port), "-t", "nfs", fmt.Sprintf("localhost:%s", path), req.MountPoint)
	if err := cmd.Run(); err != nil {
		s.lgr.Error("Failed to mount NFS share:", slog.Any("mount error", err))
		return nil, fmt.Errorf("failed to mount NFS share: %w", err)
	}

	s.lgr.Info("Mounted NFS share successfully at", slog.String("mountPath", req.MountPoint))
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
	s.lgr.Info("Mount server running at %s\n", slog.String("unixSocketPath", s.Server.UnixSocket))
	return nil
}

func (s *MountServer) Stop() error {
	s.lgr.Info("Stopping mount server...")
	if err := s.Server.Stop(); err != nil {
		return fmt.Errorf("failed to stop server: %w", err)
	}

	s.lgr.Debug("Server stopped, unmounting all mount points...")
	for _, listener := range s.listeners {
		s.lgr.Debug("Unmounting mount point:", slog.String("mountPath", listener.mountPoint))

		if err := listener.listener.Close(); err != nil {
			return fmt.Errorf("failed to close listener for mount point %s: %w", listener.mountPoint, err)
		}

		cmd := exec.Command("umount", listener.mountPoint)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to unmount %s: %w", listener.mountPoint, err)
		}
		s.lgr.Debug("Unmounted", slog.String("mountPath", listener.mountPoint))
		if err := os.RemoveAll(listener.mountPoint); err != nil {
			return fmt.Errorf("failed to remove mount point %s: %w", listener.mountPoint, err)
		}
		s.lgr.Debug("Removed mount point", slog.String("mountPath", listener.mountPoint))
	}
	s.listeners = nil
	return nil
}
