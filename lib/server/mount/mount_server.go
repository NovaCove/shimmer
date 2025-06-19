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
	"path/filepath"
	"strings"

	"github.com/go-git/go-billy/v5"
	nfs "github.com/willscott/go-nfs"
	nfshelper "github.com/willscott/go-nfs/helpers"

	"github.com/willscott/memphis"

	"github.com/NovaCove/shimmer/lib/server/rpc"
)

type MountedListener struct {
	listener   net.Listener
	mountPoint string
}

type SingleMountedFileListener struct {
	MountedListener
	linkedFileSrcLoc  string // Path to the symlink for the single file
	linkedFileDestLoc string // Location of the symlink for the single file
}

type MountServer struct {
	*rpc.Server
	PID int

	lgr *slog.Logger

	listeners           []MountedListener
	singleFileListeners []SingleMountedFileListener
}

// NewMountServer creates a new MountServer instance with the specified Unix socket path.
func NewMountServer(unixSocket string, pid int, lgr *slog.Logger) *MountServer {
	return &MountServer{
		Server:              rpc.NewServer(unixSocket, lgr),
		PID:                 pid,
		lgr:                 lgr,
		listeners:           []MountedListener{},
		singleFileListeners: []SingleMountedFileListener{},
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

type ContextualFS struct {
	billy.Filesystem
	lgr *slog.Logger
}

// func (cfs *ContextualFS) OpenWithContext(ctx context.Context, filename string) (billy.File, error) {
// 	// user := getUserFromContext(ctx)
// 	// fmt.Println("Opening file with user:", user)
// 	cfs.lgr.Info("Opening file with context:")
// 	cfs.lgr.Info("", ctx)

// 	return cfs.Filesystem.Open(filename)
// }

// func getUserFromContext(ctx context.Context) *User {
// 	if user, ok := ctx.Value("user").(*User); ok {
// 		return user
// 	}
// 	return nil
// }

func (s *MountServer) mountListener(path, mountPoint string, port int, cacheAsListener bool) error {
	s.lgr.Info("Mounting path", slog.String("source", path), slog.String("mountPath", mountPoint))
	if path == "" || mountPoint == "" {
		return fmt.Errorf("path and mount_point must be provided")
	}

	// Logic here to load the filesystem into the handler for NFS
	if strings.HasPrefix(path, "file://") {
		return fmt.Errorf("path must be relative, not absolute")
	}
	var destPath = strings.TrimPrefix(path, "file://")
	fs := memphis.FromOS(path)
	s.lgr.Info("adding contextual FS")
	bfs := ContextualFS{fs.AsBillyFS(0, 0), s.lgr}
	handler := nfshelper.NewNullAuthHandler(bfs)
	cacheHelper := nfshelper.NewCachingHandler(handler, 1024)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", port, err)
	}

	s.lgr.Info("Mount server running at", slog.Any("addr", listener.Addr()))
	go func() {
		if err := nfs.Serve(listener, cacheHelper); err != nil {
			s.lgr.Error("Error serving NFS", slog.Any("err", err))
			return
		}
	}()

	// Now run the os exec command to mount the NFS share
	s.lgr.Debug("Mounting NFS share at", slog.String("mountPath", mountPoint))
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		return fmt.Errorf("failed to create mount point %s: %w", mountPoint, err)
	}

	s.lgr.Debug("Setting permissions on mount point", slog.String("mountPath", mountPoint))
	if err := os.Chmod(mountPoint, 0755); err != nil {
		return fmt.Errorf("failed to set permissions on mount point %s: %w", mountPoint, err)
	}

	s.lgr.Debug(
		"Mounting NFS share from",
		slog.String("source", fmt.Sprintf("localhost:%s", destPath)),
		slog.String("mountPath", mountPoint),
	)
	cmd := exec.Command("mount", "-o", fmt.Sprintf("port=%d,mountport=%d", port, port), "-t", "nfs", fmt.Sprintf("localhost:%s", destPath), mountPoint)
	if err := cmd.Run(); err != nil {
		s.lgr.Error("Failed to mount NFS share:", slog.Any("mount error", err))
		return fmt.Errorf("failed to mount NFS share: %w", err)
	}

	s.lgr.Info("Mounted NFS share successfully at", slog.String("mountPath", mountPoint))
	if cacheAsListener {
		s.listeners = append(s.listeners, struct {
			listener   net.Listener
			mountPoint string
		}{
			listener:   listener,
			mountPoint: mountPoint,
		})
	}

	return nil
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

	// For now, do some port mapping, later we'll prefix in the nfs paths for mounting
	port := randomPort()

	if err := s.mountListener(req.Path, req.MountPoint, port, true); err != nil {
		s.lgr.Error("Failed to mount listener", slog.String("mountPath", req.MountPoint), slog.Any("error", err))
		return nil, fmt.Errorf("failed to mount listener for mount point %s: %w", req.MountPoint, err)
	}

	return json.Marshal(map[string]any{
		"mount_point": req.MountPoint,
		"port":        port,
	})
}

const (
	shimmerDir     = ".shimmer"
	shimmerDataDir = ".mount-data"
)

func homeShimmerDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	// See if the shimmer directory exists, if not create it
	if _, err := os.Stat(filepath.Join(homeDir, shimmerDir)); err != nil && !os.IsNotExist(err) {
		return "", err
	}

	shimmerDirPath := filepath.Join(homeDir, shimmerDir, shimmerDataDir)
	if err := os.MkdirAll(shimmerDirPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create shimmer directory %s: %w", shimmerDirPath, err)
	}
	return shimmerDirPath, nil
}

func (s *MountServer) StartSingleMountFileHandler(ctxt context.Context, request []byte) ([]byte, error) {
	s.lgr.Debug("Received single file mount request")
	s.lgr.Debug("Request:\n", slog.Any("request", request))
	var req struct {
		SourceFile string `json:"source_file"` // Path to the source file to be mounted
		MountPoint string `json:"mount_point"` // Path where the file should be mounted
	}
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}

	// For now, do some port mapping, later we'll prefix in the nfs paths for mounting
	port := randomPort()
	if req.SourceFile == "" || req.MountPoint == "" {
		return nil, fmt.Errorf("source_file and mount_point must be provided")
	}

	// Grab the base dir to mount the dir to.
	baseDir := filepath.Dir(req.SourceFile)
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("base directory %s does not exist", baseDir)
	}

	// Ensure that our hidden data dir exists.
	shimmerDataDir, err := homeShimmerDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get shimmer data directory: %w", err)
	}

	fName := filepath.Base(req.SourceFile)
	// Get a random file name to mount the dir at
	linkedDirMountLoc := filepath.Join(shimmerDataDir, fmt.Sprintf("%s-%d", fName, rand.Intn(10000)))
	s.lgr.Debug("Determined linked directory mount location", slog.String("linkedDirMountLoc", linkedDirMountLoc))
	if _, err := os.Stat(linkedDirMountLoc); err == nil {
		return nil, fmt.Errorf("mount point %s already exists, please choose a different name", linkedDirMountLoc)
	}

	// Make the mount point directory
	s.lgr.Debug("Creating mount point directory", slog.String("mountPath", linkedDirMountLoc))
	if err := os.MkdirAll(linkedDirMountLoc, 0755); err != nil {
		return nil, fmt.Errorf("failed to create mount point directory %s: %w", linkedDirMountLoc, err)
	}

	// Mount the directory using NFS
	s.lgr.Debug("Mounting single file listener", slog.String("sourceFile", req.SourceFile), slog.String("mountPath", linkedDirMountLoc))
	if err := s.mountListener(baseDir, linkedDirMountLoc, port, false); err != nil {
		s.lgr.Error("Failed to mount single file listener", slog.String("mountPath", linkedDirMountLoc), slog.Any("error", err))
		return nil, fmt.Errorf("failed to mount single file listener for mount point %s: %w", linkedDirMountLoc, err)
	}
	s.lgr.Info("Mounted single file listener successfully", slog.String("mountPoint", linkedDirMountLoc))

	// Create a symlink to the source file in the mount point
	linkedFileLoc := filepath.Join(linkedDirMountLoc, fName)
	s.lgr.Debug("Creating symlink for single file mount", slog.String("linkedFileLoc", linkedFileLoc), slog.String("sourceFile", req.SourceFile))
	if err := os.Symlink(linkedFileLoc, req.MountPoint); err != nil {
		s.lgr.Error("Failed to create symlink for single file mount", slog.String("linkedFileLoc", linkedFileLoc), slog.String("sourceFile", req.SourceFile), slog.Any("error", err))
		return nil, fmt.Errorf("failed to create symlink %s -> %s: %w", linkedFileLoc, req.MountPoint, err)
	}
	s.lgr.Info("Created symlink for single file mount", slog.String("linkedFileLoc", linkedFileLoc), slog.String("sourceFile", req.SourceFile))
	s.singleFileListeners = append(s.singleFileListeners, SingleMountedFileListener{
		MountedListener: MountedListener{
			listener:   s.listeners[len(s.listeners)-1].listener, // Use the last listener
			mountPoint: linkedDirMountLoc,
		},
		linkedFileSrcLoc:  req.MountPoint,
		linkedFileDestLoc: linkedFileLoc,
	})
	s.lgr.Info("Single file mounted successfully", slog.String("mountPoint", linkedDirMountLoc), slog.String("linkedFileLoc", linkedFileLoc))
	return json.Marshal(map[string]any{
		"mount_point": linkedDirMountLoc,
		"linked_file": linkedFileLoc,
		"port":        port,
	})
}

func randomPort() int {
	return 10000 + rand.Intn(10000) // Random port between 10000 and 20000
}

func (s *MountServer) Start() error {
	s.Server.RegisterHandler("/auth/check", s.IsPIDAuthenticatedHandler)
	s.Server.RegisterHandler("/mount/start", s.StartMountHandler)
	s.Server.RegisterHandler("/mount/single", s.StartSingleMountFileHandler)

	if err := s.Server.Start(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	s.lgr.Info("Mount server running at %s\n", slog.String("unixSocketPath", s.Server.UnixSocket))
	return nil
}

func (s *MountServer) unmountSingleFile(l net.Listener, mountPath, linkedFileLoc string) error {
	// First unlink the symlink
	s.lgr.Debug("Unlinking symlink for file", slog.String("linkedFileLoc", linkedFileLoc))
	if err := os.Remove(linkedFileLoc); err != nil {
		return fmt.Errorf("failed to remove symlink %s: %w", linkedFileLoc, err)
	}
	s.lgr.Debug("Unlinked symlink for file", slog.String("linkedFileLoc", linkedFileLoc))

	return s.unmountListener(l, mountPath)
}

func (s *MountServer) unmountListener(listener net.Listener, mountPoint string) error {
	s.lgr.Debug("Unmounting mount point:", slog.String("mountPath", mountPoint))

	if err := listener.Close(); err != nil {
		return fmt.Errorf("failed to close listener for mount point %s: %w", mountPoint, err)
	}

	cmd := exec.Command("umount", mountPoint)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to unmount %s: %w", mountPoint, err)
	}
	s.lgr.Debug("Unmounted", slog.String("mountPath", mountPoint))
	if err := os.RemoveAll(mountPoint); err != nil {
		return fmt.Errorf("failed to remove mount point %s: %w", mountPoint, err)
	}
	s.lgr.Debug("Removed mount point", slog.String("mountPath", mountPoint))
	return nil
}

func (s *MountServer) Stop() error {
	s.lgr.Info("Stopping mount server...")
	if err := s.Server.Stop(); err != nil {
		return fmt.Errorf("failed to stop server: %w", err)
	}

	s.lgr.Debug("Server stopped, unmounting all mount points...")
	for _, listener := range s.listeners {
		if err := s.unmountListener(listener.listener, listener.mountPoint); err != nil {
			s.lgr.Error("Failed to unmount listener", slog.String("mountPath", listener.mountPoint), slog.Any("error", err))
			return fmt.Errorf("failed to unmount listener for mount point %s: %w", listener.mountPoint, err)
		}
	}

	for _, singleFileListener := range s.singleFileListeners {
		if err := s.unmountSingleFile(singleFileListener.listener, singleFileListener.mountPoint, singleFileListener.linkedFileSrcLoc); err != nil {
			s.lgr.Error("Failed to unmount single file listener", slog.String("mountPath", singleFileListener.mountPoint), slog.Any("error", err))
			return fmt.Errorf("failed to unmount single file listener for mount point %s: %w", singleFileListener.mountPoint, err)
		}
	}
	s.lgr.Info("All mount points unmounted successfully")

	s.listeners = nil
	return nil
}
