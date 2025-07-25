package mount

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	touchid "github.com/NovaCove/shimmer/lib/auth/touchid"
	"github.com/go-git/go-billy/v5"
	nfs "github.com/willscott/go-nfs"
	nfshelper "github.com/willscott/go-nfs/helpers"

	"github.com/willscott/memphis"

	serrors "github.com/NovaCove/shimmer/lib/errors"
	"github.com/NovaCove/shimmer/lib/server/config"
	"github.com/NovaCove/shimmer/lib/server/rpc"
	"github.com/NovaCove/shimmer/lib/server/secure/internaldata"
	"github.com/NovaCove/shimmer/lib/server/secure/keymanagement"
	"github.com/NovaCove/shimmer/lib/server/secure/transform"
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

type ServerState int

const (
	ServerStateStopped ServerState = iota
	ServerStateStarting
	ServerStateLocked
	ServerStateRunning
	ServerStateStopping
	ServerStateError
)

// String returns a string representation of the ServerState.
func (s ServerState) String() string {
	switch s {
	case ServerStateStopped:
		return "stopped"
	case ServerStateStarting:
		return "starting"
	case ServerStateLocked:
		return "locked"
	case ServerStateRunning:
		return "running"
	case ServerStateStopping:
		return "stopping"
	case ServerStateError:
		return "error"
	default:
		return "unknown"
	}
}

type serverState struct {
	// stateLock is an atomic mutex over an enum value that indicates the state of the server
	sync.RWMutex
	state ServerState
}

type MountServer struct {
	// stateLock is an atomic mutex over an enum value that indicates the state of the server.
	state serverState

	*rpc.Server
	PID int

	lgr *slog.Logger

	listeners           []MountedListener
	singleFileListeners []SingleMountedFileListener

	skm *keymanagement.SecureKeychainManager

	internalData internaldata.InternalData

	bootedAt   time.Time
	unlockedAt time.Time
	lockedAt   time.Time

	diagnostic ServerDiagnostic
}

type ServerDiagnostic struct {
	LaunchctlManaged bool `json:"launchctl_managed"`
}

// NewMountServer creates a new MountServer instance with the specified Unix socket path.
func NewMountServer(unixSocket string, pid int, lgr *slog.Logger) *MountServer {
	return &MountServer{
		state: serverState{
			state: ServerStateLocked,
		},
		Server:              rpc.NewServer(unixSocket, lgr),
		PID:                 pid,
		lgr:                 lgr,
		listeners:           []MountedListener{},
		singleFileListeners: []SingleMountedFileListener{},
		bootedAt:            time.Now(),
		diagnostic:          ServerDiagnostic{},
	}
}

func (s *MountServer) GetServerState() ServerState {
	s.state.RLock()
	defer s.state.RUnlock()
	return s.state.state
}

func (s *MountServer) SetServerState(state ServerState) {
	s.state.Lock()
	defer s.state.Unlock()
	s.lgr.Debug("Setting server state", slog.String("state", state.String()))
	s.state.state = state
}

func (s *MountServer) initializeCrypto() error {
	var err error
	if s.skm, err = keymanagement.InitializeSecureKeychain(s.lgr); err != nil {
		return fmt.Errorf("failed to initialize secure keychain manager: %w", err)
	}

	s.lgr.Info("Secure keychain manager initialized and authenticated successfully")
	return nil
}

const EncKeyInternalDataName = "internal-data-encryption-key"

func (s *MountServer) dataDirPath() (string, error) {
	// Get the home directory and create the shimmer data directory if it doesn't exist
	dataPath, err := internalDataDirPath()
	if err != nil {
		return "", fmt.Errorf("failed to get shimmer data directory: %w", err)
	}

	s.lgr.Debug("Data directory path:", slog.String("dataPath", dataPath))
	return dataPath, nil
}

func (s *MountServer) initializeInternalData() error {
	// Initialize internal data storage
	dataPath, err := s.dataDirPath()
	if err != nil {
		return fmt.Errorf("failed to get shimmer data directory: %w", err)
	}

	s.lgr.Debug("Initializing internal data storage at", slog.String("dataPath", dataPath))
	internalDataKey, err := s.skm.RetrieveEncryptionKey(EncKeyInternalDataName)
	if err != nil {
		// DIDNTDO(ttacon): distinguish between not found and other errors.
		return serrors.ErrIsNotBootstrapped
	}

	s.internalData = internaldata.NewInternalData(dataPath, []byte(internalDataKey), s.lgr, s.skm)

	s.lgr.Debug("Loading internal data storage")
	if err := s.internalData.Load(); err != nil {
		return fmt.Errorf("failed to load internal data: %w", err)
	} else if _, err := s.internalData.LoadMounts(); err != nil {
		return fmt.Errorf("failed to load mounts from internal data: %w", err)
	}

	s.lgr.Info("Internal data storage initialized successfully")
	return nil
}

func (s *MountServer) checkLaunchctlSetup() error {
	s.lgr.Debug("Checking if server is running under launchctl")
	if _, err := exec.LookPath("launchctl"); err != nil {
		s.lgr.Warn("launchctl not found, server may not be running under launchctl")
		return fmt.Errorf("launchctl not found, server may not be running under launchctl")
	}

	// See if launchctl is managing this process
	cmd := exec.Command("launchctl", "list")
	output, err := cmd.CombinedOutput()
	if err != nil {
		s.lgr.Warn("Failed to check launchctl status", slog.Any("error", err))
		return fmt.Errorf("failed to check launchctl status: %w", err)
	} else if !strings.Contains(string(output), "shimmer") {
		s.lgr.Warn("Server is not managed by launchctl, please consider using launchctl to manage the server")
		return fmt.Errorf("server is not managed by launchctl, please consider using launchctl to manage the server")
	}
	s.lgr.Info("Server is managed by launchctl")
	s.diagnostic.LaunchctlManaged = true
	return nil
}

func (s *MountServer) Initialize(ctxt context.Context) error {
	s.lgr.Debug("Initializing mount server")
	if s.GetServerState() != ServerStateStopped && s.GetServerState() != ServerStateLocked {
		return fmt.Errorf("server is not in stopped state, cannot start, current state: %s", s.GetServerState().String())
	}

	s.SetServerState(ServerStateStarting)
	s.lgr.Info("Mount server starting...")

	// Initialize:
	// 1. Ensure we're installed correctly (dirs, files, etc.)
	// 2. Ensure we have the correct permissions to run.
	// 3. See if we're installed via launctl. If not, drop a warning.
	if err := s.checkLaunchctlSetup(); err != nil {
		s.lgr.Warn("Launchctl setup check failed", slog.Any("error", err))
	}
	// 4. See if we have our keychain set up, if not, drop a warning.
	// 5. Ensure that we can authenticate to our keychain.
	if err := s.initializeCrypto(); err != nil {
		return errors.Join(err, errors.New("failed to initialize crypto"))
	}
	s.lgr.Debug("Crypto initialized successfully")
	// 6. Validate our configuration, if any.
	if err := s.initializeInternalData(); err != nil {
		return fmt.Errorf("failed to initialize internal data: %w", err)
	}
	s.lgr.Debug("Internal data initialized successfully")

	s.SetServerState(ServerStateRunning)

	s.lgr.Info("Mount server initialized successfully")
	return nil
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

func (c ContextualFS) Open(filename string) (billy.File, error) {
	c.lgr.Info("Opening file", slog.String("filename", filename))
	// Here we could add context-specific logic, e.g., logging, user info, etc.
	// For now, we just log the filename.
	file, err := c.Filesystem.Open(filename)
	if err != nil {
		c.lgr.Error("Failed to open file", slog.String("filename", filename), slog.Any("error", err))
		return nil, err
	}
	c.lgr.Info("File opened successfully", slog.String("filename", filename))
	return file, nil
}

func (c ContextualFS) ReadDir(dirname string) ([]os.FileInfo, error) {
	c.lgr.Info("Reading directory", slog.String("dirname", dirname))
	// Here we could add context-specific logic, e.g., logging, user info, etc.
	// For now, we just log the directory name.
	files, err := c.Filesystem.ReadDir(dirname)
	if err != nil {
		c.lgr.Error("Failed to read directory", slog.String("dirname", dirname), slog.Any("error", err))
		return nil, err
	}
	c.lgr.Info("Directory read successfully", slog.String("dirname", dirname), slog.Int("fileCount", len(files)))
	return files, nil
}

func (c ContextualFS) Stat(filename string) (os.FileInfo, error) {
	c.lgr.Info("Statting file", slog.String("filename", filename))
	// Here we could add context-specific logic, e.g., logging, user info, etc.
	// For now, we just log the filename.
	fileInfo, err := c.Filesystem.Stat(filename)
	if err != nil {
		c.lgr.Error("Failed to stat file", slog.String("filename", filename), slog.Any("error", err))
		return nil, err
	}
	c.lgr.Info("File statted successfully", slog.String("filename", filename), slog.Any("fileInfo", fileInfo))
	return fileInfo, nil
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

func (s *MountServer) mountListener(path, mountPoint string, port int, cacheAsListener bool, ttl string) error {
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

		go func() {
			// Keep the listener alive for the specified TTL
			if len(ttl) > 0 {
				dur, err := time.ParseDuration(ttl)
				if err != nil {
					return
				}
				time.Sleep(dur)
				s.lgr.Info("Stopping listener after TTL", slog.String("ttl", ttl))
				s.unmountListener(listener, mountPoint)
			}
		}()
	}

	return nil
}

// DIDNTDO(ttacon): this is a duplicate of the above function, refactor to combine via billy.FS param.
func (s *MountServer) mountListenerFromBillyFS(name string, gbfs billy.Filesystem, mountPoint string, port int, cacheAsListener bool, ttl string) error {
	s.lgr.Info("Mounting path", slog.String("mountPath", mountPoint))
	if mountPoint == "" {
		return fmt.Errorf("path and mount_point must be provided")
	}

	bfs := ContextualFS{gbfs, s.lgr}
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
		slog.String("mountPath", mountPoint),
	)
	// NOTE(ttacon): why was the destPath used here before? Where we bypassing the NFS server somehow?
	destPath := gbfs.Root() // Get the root of the billy filesystem
	s.lgr.Debug("Mounting NFS share from billy filesystem root", slog.String("destPath", destPath))
	cmd := exec.Command("mount", "-o", fmt.Sprintf("port=%d,mountport=%d", port, port), "-t", "nfs", fmt.Sprintf("localhost:%s", name), mountPoint)
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

		go func() {
			// Keep the listener alive for the specified TTL
			if len(ttl) > 0 {
				dur, err := time.ParseDuration(ttl)
				if err != nil {
					return
				}
				time.Sleep(dur)
				s.lgr.Info("Stopping listener after TTL", slog.String("ttl", ttl))
				s.unmountListener(listener, mountPoint)
			}
		}()
	}

	return nil
}

var ErrServerIsLocked = fmt.Errorf("server is locked, please authenticate first")

func (s *MountServer) StartMountHandler(ctxt context.Context, request []byte) ([]byte, error) {
	s.lgr.Debug("Received mount request")
	s.lgr.Debug("Request:\n", slog.Any("request", request))
	var req struct {
		Path       string `json:"path"`
		MountPoint string `json:"mount_point"`
		TTL        string `json:"ttl"`
	}
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}

	// For now, do some port mapping, later we'll prefix in the nfs paths for mounting
	port := randomPort()

	if err := s.mountListener(req.Path, req.MountPoint, port, true, req.TTL); err != nil {
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

var internalDataDirName = "internaldata"

func internalDataDirPath() (string, error) {
	return shimmerInternalPath(internalDataDirName)
}

func shimmerInternalPath(finalSegment string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	destDir := filepath.Join(homeDir, shimmerDir, finalSegment)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", err
	}
	return destDir, nil
}

func (s *MountServer) StartSingleMountFileHandler(ctxt context.Context, request []byte) ([]byte, error) {
	s.lgr.Debug("Received single file mount request")
	s.lgr.Debug("Request:\n", slog.Any("request", request))
	var req struct {
		SourceFile string `json:"source_file"` // Path to the source file to be mounted
		MountPoint string `json:"mount_point"` // Path where the file should be mounted
		TTL        string `json:"ttl"`
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
	if err := s.mountListener(baseDir, linkedDirMountLoc, port, false, req.TTL); err != nil {
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
	lsnr := s.listeners[len(s.listeners)-1].listener
	s.singleFileListeners = append(s.singleFileListeners, SingleMountedFileListener{
		MountedListener: MountedListener{
			listener:   lsnr,
			mountPoint: linkedDirMountLoc,
		},
		linkedFileSrcLoc:  req.MountPoint,
		linkedFileDestLoc: linkedFileLoc,
	})
	s.lgr.Info("Single file mounted successfully", slog.String("mountPoint", linkedDirMountLoc), slog.String("linkedFileLoc", linkedFileLoc))

	go func() {
		if len(req.TTL) > 0 {
			dur, err := time.ParseDuration(req.TTL)
			if err != nil {
				return
			}
			time.Sleep(dur)
			s.lgr.Info("Stopping single file listener after TTL", slog.String("ttl", req.TTL))
			s.unmountSingleFile(lsnr, linkedDirMountLoc, linkedFileLoc)
		}
	}()

	return json.Marshal(map[string]any{
		"mount_point": linkedDirMountLoc,
		"linked_file": linkedFileLoc,
		"port":        port,
	})
}

func randomPort() int {
	return 10000 + rand.Intn(10000) // Random port between 10000 and 20000
}

func (s *MountServer) handlerAuthWrapper(handler rpc.Handler) rpc.Handler {
	return func(ctxt context.Context, request []byte) ([]byte, error) {
		if s.GetServerState() == ServerStateLocked {
			s.lgr.Warn("Server is locked, authentication required")
			return nil, ErrServerIsLocked
		}
		// if !s.IsPIDAuthenticated(s.PID) {
		// 	return nil, fmt.Errorf("pid %d is not authenticated", s.PID)
		// }
		return handler(ctxt, request)
	}
}

type AuthRequest struct {
	Method string          `json:"method"` // e.g., "password", "token"
	Data   json.RawMessage `json:"data"`   // The actual data for authentication, e.g., password or token
}

type AuthMethod func(ctx context.Context, request AuthRequest) (bool, error)

var authMap = map[string]AuthMethod{
	"touchid": func(ctx context.Context, request AuthRequest) (bool, error) {
		success, err := touchid.AuthenticateTouch("Unlock shimmer")
		if err != nil {
			return false, err
		}
		return success, nil
	},
}

func (s *MountServer) Authenticate(ctxt context.Context, request []byte) ([]byte, error) {
	// TODO(ttacon): call the authentication handler
	// eventually this will be a plugin
	s.lgr.Debug("Received authentication request")
	var authReq AuthRequest
	if err := json.Unmarshal(request, &authReq); err != nil {
		return nil, fmt.Errorf("failed to unmarshal authentication request: %w", err)
	}

	s.lgr.Debug("Authentication request method", slog.String("method", authReq.Method))
	authMethod, ok := authMap[authReq.Method]
	if !ok {
		return nil, fmt.Errorf("unknown authentication method: %s", authReq.Method)
	}

	s.lgr.Debug("Calling authentication method", slog.String("method", authReq.Method))
	success, err := authMethod(ctxt, authReq)
	if err != nil {
		s.lgr.Error("Authentication failed", slog.String("method", authReq.Method), slog.Any("error", err))
		return nil, fmt.Errorf("authentication failed: %w", err)
	} else if !success {
		s.lgr.Warn("Authentication failed", slog.String("method", authReq.Method))
		return nil, fmt.Errorf("authentication failed")
	}

	s.lgr.Info("Authentication successful", slog.String("method", authReq.Method))

	// Now initialize the internal data storage.
	if err := s.Initialize(ctxt); err != nil {
		if errors.Is(err, serrors.ErrIsNotBootstrapped) {
			s.lgr.Warn("Server is not bootstrapped, cannot initialize internal data", slog.Any("error", err))
			return json.Marshal(map[string]any{
				"status":      "not_bootstrapped",
				"initialized": false,
			})
		}
		s.lgr.Error("Failed to initialize internal data after authentication", slog.Any("error", err))
		return nil, fmt.Errorf("failed to initialize internal data after authentication: %w", err)
	}
	s.lgr.Info("Internal data initialized successfully after authentication")

	return json.Marshal(map[string]any{
		"status":      "authenticated",
		"initialized": true,
	})
}

// Init is the handler that initializes the server on before we ever first use shimmer.
// The server should be running, but in a locked state. We need to initialize the keychain
// manager, the initial encryption key, and the internal data storage.
func (s *MountServer) Init(ctxt context.Context, request []byte) ([]byte, error) {
	s.lgr.Debug("Received initialization request")
	if s.GetServerState() != ServerStateStopped {
		return nil, fmt.Errorf("server is not in stopped state, cannot initialize, current state: %s", s.GetServerState().String())
	}

	var err error
	if s.skm, err = keymanagement.InitializeSecureKeychain(s.lgr); err != nil {
		return nil, fmt.Errorf("failed to initialize secure keychain manager: %w", err)
	}

	s.lgr.Info("Secure keychain manager initialized successfully")

	// Create the root encryption key for the internal data storage.
	rootKey, err := s.skm.GenerateEncryptionKey(EncKeyInternalDataName, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to create root encryption key: %w", err)
	}
	s.lgr.Info("Root encryption key created successfully", slog.String("keyID", EncKeyInternalDataName))

	// Initialize the internal data storage
	dataPath, err := s.dataDirPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get shimmer data directory: %w", err)
	}
	s.internalData = internaldata.NewInternalData(dataPath, []byte(rootKey), s.lgr, s.skm)
	if err := s.internalData.Bootstrap(); err != nil {
		return nil, fmt.Errorf("failed to bootstrap internal data storage: %w", err)
	}
	s.lgr.Info("Internal data storage bootstrapped successfully")
	s.SetServerState(ServerStateLocked)
	s.lgr.Info("Mount server initialized and locked successfully")
	return json.Marshal(map[string]any{
		"status":      "initialized",
		"initialized": true,
		"booted_at":   s.bootedAt.Format(time.RFC3339),
	})
}

// Doctor is a diagnostic endpoint that can be used to check the health of the server.
// If the server is locked, it will only return unauthenticated information.
// If the server is running, it will return detailed information about the server state.
// This can be used for debugging purposes, and for generating debug reports for issue reporting.
func (s *MountServer) Doctor(ctxt context.Context, request []byte) ([]byte, error) {
	s.lgr.Debug("Received doctor request")

	defaultResponse := map[string]any{
		"state":     s.GetServerState().String(),
		"booted_at": s.bootedAt.Format(time.RFC3339),
	}

	if s.GetServerState() == ServerStateLocked {
		s.lgr.Warn("Doctor request received while server is locked")
		return json.Marshal(defaultResponse)
	}

	if !s.unlockedAt.IsZero() {
		defaultResponse["unlocked_at"] = s.unlockedAt.Format(time.RFC3339)
	}
	if !s.lockedAt.IsZero() {
		defaultResponse["locked_at"] = s.lockedAt.Format(time.RFC3339)
	}

	if s.internalData != nil {
		defaultResponse["internal_data"] = map[string]any{
			"num_mounts": s.internalData.NumMounts(),
		}
		defaultResponse["diagnostic"] = s.diagnostic
	}

	return json.Marshal(defaultResponse)
}

type ListKnownMountsResponse struct {
	Mounts []config.MountConfig `json:"mounts"`
}

func (s *MountServer) ListKnownMounts(ctxt context.Context, request []byte) ([]byte, error) {
	s.lgr.Debug("Listing known mounts")
	if s.internalData == nil {
		return nil, fmt.Errorf("internal data is not initialized")
	}

	s.lgr.Debug("Loading mounts from internal data")
	mounts, err := s.internalData.LoadMounts()
	if err != nil {
		s.lgr.Error("Failed to load mounts from internal data", slog.Any("error", err))
		return nil, fmt.Errorf("failed to load mounts: %w", err)
	}

	s.lgr.Debug("Loaded mounts from internal data", slog.Int("numMounts", len(mounts.Mounts)))
	response := ListKnownMountsResponse{
		Mounts: mounts.Mounts,
	}
	if response.Mounts == nil {
		response.Mounts = []config.MountConfig{}
	}
	data, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}
	return data, nil
}

type FSRegisterRequest struct {
	Name           string `json:"name"`             // Name of the filesystem to be registered
	SourcePath     string `json:"source_path"`      // Path to the filesystem to be registered
	RemoveOnImport bool   `json:"remove_on_import"` // Whether to remove the filesystem on import
}

type FSRegisterResponse struct {
	Success bool `json:"success"`
}

var ShimmerDataDir = "fs-data"

func (s *MountServer) FSRegisterNewFS(ctxt context.Context, request []byte) ([]byte, error) {
	s.lgr.Debug("Received FS register request")
	var req FSRegisterRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	} else if req.SourcePath == "" {
		return nil, fmt.Errorf("path must be provided")
	}

	shimmerInteralDestPath, err := shimmerInternalPath(ShimmerDataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get shimmer data directory: %w", err)
	}

	destPath := filepath.Join(shimmerInteralDestPath, req.Name)
	s.lgr.Debug("Registering new filesystem", slog.String("path", req.SourcePath), slog.String("destPath", destPath))
	ingstr := transform.NewIngestor(
		req.Name,
		req.SourcePath,
		destPath,
		s.internalData,
		s.skm,
		s.lgr,
	)

	s.lgr.Debug("Initializing ingestor for new filesystem")
	if err := ingstr.Init(); err != nil {
		s.lgr.Error("Failed to initialize ingestor for new filesystem", slog.String("path", req.SourcePath), slog.Any("error", err))
		return nil, err
	}

	s.lgr.Debug(
		"Ingesting new filesystem",
		slog.String("name", req.Name),
		slog.String("sourcePath", req.SourcePath),
		slog.String("destPath", destPath),
	)
	if err := ingstr.Ingest(); err != nil {
		s.lgr.Error("Failed to register new filesystem", slog.String("path", req.SourcePath), slog.Any("error", err))
		return nil, fmt.Errorf("failed to register new filesystem: %w", err)
	}

	if req.RemoveOnImport {
		s.lgr.Debug("Removing source path after import", slog.String("sourcePath", req.SourcePath))
		if err := os.RemoveAll(req.SourcePath); err != nil {
			s.lgr.Error("Failed to remove source path after import", slog.String("sourcePath", req.SourcePath), slog.Any("error", err))
			return nil, err
		}
		s.lgr.Info("Removed source path after import", slog.String("sourcePath", req.SourcePath))
	} else {
		s.lgr.Debug("Not removing source path after import, flag not specified", slog.String("sourcePath", req.SourcePath))
	}

	s.lgr.Info("Registered new filesystem successfully", slog.String("path", destPath))
	return json.Marshal(FSRegisterResponse{Success: true})
}

type FSMountKnownFSRequest struct {
	Name       string `json:"name"`        // Name of the filesystem to be mounted
	MountPoint string `json:"mount_point"` // Path where the filesystem should be mounted
}

func (s *MountServer) MountKnownFS(ctxt context.Context, request []byte) ([]byte, error) {
	s.lgr.Debug("Received mount known FS request")
	var req FSMountKnownFSRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	} else if req.Name == "" || req.MountPoint == "" {
		return nil, fmt.Errorf("name and mount_point must be provided")
	}

	shimmerInteralDestPath, err := shimmerInternalPath(ShimmerDataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get shimmer data directory: %w", err)
	}
	sourcePath := filepath.Join(shimmerInteralDestPath, req.Name)
	s.lgr.Debug("Mounting known filesystem", slog.String("name", req.Name), slog.String("sourcePath", sourcePath), slog.String("mountPoint", req.MountPoint))
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("filesystem %s does not exist at %s", req.Name, sourcePath)
	}

	efs, err := s.internalData.RetrieveMountByName(req.Name)
	if err != nil {
		s.lgr.Error("Failed to retrieve mount by name", slog.String("name", req.Name), slog.Any("error", err))
		return nil, err
	} else if efs == nil {
		return nil, fmt.Errorf("filesystem %s not found in internal data", req.Name)
	}

	if err := s.mountListenerFromBillyFS(sourcePath, efs, req.MountPoint, randomPort(), true, ""); err != nil {
		s.lgr.Error("Failed to mount known filesystem", slog.String("name", req.Name), slog.String("mountPoint", req.MountPoint), slog.Any("error", err))
		return nil, fmt.Errorf("failed to mount known filesystem %s: %w", req.Name, err)
	}
	s.lgr.Info("Mounted known filesystem successfully", slog.String("name", req.Name), slog.String("mountPoint", req.MountPoint))
	return json.Marshal(FSMountKnownFSResponse{
		MountPoint: req.MountPoint,
		SourcePath: sourcePath,
		Success:    true,
	})
}

type FSMountKnownFSResponse struct {
	MountPoint string `json:"mount_point"` // Path where the filesystem is mounted
	SourcePath string `json:"source_path"` // Path to the source filesystem
	Success    bool   `json:"status"`      // Status of the mount operation
}

func (s *MountServer) Start() error {
	s.Server.RegisterHandler("/auth/check", s.handlerAuthWrapper(s.IsPIDAuthenticatedHandler))
	s.Server.RegisterHandler("/mount/start", s.handlerAuthWrapper(s.StartMountHandler))
	s.Server.RegisterHandler("/mount/single", s.handlerAuthWrapper(s.StartSingleMountFileHandler))
	s.Server.RegisterHandler("/mount/list", s.handlerAuthWrapper(s.ListKnownMounts))
	s.Server.RegisterHandler("/fs/register", s.handlerAuthWrapper(s.FSRegisterNewFS))
	s.Server.RegisterHandler("/fs/mount", s.handlerAuthWrapper(s.MountKnownFS))
	s.Server.RegisterHandler("/fs/delete", s.handlerAuthWrapper(s.FSDeleteKnownMount))
	s.Server.RegisterHandler("/fs/invalidate", s.handlerAuthWrapper(s.FSInvalidateMount))
	s.Server.RegisterHandler("/fs/eject", s.handlerAuthWrapper(s.FSEjectKnownMount))
	s.Server.RegisterHandler("/fs/unmount", s.handlerAuthWrapper(s.FSUnmountKnownMount))
	s.Server.RegisterHandler("/unlock", s.Authenticate)
	s.Server.RegisterHandler("/doctor", s.Doctor)
	s.Server.RegisterHandler("/init", s.Init)

	if err := s.Server.Start(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	s.lgr.Info("Mount server running at %s\n", slog.String("unixSocketPath", s.Server.UnixSocket))
	return nil
}

type FSDeleteKnownMountRequest struct {
	Name string `json:"name"` // Name of the filesystem to be deleted
}

type FSDeleteKnownMountResponse struct {
	Success bool `json:"success"` // Status of the delete operation
}

func (s *MountServer) FSDeleteKnownMount(ctxt context.Context, request []byte) ([]byte, error) {
	s.lgr.Debug("Received FS delete known mount request")
	var req FSDeleteKnownMountRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	} else if req.Name == "" {
		return nil, fmt.Errorf("name must be provided")
	}

	s.lgr.Debug("Deleting known filesystem", slog.String("name", req.Name))
	if err := s.internalData.DeleteMountByName(req.Name); err != nil {
		s.lgr.Error("Failed to delete known filesystem", slog.String("name", req.Name), slog.Any("error", err))
		return nil, fmt.Errorf("failed to delete known filesystem %s: %w", req.Name, err)
	}

	s.lgr.Info("Deleted known filesystem successfully", slog.String("name", req.Name))
	return json.Marshal(FSDeleteKnownMountResponse{
		Success: true,
	})
}

func (s *MountServer) FSInvalidateMount(ctxt context.Context, request []byte) ([]byte, error) {
	s.lgr.Debug("Received FS invalidate mount request")
	var req FSDeleteKnownMountRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	} else if req.Name == "" {
		return nil, fmt.Errorf("name must be provided")
	}

	s.lgr.Debug("Invalidating known filesystem", slog.String("name", req.Name))
	if err := s.internalData.InvalidateMount(req.Name); err != nil {
		s.lgr.Error("Failed to invalidate known filesystem", slog.String("name", req.Name), slog.Any("error", err))
		return nil, fmt.Errorf("failed to invalidate known filesystem %s: %w", req.Name, err)
	}

	s.lgr.Info("Invalidated known filesystem successfully", slog.String("name", req.Name))
	return json.Marshal(FSDeleteKnownMountResponse{
		Success: true,
	})
}

type FSKnownMountNameRequest struct {
	Name string `json:"name"` // Name of the filesystem to be ejected
}

type FSSuccessResponse struct {
	Success bool `json:"success"` // Status of the eject operation
}

func (s *MountServer) FSEjectKnownMount(ctxt context.Context, request []byte) ([]byte, error) {
	s.lgr.Debug("Received FS eject known mount request")
	var req FSKnownMountNameRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	} else if req.Name == "" {
		return nil, fmt.Errorf("name must be provided")
	}

	s.lgr.Debug("Ejecting known filesystem", slog.String("name", req.Name))
	if err := s.internalData.EjectKnownMount(req.Name); err != nil {
		s.lgr.Error("Failed to eject known filesystem", slog.String("name", req.Name), slog.Any("error", err))
		return nil, fmt.Errorf("failed to eject known filesystem %s: %w", req.Name, err)
	}

	s.lgr.Info("Ejected known filesystem successfully", slog.String("name", req.Name))
	return json.Marshal(FSSuccessResponse{
		Success: true,
	})
}

type FSUnmountKnownMountRequest struct {
	Name       string `json:"name"`        // Name of the filesystem to be unmounted
	MountPoint string `json:"mount_point"` // Path where the filesystem is mounted
}

func (s *MountServer) FSUnmountKnownMount(ctxt context.Context, request []byte) ([]byte, error) {
	s.lgr.Debug("Received FS unmount known mount request")
	var req FSUnmountKnownMountRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	} else if req.Name == "" {
		return nil, fmt.Errorf("name must be provided")
	}

	s.lgr.Debug("Identifying known filesystem to unmount", slog.String("name", req.Name))
	var mountListener *MountedListener
	for _, listener := range s.listeners {
		if listener.mountPoint == req.MountPoint {
			mountListener = &listener
			break
		}
	}
	if mountListener == nil {
		s.lgr.Error("Failed to find mount listener for known filesystem", slog.String("name", req.Name), slog.String("mountPoint", req.MountPoint))
		return nil, internaldata.ErrMountNotFound
	}

	s.lgr.Debug("Unmounting known filesystem", slog.String("name", req.Name), slog.String("mountPoint", req.MountPoint))
	if err := s.unmountListener(mountListener.listener, mountListener.mountPoint); err != nil {
		s.lgr.Error("Failed to unmount known filesystem", slog.String("name", req.Name), slog.String("mountPoint", req.MountPoint), slog.Any("error", err))
		return nil, err
	}

	s.lgr.Info("Unmounted known filesystem successfully", slog.String("name", req.Name))
	return json.Marshal(FSSuccessResponse{
		Success: true,
	})
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
