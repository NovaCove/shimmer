package rpc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"

	touchid "github.com/NovaCove/shimmer/lib/auth/touchid"
)

type Handler func(context context.Context, request []byte) ([]byte, error)

// Server represents a local command and control server that listens for commands
// over a Unix socket. It can be used to handle various commands by registering
// handlers for specific command types. The server can be started and stopped,
// and it provides a way to handle incoming requests asynchronously.
type Server struct {
	UnixSocket string
	Handlers   map[string]Handler
	Lgr        *slog.Logger

	listener          net.Listener
	authenticatedPIDs map[int]bool // Track authenticated PIDs
}

// NewServer creates a new Server instance with the specified Unix socket path.
func NewServer(unixSocket string, lgr *slog.Logger) *Server {
	return &Server{
		UnixSocket: unixSocket,
		Handlers:   make(map[string]Handler),
		Lgr:        lgr,
	}
}

// RegisterHandler registers a handler for a specific command type.
func (s *Server) RegisterHandler(command string, handler Handler) {
	s.Handlers[command] = handler
}

func (s *Server) UnregisterHandler(command string) {
	// Unregister a handler for a specific command type.
	delete(s.Handlers, command)
}

func (s *Server) IsPIDAuthenticated(pid int) bool {
	// Check if the PID is authenticated.
	if s.authenticatedPIDs == nil {
		return false
	}
	return s.authenticatedPIDs[pid]
}

type Request struct {
	Command string          `json:"command"`
	PID     int             `json:"pid"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

func (s *Server) handleConnection(conn net.Conn) {
	// defer conn.Close()

	defer func() {
		if r := recover(); r != nil {
			s.Lgr.Info("Handler panicked", "error", r)
			conn.Close()
		}
	}()

	reqRaw, err := readMessage(conn)
	if err != nil {
		s.Lgr.Error("failed to read message from connection:", err)
		return
	}

	var request Request
	if err := json.Unmarshal(reqRaw, &request); err != nil {
		// If we can't decode the request, we can just close the connection.
		return
	}
	// Look up the handler for the command.
	handler, ok := s.Handlers[request.Command]
	if !ok {
		// If we don't have a handler for the command, we can just close the connection.
		return
	}

	// Call the handler with the request payload.
	s.Lgr.Debug("Handling request", "command", request.Command, "pid", request.PID)
	response, err := handler(context.Background(), request.Payload)
	if err != nil {
		s.Lgr.Error("Error handling request", "command", request.Command, "pid", request.PID, "error", err)
		if err := returnErrViaConn(conn, err); err != nil {
			s.Lgr.Error("Error sending error response", "command", request.Command, "pid", request.PID, "error", err)
		}
		return
	}

	s.Lgr.Debug("Response from handler", "command", request.Command, "pid", request.PID)

	respRaw, err := json.Marshal(DataResponse{
		Data:  response,
		Error: "",
	})
	if err != nil {
		// If we can't encode the response, we can just close the connection.
		s.Lgr.Error("Error encoding response", "command", request.Command, "pid", request.PID, "error", err)
		return
	} else if err := writeMessage(conn, respRaw); err != nil {
		s.Lgr.Error("failed to send response:", err)
		return
	}

	s.Lgr.Debug(string(response))

	s.Lgr.Debug("Response sent for command", "command", request.Command, "pid", request.PID)
}

type DataResponse struct {
	Data  json.RawMessage `json:"data"`
	Error string          `json:"error,omitempty"`
}

func returnErrViaConn(conn net.Conn, err error) error {
	return json.NewEncoder(conn).Encode(DataResponse{
		Data:  nil,
		Error: err.Error(),
	})
}

func (s *Server) Authenticate(pid int) (bool, error) {
	ok, err := touchid.AuthenticateTouch("access llamas")
	if err != nil {
		return false, err
	}

	if !ok {
		return false, nil
	}
	// If the PID is already authenticated, return true.
	if s.authenticatedPIDs == nil {
		s.authenticatedPIDs = make(map[int]bool)
	}
	s.authenticatedPIDs[pid] = true
	return true, nil
}

// Start starts the server and listens for incoming requests on the Unix socket.
func (s *Server) Start() error {
	s.Lgr.Info("Starting server", "socket", s.UnixSocket)
	// First, see if the Unix socket already exists and remove it if it does.
	if err := os.RemoveAll(s.UnixSocket); err != nil {
		return err
	}

	s.Lgr.Debug("Creating Unix socket listener", "socket", s.UnixSocket)
	listener, err := net.Listen("unix", s.UnixSocket)
	if err != nil {
		return err
	}

	defer func() {
		if r := recover(); r != nil {
			s.Lgr.Info("Server panicked", "error", r)
		}
	}()

	s.listener = listener
	defer listener.Close()
	s.Lgr.Info("Server is listening for connections")
	for {
		s.Lgr.Debug("Waiting for new connection...")
		conn, err := s.listener.Accept()
		if err != nil {
			// If the listener is closed, we can exit gracefully.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil
			} else if ne, ok := err.(*net.OpError); ok && ne.Err.Error() == "use of closed network connection" {
				s.Lgr.Info("Listener closed, exiting accept loop")
				return nil
			}
			s.Lgr.Info("Error accepting connection", "error", err)
			continue
		}

		s.Lgr.Debug("New connection accepted")
		go s.handleConnection(conn)
	}
}

type Client struct {
	UnixSocket string
	PID        int
	lgr        *slog.Logger
	// activeConn net.Conn // Keep track of the active connection for the client
}

// NewClient creates a new Client instance with the specified Unix socket path.
func NewClient(unixSocket string, pid int, logLevel slog.Level) *Client {
	return &Client{
		UnixSocket: unixSocket,
		PID:        pid,
		lgr:        slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: &logLevel})),
	}
}

// Send sends a command to the server and waits for a response.
func (c *Client) Send(command string, payload interface{}) ([]byte, error) {
	conn, err := net.Dial("unix", c.UnixSocket)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	request := Request{
		Command: command,
		PID:     c.PID,
	}

	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		request.Payload = data
	}

	c.lgr.Debug("Sending request", "command", command, "pid", c.PID)
	reqPayload, err := json.Marshal(request)
	if err != nil {
		c.lgr.Error("Error marshaling request", "command", command, "pid", c.PID, "error", err)
		return nil, err
	}

	if err := writeMessage(conn, reqPayload); err != nil {
		c.lgr.Error("Error writing request to connection", "command", command, "pid", c.PID, "error", err)
		return nil, err
	}

	c.lgr.Debug("Request sent", "command", command, "pid", c.PID)
	respRaw, err := readMessage(conn)
	if err != nil {
		c.lgr.Error("Error reading response from connection", "command", command, "pid", c.PID, "error", err)
		return nil, err
	}

	c.lgr.Debug("Response received", "command", command, "pid", c.PID)
	return respRaw, nil
}

func writeMessage(conn net.Conn, data []byte) error {
	length := uint32(len(data))
	if err := binary.Write(conn, binary.BigEndian, length); err != nil {
		return err
	}

	_, err := conn.Write(data)
	return err
}

// Reading a message
func readMessage(conn net.Conn) ([]byte, error) {
	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	data := make([]byte, length)
	_, err := io.ReadFull(conn, data)
	return data, err
}

// Stop stops the server by closing the listener.
func (s *Server) Stop() error {
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			return err
		}
		// FIXME: s.listener = nil
	}
	// Remove the Unix socket file if it exists.
	if err := os.RemoveAll(s.UnixSocket); err != nil {
		return err
	}
	return nil
}

// IsRunning checks if the server is currently running by attempting to connect to the Unix socket.
func (c *Client) IsRunning() bool {
	conn, err := net.Dial("unix", c.UnixSocket)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Stop stops the client by closing the connection to the server.
func (c *Client) Stop() error {
	conn, err := net.Dial("unix", c.UnixSocket)
	if err != nil {
		return err
	}
	defer conn.Close()
	// We can just close the connection to stop the client.
	return nil
}
