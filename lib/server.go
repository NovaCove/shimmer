package lib

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"

	touchid "github.com/lox/go-touchid"
)

type Handler func(context context.Context, request []byte) ([]byte, error)

// Server represents a local command and control server that listens for commands
// over a Unix socket. It can be used to handle various commands by registering
// handlers for specific command types. The server can be started and stopped,
// and it provides a way to handle incoming requests asynchronously.
type Server struct {
	UnixSocket string
	Handlers   map[string]Handler

	listener          net.Listener
	authenticatedPIDs map[int]bool // Track authenticated PIDs
}

// NewServer creates a new Server instance with the specified Unix socket path.
func NewServer(unixSocket string) *Server {
	return &Server{
		UnixSocket: unixSocket,
		Handlers:   make(map[string]Handler),
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
	defer conn.Close()

	defer func() {
		if r := recover(); r != nil {
			// If the handler panics, we can just close the connection.
			fmt.Println("Handler panicked:", r)
			conn.Close()
		}
	}()

	// Read the full packet from the connection, and unmartial it into a request.
	decoder := json.NewDecoder(conn)

	var request Request
	if err := decoder.Decode(&request); err != nil {
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
	fmt.Println("Handling request:", request.Command, "from PID:", request.PID, "for handler:", request.Command)
	response, err := handler(context.Background(), request.Payload)
	if err != nil {
		// If the handler returns an error, we can just close the connection.
		return
	}

	fmt.Println("Response from handler:", request.Command, "for PID:", request.PID)
	// Marshal the response and write it back to the connection.
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(response); err != nil {
		// If we can't encode the response, we can just close the connection.
		return
	}

	fmt.Println("Response sent for command:", request.Command, "from PID:", request.PID)
}

func (s *Server) Authenticate(pid int) (bool, error) {
	ok, err := touchid.Authenticate("access llamas")
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
	fmt.Println("Starting server on", s.UnixSocket)
	// First, see if the Unix socket already exists and remove it if it does.
	if err := os.RemoveAll(s.UnixSocket); err != nil {
		return err
	}

	fmt.Println("Creating Unix socket listener at", s.UnixSocket)
	listener, err := net.Listen("unix", s.UnixSocket)
	if err != nil {
		return err
	}

	defer func() {
		if r := recover(); r != nil {
			// If the server panics, we can just close the listener.
			fmt.Println("Server panicked:", r)
		}
	}()

	s.listener = listener
	defer listener.Close()
	fmt.Println("Server is listening for connections...")
	for {
		// if s.listener == nil {
		// 	// If the listener is nil, we can exit the accept loop.
		// 	// This can happen if the server is stopped while waiting for a new connection.
		// 	fmt.Println("Server listener is nil, exiting accept loop")
		// 	return
		// }

		fmt.Println("Waiting for new connection...")
		conn, err := s.listener.Accept()
		if err != nil {
			// If the listener is closed, we can exit gracefully.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil
			} else if ne, ok := err.(*net.OpError); ok && ne.Err.Error() == "use of closed network connection" {
				fmt.Println("Listener closed, exiting accept loop")
				return nil
			}
			// Log the error and continue accepting new connections.
			// In a real application, you might want to log this error.
			fmt.Println("Error accepting connection:", err)
			continue
		}

		fmt.Println("New connection accepted")
		go s.handleConnection(conn)
	}
}

type Client struct {
	UnixSocket string
	PID        int
}

// NewClient creates a new Client instance with the specified Unix socket path.
func NewClient(unixSocket string, pid int) *Client {
	return &Client{
		UnixSocket: unixSocket,
		PID:        pid,
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

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(request); err != nil {
		return nil, err
	}

	var response []byte
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&response); err != nil {
		return nil, err
	}

	return response, nil
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
