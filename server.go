package serveforme

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/matheuscscp/serve-for-me/internal/logging"
)

// ServerOption defines a function that can modify the server options.
type ServerOption func(*serverOptions)

// WithOIDCClient sets the OIDC HTTP client for the server.
func WithOIDCClient(oidcClient *http.Client) ServerOption {
	return func(o *serverOptions) {
		o.oidcClient = oidcClient
	}
}

type Server struct {
	allowedIdentities map[Identity]struct{}
	connectedBackends map[string]*backend
	oidcClient        *http.Client
	mu                sync.RWMutex
}

type serverOptions struct {
	oidcClient *http.Client
}

// NewServer creates a new Server instance with the provided options.
func NewServer(allowedIdentities []Identity, opts ...ServerOption) (*Server, error) {
	if len(allowedIdentities) == 0 {
		return nil, fmt.Errorf("at least one allowed identity must be provided")
	}

	var o serverOptions
	for _, opt := range opts {
		opt(&o)
	}

	allowed := make(map[Identity]struct{}, len(allowedIdentities))
	for _, id := range allowedIdentities {
		allowed[id] = struct{}{}
	}

	return &Server{
		allowedIdentities: allowed,
		connectedBackends: make(map[string]*backend),
		oidcClient:        o.oidcClient,
	}, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(HeaderServe) != "" {
		s.serveForMe(w, r)
		return
	}

	// Find a backend that can handle the request.
	s.mu.RLock()
	var b *backend
	for _, cb := range s.connectedBackends {
		if cb.matches(r) {
			b = cb
			break
		}
	}
	s.mu.RUnlock()

	if b == nil {
		http.Error(w, "Backend not found", http.StatusNotFound)
		return
	}

	b.ServeHTTP(w, r)
}

func (s *Server) serveForMe(w http.ResponseWriter, r *http.Request) {
	l := logging.FromContext(r.Context()).WithField("handler", HeaderServe)

	// Authenticate the request.
	id, err := s.authenticate(r)
	if err != nil {
		logging.FromContext(r.Context()).WithError(err).Error("failed to authenticate request")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	l = l.WithField("identity", id)

	// Upgrade the request to a WebSocket connection.
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		l.WithError(err).Error("failed to accept websocket connection")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer conn.CloseNow()

	// Read patterns.
	var patterns []string
	if err := wsjson.Read(r.Context(), conn, &patterns); err != nil {
		l.WithError(err).Error("failed to read handler patterns")
		return
	}
	l = l.WithField("patterns", patterns)

	// Build the backend.
	backendChannel := make(chan *request)
	defer func() {
		for {
			select {
			case job := <-backendChannel:
				close(job.resp)
			default:
				close(backendChannel)
				return
			}
		}
	}()
	backend := newBackend(id, patterns, backendChannel)

	// Register the backend.
	backendID := s.addBackend(backend)
	defer s.deleteBackend(backendID)

	// Send started message.
	startedMsg := map[string]bool{"started": true}
	if err := wsjson.Write(r.Context(), conn, startedMsg); err != nil {
		l.WithError(err).Error("failed to send started message")
		return
	}

	// Handle incoming requests.
	const pingInterval = 100 * time.Millisecond
	l.Info("handling requests")
	ctx := r.Context()
	done := ctx.Done()
	pingTimer := time.NewTimer(pingInterval)
	for {
		select {
		case <-done:
			conn.Close(websocket.StatusGoingAway, "backend context done")
			return
		case <-pingTimer.C:
			// Instead of a periodic ping, ideally we would have an event to select on
			// that would tell when the client closed the connection.
			// xref: https://github.com/coder/websocket/issues/533
			if err := wsjson.Write(ctx, conn, struct{}{}); err != nil {
				l.WithError(err).Error("failed to send ping")
				return
			}
			if err := wsjson.Read(ctx, conn, &struct{}{}); err != nil {
				l.WithError(err).Error("failed to read pong")
				return
			}
		case job := <-backendChannel:
			l := l.WithField("request", map[string]any{
				"method": job.req.Method,
				"host":   job.req.Host,
				"path":   job.req.URL.Path,
			})
			if _, err := callBackend(done, conn, job); err != nil {
				l.WithError(err).Error("failed to call backend")
				return
			}
		}
		pingTimer.Stop()
		pingTimer.Reset(pingInterval)
	}
}

func (s *Server) addBackend(b *backend) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	for {
		backendID := uuid.NewString()
		if _, ok := s.connectedBackends[backendID]; !ok {
			s.connectedBackends[backendID] = b
			return backendID
		}
	}
}

func (s *Server) deleteBackend(backendID string) {
	s.mu.Lock()
	delete(s.connectedBackends, backendID)
	s.mu.Unlock()
}

func (s *Server) authenticate(r *http.Request) (*Identity, error) {
	idToken := r.Header.Get(HeaderServe)
	id, err := parseIDToken(idToken)
	if err != nil {
		return nil, err
	}
	if _, ok := s.allowedIdentities[*id]; !ok {
		return nil, ErrInvalidIdentity
	}
	ctx := r.Context()
	if s.oidcClient != nil {
		ctx = oidc.ClientContext(ctx, s.oidcClient)
	}
	if err := id.Verify(ctx, idToken); err != nil {
		return nil, err
	}
	return id, nil
}

func parseIDToken(idToken string) (*Identity, error) {
	tok, _, err := jwt.NewParser().ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	issuer, err := tok.Claims.GetIssuer()
	if err != nil {
		return nil, err
	}
	audiences, err := tok.Claims.GetAudience()
	if err != nil {
		return nil, err
	}
	if len(audiences) != 1 {
		return nil, fmt.Errorf("exactly one audience is expected, got [%s]", strings.Join(audiences, ", "))
	}
	clientID := audiences[0]
	subject, err := tok.Claims.GetSubject()
	if err != nil {
		return nil, err
	}
	return &Identity{
		Issuer:   issuer,
		ClientID: clientID,
		Subject:  subject,
	}, nil
}
