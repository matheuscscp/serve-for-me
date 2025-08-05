package serveforme

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// ClientOption defines a function that can modify the client options.
type ClientOption func(*clientOptions)

// WithIDToken sets the ID token for the client.
func WithIDToken(idToken string) ClientOption {
	return func(o *clientOptions) {
		o.idToken = idToken
	}
}

// WithHTTPClient sets the HTTP client for the client.
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(o *clientOptions) {
		o.httpClient = httpClient
	}
}

type clientOptions struct {
	idToken    string
	httpClient *http.Client
}

// ServeForMe starts a websocket with the server and handles requests
// until the context is done.
func ServeForMe(ctx context.Context, serverURL string,
	started chan<- struct{}, handlers map[string]http.Handler,
	opts ...ClientOption) error {

	var o clientOptions
	for _, opt := range opts {
		opt(&o)
	}

	if err := o.ensureIDToken(ctx); err != nil {
		return fmt.Errorf("failed to retrieve ID token: %w", err)
	}

	// Build handler patterns and ServeMux.
	var patterns []string
	mux := http.NewServeMux()
	for pattern, handler := range handlers {
		patterns = append(patterns, pattern)
		mux.Handle(pattern, handler)
	}

	// Dial.
	conn, _, err := websocket.Dial(ctx, serverURL, &websocket.DialOptions{
		HTTPClient: o.httpClient,
		HTTPHeader: http.Header{HeaderServe: []string{o.idToken}},
	})
	if err != nil {
		return err
	}
	defer conn.CloseNow()

	// Send handler patterns.
	if err := wsjson.Write(ctx, conn, patterns); err != nil {
		return fmt.Errorf("failed to send handler patterns: %w", err)
	}

	// Read started message.
	var startedMsg map[string]bool
	if err := wsjson.Read(ctx, conn, &startedMsg); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("failed to read started message: %w", err)
	}
	if !startedMsg["started"] {
		return fmt.Errorf("server did not start successfully")
	}
	close(started)

	for {
		var jsonReq Request
		if err := wsjson.Read(ctx, conn, &jsonReq); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("failed to read request from websocket: %w", err)
		}

		// Ping?
		if jsonReq.Proto == "" {
			if err := wsjson.Write(ctx, conn, struct{}{}); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("failed to send pong: %w", err)
			}
			continue
		}

		// Parse request.
		u, err := url.Parse(jsonReq.URL)
		if err != nil {
			return fmt.Errorf("failed to parse request URL: %w", err)
		}
		if len(jsonReq.Header) == 0 {
			jsonReq.Header = make(http.Header)
		}
		r := &http.Request{
			Proto:         jsonReq.Proto,
			ProtoMajor:    jsonReq.ProtoMajor,
			ProtoMinor:    jsonReq.ProtoMinor,
			Method:        jsonReq.Method,
			Host:          jsonReq.Host,
			URL:           u,
			RequestURI:    jsonReq.RequestURI,
			RemoteAddr:    jsonReq.RemoteAddr,
			ContentLength: jsonReq.ContentLength,
			Header:        jsonReq.Header,
			Body:          io.NopCloser(bytes.NewReader(jsonReq.Body)),
		}

		// Serve.
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r.WithContext(ctx))
		res := w.Result()

		// Assemble response.
		header := res.Header
		if len(header) == 0 {
			header = nil
		}
		body, err := io.ReadAll(res.Body)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("failed to read response body from memory: %w", err)
		}
		if len(body) == 0 {
			body = nil
		}
		resp := &Response{
			StatusCode: res.StatusCode,
			Header:     header,
			Body:       body,
		}

		if err := wsjson.Write(ctx, conn, resp); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("failed to write response to websocket: %w", err)
		}
	}
}

func (o *clientOptions) ensureIDToken(ctx context.Context) error {
	switch {
	case o.idToken != "":
		return nil
	case os.Getenv("GITHUB_ACTIONS") == "true":
		return o.fetchGitHubActionOIDCToken(ctx)
	default:
		return errors.New("no ID token source is present in environment")
	}
}

func (o *clientOptions) fetchGitHubActionOIDCToken(ctx context.Context) error {
	endpoint := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	if endpoint == "" {
		return errors.New("ACTIONS_ID_TOKEN_REQUEST_URL is not set (did you enable id-token: write?)")
	}
	endpoint = fmt.Sprintf("%s&audience=%s", endpoint, url.QueryEscape(ClientID))

	bearer := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if bearer == "" {
		return errors.New("ACTIONS_ID_TOKEN_REQUEST_TOKEN is not set")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("requesting OIDC token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OIDC endpoint returned %s", resp.Status)
	}

	var payload struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return fmt.Errorf("decoding JSON: %w", err)
	}

	o.idToken = payload.Value

	return nil
}
