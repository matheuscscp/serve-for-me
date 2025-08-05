package serveforme

import "net/http"

const (
	// HeaderServe is the header used to indicate a request for serving on the client's behalf.
	// It should contain an OIDC ID token representing an identity that is authorized in the
	// configuration.
	HeaderServe = "X-Serve-For-Me"

	// ClientID is the client ID used for issuing tokens from environments that support it,
	// such as GitHub Actions.
	ClientID = "serve-for-me"
)

// Request is the JSON serialization of an HTTP request the server will send to the backend.
type Request struct {
	Proto         string      `json:"proto,omitempty"`
	ProtoMajor    int         `json:"protoMajor,omitempty"`
	ProtoMinor    int         `json:"protoMinor,omitempty"`
	Method        string      `json:"method,omitempty"`
	Host          string      `json:"host,omitempty"`
	URL           string      `json:"url,omitempty"`
	RequestURI    string      `json:"requestURI,omitempty"`
	RemoteAddr    string      `json:"remoteAddr,omitempty"`
	ContentLength int64       `json:"contentLength,omitempty"`
	Header        http.Header `json:"header,omitempty"`
	Body          []byte      `json:"body,omitempty"`
}

// Response is the JSON serialization of an HTTP response the backend must send back to the server.
type Response struct {
	StatusCode int         `json:"statusCode,omitempty"`
	Header     http.Header `json:"header,omitempty"`
	Body       []byte      `json:"body,omitempty"`
}
