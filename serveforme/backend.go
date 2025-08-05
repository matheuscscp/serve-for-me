package serveforme

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/matheuscscp/serve-for-me/api"
	"github.com/matheuscscp/serve-for-me/internal/logging"
)

const (
	// statusClientClosedRequest is a non-standard widely used status code
	// indicating that the client closed the request before the server could respond.
	// xref: https://http.cat/status/499
	statusClientClosedRequest = 499
)

type backend struct {
	id   *Identity
	mux  *http.ServeMux
	reqs chan<- *request
}

type request struct {
	req  *http.Request
	resp chan<- *http.Response
}

func newBackend(id *Identity, patterns []string, requests chan<- *request) *backend {
	mux := http.NewServeMux()
	for _, pattern := range patterns {
		mux.HandleFunc(pattern, func(http.ResponseWriter, *http.Request) {})
	}

	return &backend{
		id:   id,
		mux:  mux,
		reqs: requests,
	}
}

func (b *backend) matches(r *http.Request) bool {
	_, pattern := b.mux.Handler(r)
	return pattern != ""
}

func (b *backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	respChannel := make(chan *http.Response, 1)

	// Send request to the backend goroutine.
	job := &request{
		req:  r,
		resp: respChannel,
	}
	if !b.sendToGoroutine(w, r, job) {
		return
	}

	// Wait for the response.
	resp, ok := <-respChannel
	if !ok {
		http.Error(w, "Backend closed", http.StatusServiceUnavailable)
		return
	}

	// Write the response.
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		logging.
			FromContext(r.Context()).
			WithError(err).
			WithField("backend", b.id).
			Error("failed to write response body")
	}
}

func (b *backend) sendToGoroutine(w http.ResponseWriter, r *http.Request, job *request) (sent bool) {
	defer func() {
		// b.reqs <- job may panic if the backend has closed the connection
		if recover() != nil {
			close(job.resp)
			http.Error(w, "Backend closed before receiving request", http.StatusServiceUnavailable)
			sent = false
		}
	}()

	select {
	case <-r.Context().Done():
		close(job.resp)
		http.Error(w, "Request cancelled", statusClientClosedRequest)
		return false
	case b.reqs <- job:
		return true
	}
}

func callBackend(done <-chan struct{}, conn *websocket.Conn,
	connReader <-chan *api.Response, job *request) (resp *http.Response, err error) {

	defer func() {
		if err == nil {
			job.resp <- resp
		}
		close(job.resp)
	}()

	// Build request.
	body, err := io.ReadAll(job.req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	jsonReq := &api.Request{
		Proto:         job.req.Proto,
		ProtoMajor:    job.req.ProtoMajor,
		ProtoMinor:    job.req.ProtoMinor,
		Method:        job.req.Method,
		Host:          job.req.Host,
		URL:           job.req.URL.String(),
		RequestURI:    job.req.RequestURI,
		RemoteAddr:    job.req.RemoteAddr,
		ContentLength: job.req.ContentLength,
	}
	if len(job.req.Header) > 0 {
		jsonReq.Header = job.req.Header
	}
	if len(body) > 0 {
		jsonReq.Body = body
	}

	// Merge done channel into the request context.
	ctx, cancel := context.WithCancel(job.req.Context())
	defer cancel()
	go func() {
		select {
		case <-done:
			cancel()
		case <-ctx.Done():
		}
	}()

	// Send request to the backend.
	if err := wsjson.Write(ctx, conn, jsonReq); err != nil {
		return nil, fmt.Errorf("failed to write request to backend: %w", err)
	}

	// Wait for the response.
	var jsonResp *api.Response
	var ok bool
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("context done before receiving response: %w", ctx.Err())
	case jsonResp, ok = <-connReader:
		if !ok {
			return nil, fmt.Errorf("backend connection closed before response was received")
		}
	}

	// Send back to the client.
	resp = &http.Response{
		StatusCode: jsonResp.StatusCode,
		Header:     jsonResp.Header,
		Body:       io.NopCloser(bytes.NewReader(jsonResp.Body)),
	}

	return
}
