package reader

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/coder/websocket"

	"github.com/matheuscscp/serve-for-me/serveforme/internal/logging"
)

const (
	errFailedToUnmarshalJSON = "failed to unmarshal JSON"
)

// ReadJSON starts a goroutine to read messages from the connection
// and unmarshal them from JSON into the specified type T.
// The first channel returns the unmarshaled objects, and is closed
// when the connection is closed or an error occurs.
// The second channel is closed at the same time as the first one,
// and can be used to detect when the goroutine has finished.
func ReadJSON[T any](ctx context.Context, c *websocket.Conn) (<-chan *T, <-chan struct{}) {
	ch := make(chan *T)
	done := make(chan struct{})

	go func() {
		defer close(ch)
		defer close(done)

		for {
			_, r, err := c.Reader(ctx)
			if err != nil {
				logging.FromContext(ctx).WithError(err).Error("error reading from websocket")
				return
			}

			obj, err := read[T](r)
			if err != nil {
				if strings.Contains(err.Error(), errFailedToUnmarshalJSON) {
					c.Close(websocket.StatusInvalidFramePayloadData, "failed to unmarshal JSON")
				}
				logging.FromContext(ctx).WithError(err).Error("error reading from websocket buffer")
				return
			}

			select {
			case <-ctx.Done():
				return
			case ch <- obj:
			}
		}
	}()

	return ch, done
}

func read[T any](r io.Reader) (*T, error) {
	b := bpool.Get().(*bytes.Buffer)
	defer func() {
		b.Reset()
		bpool.Put(b)
	}()

	_, err := b.ReadFrom(r)
	if err != nil {
		return nil, err
	}

	var v T
	if err := json.Unmarshal(b.Bytes(), &v); err != nil {
		return nil, fmt.Errorf("%s: %w", errFailedToUnmarshalJSON, err)
	}

	return &v, nil
}

var bpool = sync.Pool{
	New: func() any {
		return &bytes.Buffer{}
	},
}
