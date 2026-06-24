package msix

import (
	"bytes"
	"io"
	"os"
)

// fileSource is a re-openable byte source. open may be called more than once and
// each call returns a fresh reader positioned at the start. This is what lets the
// build engine read payloads without ever holding a whole file in memory, and read
// the same source again for the signed path's digest + output replays.
type fileSource interface {
	open() (io.ReadCloser, error)
}

// diskFileSource opens a file from disk lazily on each call.
type diskFileSource struct {
	path string
}

func (s diskFileSource) open() (io.ReadCloser, error) { return os.Open(s.path) }

// bytesFileSource wraps an in-memory byte slice. Used for small generated XML
// (manifest, block map, content types) and AddFileFromBytes payloads.
type bytesFileSource struct {
	data []byte
}

func (s bytesFileSource) open() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.data)), nil
}

// funcFileSource adapts a user-supplied re-openable opener.
type funcFileSource struct {
	opener func() (io.ReadCloser, error)
}

func (s funcFileSource) open() (io.ReadCloser, error) { return s.opener() }
