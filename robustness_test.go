package msix

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuild_TempFilesCleanedUp verifies both the reader spill (from AddFileFromReader)
// and the compressed spills are removed from the temp dir once Build returns.
func TestBuild_TempFilesCleanedUp(t *testing.T) {
	dir := t.TempDir()
	b := goldenBaseBuilder()
	b.(*builder).tempDir = dir
	b.AddFileFromReader("data.bin", strings.NewReader("hello reader payload"))
	b.AddFileFromBytes("App.exe", []byte("MZ"))

	var buf bytes.Buffer
	require.NoError(t, b.Build(context.Background(), &buf))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "temp dir should be empty after Build (reader + compressed spills removed)")
}

// TestBuild_SourceOpenedOncePerBuild verifies a deflate payload source is read
// exactly once (compressed to a spill, which is then replayed for output/digests).
func TestBuild_SourceOpenedOncePerBuild(t *testing.T) {
	var opens int64
	b := goldenBaseBuilder().AddFileSource("big.dat", func() (io.ReadCloser, error) {
		atomic.AddInt64(&opens, 1)
		return io.NopCloser(strings.NewReader("payload data that will be deflated to a spill")), nil
	})

	var buf bytes.Buffer
	require.NoError(t, b.Build(context.Background(), &buf))
	assert.Equal(t, int64(1), atomic.LoadInt64(&opens),
		"deflate source must be read exactly once; the compressed spill is replayed thereafter")
}

// TestBuild_ValidationErrorsAggregated verifies required-field validation reports all
// problems at once via errors.Join.
func TestBuild_ValidationErrorsAggregated(t *testing.T) {
	err := NewBuilder().
		AddApplication(NewApplication().Build()).
		Build(context.Background(), io.Discard)
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "identity name is required")
	assert.Contains(t, msg, "identity version is required")
	assert.Contains(t, msg, "identity publisher is required")
	assert.Contains(t, msg, "application[0] id is required")
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

// TestBuild_ReaderErrorSurfacedAtBuild verifies a failing AddFileFromReader source is
// reported (deferred) from Build, naming the package path.
func TestBuild_ReaderErrorSurfacedAtBuild(t *testing.T) {
	err := goldenBaseBuilder().
		AddFileFromReader("bad.bin", errReader{}).
		Build(context.Background(), io.Discard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad.bin")
}
