package msix

import (
	"context"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// genReader yields n bytes of cheap deterministic data without allocating per call,
// so a multi-GB payload can be produced without ever materializing it in memory.
type genReader struct {
	remaining int64
	b         byte
}

func (g *genReader) Read(p []byte) (int, error) {
	if g.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > g.remaining {
		n = int(g.remaining)
	}
	for i := 0; i < n; i++ {
		p[i] = g.b
		g.b++
	}
	g.remaining -= int64(n)
	return n, nil
}

// measurePeakHeapGrowth runs fn while sampling HeapAlloc, returning the peak growth
// above the pre-run baseline.
func measurePeakHeapGrowth(fn func()) uint64 {
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	stop := make(chan struct{})
	result := make(chan uint64, 1)
	go func() {
		var peak uint64
		for {
			select {
			case <-stop:
				result <- peak
				return
			default:
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				if ms.HeapAlloc > peak {
					peak = ms.HeapAlloc
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
	}()

	fn()
	close(stop)
	peak := <-result
	if peak < base.HeapAlloc {
		return 0
	}
	return peak - base.HeapAlloc
}

// largePayloadSize is the synthetic payload size for the memory tests. Far larger
// than the bounded-memory threshold so buffering would be obvious.
const largePayloadSize = 1 << 30 // 1 GiB

// peakHeapThreshold is the maximum allowed heap growth while building the large
// package. Streaming bounds memory to ~a couple of 64KB blocks + small metadata, so
// 96 MiB leaves generous headroom while still being far below the 1 GiB payload.
const peakHeapThreshold = 96 << 20

func TestStreamingMemory_Unsigned(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large bounded-memory test in -short mode")
	}

	b := goldenBaseBuilder().AddFileSource("big.dat", func() (io.ReadCloser, error) {
		return io.NopCloser(&genReader{remaining: largePayloadSize}), nil
	})
	b.(*builder).tempDir = t.TempDir()

	growth := measurePeakHeapGrowth(func() {
		require.NoError(t, b.Build(context.Background(), io.Discard))
	})
	t.Logf("unsigned: peak heap growth %d MiB building a %d MiB payload", growth>>20, largePayloadSize>>20)
	require.Less(t, growth, uint64(peakHeapThreshold),
		"unsigned build heap grew %d bytes for a %d-byte payload; expected bounded streaming", growth, largePayloadSize)
}

func TestStreamingMemory_Signed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large bounded-memory test in -short mode")
	}

	cert, key := testSelfSignedCert(t)
	b := goldenBaseBuilder().
		AddFileSource("big.dat", func() (io.ReadCloser, error) {
			return io.NopCloser(&genReader{remaining: largePayloadSize}), nil
		}).
		WithSigning(NewSigning().WithCertificate(cert).WithPrivateKey(key).Build())
	b.(*builder).tempDir = t.TempDir()

	growth := measurePeakHeapGrowth(func() {
		require.NoError(t, b.Build(context.Background(), io.Discard))
	})
	t.Logf("signed: peak heap growth %d MiB building a %d MiB payload", growth>>20, largePayloadSize>>20)
	require.Less(t, growth, uint64(peakHeapThreshold),
		"signed build heap grew %d bytes for a %d-byte payload; expected bounded streaming", growth, largePayloadSize)
}
