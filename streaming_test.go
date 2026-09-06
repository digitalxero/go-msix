package msix

import (
	"bytes"
	"context"
	"crypto/sha256"
	"hash/crc32"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompressSourceToSpill_OracleParity verifies the streaming compressor produces
// byte-identical compressed output, block hashes, sizes and CRC to the original
// in-memory compressBlocks across a range of block boundaries.
func TestCompressSourceToSpill_OracleParity(t *testing.T) {
	sizes := []int{1, 100, blockSize - 1, blockSize, blockSize + 1, 200 * 1024, 5 * 1024 * 1024}
	for _, n := range sizes {
		data := goldenPattern(n)

		wantBlocks, wantCompressed, err := compressBlocks(data)
		require.NoError(t, err)

		e, err := compressSourceToSpill("f.dat", bytesFileSource{data: data}, false, t.TempDir())
		require.NoError(t, err)
		require.NotEmpty(t, e.spillPath)
		defer os.Remove(e.spillPath)

		require.Len(t, e.blocks, len(wantBlocks), "block count (size=%d)", n)
		for i := range wantBlocks {
			assert.Equal(t, wantBlocks[i].Hash, e.blocks[i].Hash, "block %d hash (size=%d)", i, n)
			assert.Equal(t, wantBlocks[i].CompressedSize, e.blocks[i].CompressedSize, "block %d compressed size (size=%d)", i, n)
		}

		got, err := os.ReadFile(e.spillPath)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(wantCompressed, got), "compressed bytes (size=%d)", n)

		assert.Equal(t, crc32.ChecksumIEEE(data), e.crc32, "crc32 (size=%d)", n)
		assert.Equal(t, uint64(len(data)), e.uncompressedSize, "uncompressed size (size=%d)", n)
		assert.Equal(t, uint64(len(wantCompressed)), e.compressedSize, "compressed size (size=%d)", n)
	}
}

// TestSignedDigests_MatchBufferedReference verifies the streaming digest replay
// computes AXPC over file records and AXCD over the central directory including EOCD.
func TestSignedDigests_MatchBufferedReference(t *testing.T) {
	withFiles := func(b Builder) Builder {
		return b.AddFileFromBytes("App.exe", []byte("MZ")).
			AddFileFromBytes("large.dat", goldenPattern(200*1024)).
			AddFileFromBytes("empty.txt", nil)
	}

	// Reference: build the unsigned package into a buffer and hash both regions.
	var buf bytes.Buffer
	require.NoError(t, withFiles(goldenBaseBuilder()).Build(context.Background(), &buf))
	unsigned := buf.Bytes()
	cdOff, _, err := findCentralDirectoryOffset(unsigned)
	require.NoError(t, err)
	wantAXPC := sha256.Sum256(unsigned[:cdOff])
	wantAXCD := sha256.Sum256(unsigned[cdOff:])

	// New: reconstruct the unsigned layout and run the streaming digest replay.
	b := withFiles(goldenBaseBuilder()).(*builder)
	m := b.assembleManifest()
	manifestData, err := renderManifest(m)
	require.NoError(t, err)
	c := &buildCtx{b: b}
	defer c.cleanup()
	core, blockMapBytes, names, err := c.prepareCore(manifestData)
	require.NoError(t, err)
	blockMapEntry, err := c.compress("AppxBlockMap.xml", bytesFileSource{data: blockMapBytes}, false)
	require.NoError(t, err)
	unsignedNames := append(append([]string{}, names...), "AppxBlockMap.xml")
	ct, err := marshalContentTypes(unsignedNames)
	require.NoError(t, err)
	ctEntry, err := c.compress("[Content_Types].xml", bytesFileSource{data: ct}, true)
	require.NoError(t, err)

	layout := append(append([]*compressedEntry{}, core...), blockMapEntry, ctEntry)
	gotAXPC, gotAXCD, err := computeDigests(layout)
	require.NoError(t, err)

	assert.Equal(t, wantAXPC, gotAXPC, "AXPC mismatch between streaming replay and buffered reference")
	assert.Equal(t, wantAXCD, gotAXCD, "AXCD mismatch between streaming replay and buffered reference")
}

func TestSignedDigestsZIP64(t *testing.T) {
	entry, err := compressSourceToSpill("empty", bytesFileSource{}, true, t.TempDir())
	require.NoError(t, err)
	entries := make([]*compressedEntry, 1<<16)
	for i := range entries {
		entries[i] = entry
	}

	var buf bytes.Buffer
	require.NoError(t, writeZip(&buf, entries))
	data := buf.Bytes()
	require.Equal(t, []byte("PK\x06\x07"), data[len(data)-42:len(data)-38], "ZIP64 locator")
	cdOffset, _, err := findCentralDirectoryOffset(data)
	require.NoError(t, err)

	axpc, axcd, err := computeDigests(entries)
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256(data[:cdOffset]), axpc)
	require.Equal(t, sha256.Sum256(data[cdOffset:]), axcd, "AXCD includes ZIP64 end records")
}

// TestSignedPackage_DeterministicExceptSignature verifies that two signed builds
// produce identical bytes for every part except the (non-deterministic) signature,
// and that the signature is present with the PKCX magic.
func TestSignedPackage_DeterministicExceptSignature(t *testing.T) {
	cert, key := testSelfSignedCert(t)

	build := func() map[string][]byte {
		b := goldenBaseBuilder().
			AddFileFromBytes("App.exe", []byte("MZ")).
			AddFileFromBytes("large.dat", goldenPattern(200*1024)).
			WithSigning(NewSigning().WithCertificate(cert).WithPrivateKey(key).Build())
		var buf bytes.Buffer
		require.NoError(t, b.Build(context.Background(), &buf))
		return unzipAll(t, buf.Bytes())
	}

	a := build()
	bb := build()

	require.Contains(t, a, "AppxSignature.p7x")
	assert.True(t, bytes.HasPrefix(a["AppxSignature.p7x"], p7xMagic), "missing PKCX magic")
	require.Contains(t, a, "[Content_Types].xml")
	assert.Contains(t, string(a["[Content_Types].xml"]), "/AppxSignature.p7x", "signed content types must include signature override")

	for name, data := range a {
		if name == "AppxSignature.p7x" {
			continue // PKCS7 includes nondeterministic material
		}
		assert.True(t, bytes.Equal(data, bb[name]), "part %q not deterministic across signed builds", name)
	}
}
