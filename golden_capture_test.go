package msix

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// goldenBaseBuilder returns a fixed, deterministic builder (no payload files) for
// byte-equality capture. The configuration must match what the pre-rewrite struct
// literal produced so the golden hashes remain valid.
func goldenBaseBuilder() Builder {
	return NewBuilder().
		WithIdentity(NewIdentity().
			WithName("Golden.App").
			WithVersion("1.2.3.4").
			WithPublisher("CN=Golden").
			WithProcessorArchitecture("x64").
			Build()).
		WithProperties(NewProperties().
			WithDisplayName("Golden App").
			WithPublisherDisplayName("Golden Co").
			WithLogo("Assets/logo.png").
			Build()).
		WithDependencies(NewDependencies().
			AddTargetDeviceFamily("Windows.Desktop", "10.0.17763.0", "10.0.22621.0").
			Build()).
		AddResource(NewResource().WithLanguage("en-us").Build()).
		WithCapabilities(NewCapabilities().AddRestricted("runFullTrust").Build()).
		AddApplication(NewApplication().
			WithID("App").
			WithExecutable("App.exe").
			WithEntryPoint("Windows.FullTrustApplication").
			WithVisualElements(NewVisualElements().
				WithDisplayName("Golden App").
				WithDescription("Golden test application").
				WithBackgroundColor("#464646").
				WithSquare150x150Logo("Assets/150.png").
				WithSquare44x44Logo("Assets/44.png").
				Build()).
			Build())
}

// goldenPattern returns deterministic bytes of length n.
func goldenPattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*31 + 7) % 251)
	}
	return b
}

// goldenScenarios are reused by the byte-equality regression test.
func goldenScenarios() map[string]func(Builder) {
	return map[string]func(Builder){
		"single": func(b Builder) {
			b.AddFileFromBytes("App.exe", []byte("MZ deterministic exe"))
		},
		"multiblock": func(b Builder) {
			b.AddFileFromBytes("App.exe", []byte("MZ"))
			b.AddFileFromBytes("large.dat", goldenPattern(200*1024))
		},
		"subdirs_empty": func(b Builder) {
			b.AddFileFromBytes("App.exe", []byte("MZ"))
			b.AddFileFromBytes("Assets/logo.png", []byte("PNG logo bytes"))
			b.AddFileFromBytes("Data/config.json", []byte(`{"k":"v"}`))
			b.AddFileFromBytes("empty.txt", nil)
		},
	}
}

func goldenBuildUnsigned(t *testing.T, add func(Builder)) []byte {
	t.Helper()
	b := goldenBaseBuilder()
	add(b)
	var buf bytes.Buffer
	require.NoError(t, b.Build(context.Background(), &buf))
	return buf.Bytes()
}

// goldenUnsignedHashes are sha256 of the unsigned package bytes; any refactor
// MUST reproduce them byte-for-byte. Recaptured 2026-09-06 for the canonical
// MSIX container form (central directory "version made by" 4.5, ZIP64 end
// records with a sentinel EOCD stub, deflated [Content_Types].xml) that
// Windows AppxSIP requires — the previous classic-zip goldens (captured
// 2026-06-24) described a container Windows rejects with HashMismatch when
// signed.
var goldenUnsignedHashes = map[string]string{
	"single":        "871c40f83d509f3807573bd17b9008b4dcbdee00a2ff0a8c8cab9d5d84186617",
	"multiblock":    "60ef840f57b44378de017803acbc96c7b101c14cf5d4eb4590fc8dc1e124cf9b",
	"subdirs_empty": "272d44dbc0c2449fdc290cffdc06986b6a961396142831c1bc661048f4cb7326",
}

// TestUnsignedByteEquality asserts the unsigned package output is byte-identical to
// the original implementation.
func TestUnsignedByteEquality(t *testing.T) {
	for name, add := range goldenScenarios() {
		data := goldenBuildUnsigned(t, add)
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		want, ok := goldenUnsignedHashes[name]
		require.True(t, ok, "no golden hash for scenario %q", name)
		require.Equal(t, want, got, "scenario %q: unsigned package hash changed (len=%d)", name, len(data))
	}
}
