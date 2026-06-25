package msix

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalContentTypes_BasicFiles(t *testing.T) {
	files := []string{"app.exe", "icon.png", "config.json"}

	data, err := marshalContentTypes(files)
	require.NoError(t, err)
	s := string(data)

	assert.True(t, strings.HasPrefix(s, "<?xml"), "missing XML header")
	assert.Contains(t, s, contentTypesNamespace, "missing content types namespace")
	assert.Contains(t, s, `Extension="exe"`)
	assert.Contains(t, s, `Extension="png"`)
	assert.Contains(t, s, `Extension="json"`)
	assert.Contains(t, s, `/AppxBlockMap.xml`, "missing AppxBlockMap.xml override")
	// AppxManifest.xml relies on the .xml default, not a separate override.
	assert.NotContains(t, s, `PartName="/AppxManifest.xml"`)
	// No signature override for unsigned packages.
	assert.NotContains(t, s, `/AppxSignature.p7x`)
}

func TestMarshalContentTypes_ValidXML(t *testing.T) {
	files := []string{"test.exe", "data.json"}

	data, err := marshalContentTypes(files)
	require.NoError(t, err)

	var parsed contentTypesXML
	require.NoError(t, xml.Unmarshal(data, &parsed))
	assert.GreaterOrEqual(t, len(parsed.Defaults), 2)
	assert.Len(t, parsed.Overrides, 1, "expected only the AppxBlockMap.xml override")
}

func TestMarshalContentTypes_UnknownExtension(t *testing.T) {
	data, err := marshalContentTypes([]string{"data.xyz"})
	require.NoError(t, err)
	assert.Contains(t, string(data), `application/octet-stream`)
}

func TestMarshalContentTypes_NoExtension(t *testing.T) {
	data, err := marshalContentTypes([]string{"Makefile"})
	require.NoError(t, err)

	var parsed contentTypesXML
	require.NoError(t, xml.Unmarshal(data, &parsed))
	for _, d := range parsed.Defaults {
		assert.NotEmpty(t, d.Extension, "should not add Default for empty extension")
	}
}

func TestLookupMIME(t *testing.T) {
	tests := []struct {
		ext  string
		want string
	}{
		{".exe", "application/x-msdownload"},
		{".png", "image/png"},
		{".json", "application/json"},
		{".unknown", "application/octet-stream"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, lookupMIME(tt.ext), "lookupMIME(%q)", tt.ext)
	}
}
