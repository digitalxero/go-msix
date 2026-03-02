package msix

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestMarshalContentTypes_BasicFiles(t *testing.T) {
	files := []string{"app.exe", "icon.png", "config.json"}

	data, err := marshalContentTypes(files)
	if err != nil {
		t.Fatal(err)
	}

	s := string(data)

	// Check XML header.
	if !strings.HasPrefix(s, "<?xml") {
		t.Fatal("missing XML header")
	}

	// Check namespace.
	if !strings.Contains(s, contentTypesNamespace) {
		t.Fatal("missing content types namespace")
	}

	// Check defaults for known extensions.
	if !strings.Contains(s, `Extension="exe"`) {
		t.Fatal("missing exe extension")
	}
	if !strings.Contains(s, `Extension="png"`) {
		t.Fatal("missing png extension")
	}
	if !strings.Contains(s, `Extension="json"`) {
		t.Fatal("missing json extension")
	}

	// Check overrides for MSIX metadata.
	if !strings.Contains(s, `/AppxBlockMap.xml`) {
		t.Fatal("missing AppxBlockMap.xml override")
	}
	// AppxManifest.xml should NOT have an override — the .xml extension default
	// (application/vnd.ms-appx.manifest+xml) covers it, matching Microsoft's behavior.
	if strings.Contains(s, `PartName="/AppxManifest.xml"`) {
		t.Fatal("AppxManifest.xml should not have a separate override")
	}
	// AppxSignature.p7x override should not be present for unsigned packages.
	if strings.Contains(s, `/AppxSignature.p7x`) {
		t.Fatal("AppxSignature.p7x override should not be present without signature file in input list")
	}
}

func TestMarshalContentTypes_ValidXML(t *testing.T) {
	files := []string{"test.exe", "data.json"}

	data, err := marshalContentTypes(files)
	if err != nil {
		t.Fatal(err)
	}

	var parsed contentTypesXML
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}

	if len(parsed.Defaults) < 2 {
		t.Fatalf("expected at least 2 defaults, got %d", len(parsed.Defaults))
	}
	if len(parsed.Overrides) != 1 {
		t.Fatalf("expected 1 override (AppxBlockMap.xml only), got %d", len(parsed.Overrides))
	}
}

func TestMarshalContentTypes_UnknownExtension(t *testing.T) {
	files := []string{"data.xyz"}

	data, err := marshalContentTypes(files)
	if err != nil {
		t.Fatal(err)
	}

	s := string(data)
	if !strings.Contains(s, `application/octet-stream`) {
		t.Fatal("unknown extension should default to application/octet-stream")
	}
}

func TestMarshalContentTypes_NoExtension(t *testing.T) {
	files := []string{"Makefile"}

	data, err := marshalContentTypes(files)
	if err != nil {
		t.Fatal(err)
	}

	// Files without extensions should not add a Default entry.
	var parsed contentTypesXML
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	// Should only have overrides, no defaults for extensionless files.
	for _, d := range parsed.Defaults {
		if d.Extension == "" {
			t.Fatal("should not add Default for empty extension")
		}
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
		got := lookupMIME(tt.ext)
		if got != tt.want {
			t.Errorf("lookupMIME(%q) = %q, want %q", tt.ext, got, tt.want)
		}
	}
}
