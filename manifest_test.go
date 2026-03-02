package msix

import (
	"strings"
	"testing"
)

func TestRenderManifest_Basic(t *testing.T) {
	m := Manifest{
		Identity: Identity{
			Name:                  "TestCompany.TestApp",
			Version:               "1.0.0.0",
			Publisher:             "CN=TestCompany",
			ProcessorArchitecture: "x64",
		},
		Properties: Properties{
			DisplayName:         "Test App",
			PublisherDisplayName: "Test Company",
			Logo:                "Assets/logo.png",
		},
		Dependencies: Dependencies{
			TargetDeviceFamilies: []TargetDeviceFamily{
				{Name: "Windows.Desktop", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources: []Resource{
			{Language: "en-us"},
		},
		Applications: []Application{
			{
				ID:         "App",
				Executable: "TestApp.exe",
				VisualElements: VisualElements{
					DisplayName:       "Test App",
					BackgroundColor:   "#464646",
					Square150x150Logo: "Assets/150.png",
					Square44x44Logo:   "Assets/44.png",
				},
			},
		},
	}

	data, err := renderManifest(&m)
	if err != nil {
		t.Fatal(err)
	}

	s := string(data)

	// Check XML header.
	if !strings.HasPrefix(s, "<?xml") {
		t.Fatal("missing XML header")
	}

	// Check foundation namespace.
	if !strings.Contains(s, nsFoundation) {
		t.Fatal("missing foundation namespace")
	}

	// Check identity.
	if !strings.Contains(s, `Name="TestCompany.TestApp"`) {
		t.Fatal("missing identity name")
	}
	if !strings.Contains(s, `Version="1.0.0.0"`) {
		t.Fatal("missing version")
	}
	if !strings.Contains(s, `Publisher="CN=TestCompany"`) {
		t.Fatal("missing publisher")
	}
	if !strings.Contains(s, `ProcessorArchitecture="x64"`) {
		t.Fatal("missing processor architecture")
	}

	// Check properties.
	if !strings.Contains(s, "<DisplayName>Test App</DisplayName>") {
		t.Fatal("missing display name")
	}
	if !strings.Contains(s, "<PublisherDisplayName>Test Company</PublisherDisplayName>") {
		t.Fatal("missing publisher display name")
	}

	// Check dependencies.
	if !strings.Contains(s, `Name="Windows.Desktop"`) {
		t.Fatal("missing target device family")
	}

	// Check resources.
	if !strings.Contains(s, `Language="en-us"`) {
		t.Fatal("missing resource language")
	}

	// Check application.
	if !strings.Contains(s, `Id="App"`) {
		t.Fatal("missing app ID")
	}
	if !strings.Contains(s, `Executable="TestApp.exe"`) {
		t.Fatal("missing executable")
	}

	// Check VisualElements with uap prefix.
	if !strings.Contains(s, "uap:VisualElements") {
		t.Fatal("missing uap:VisualElements")
	}
}

func TestRenderManifest_WithCapabilities(t *testing.T) {
	m := Manifest{
		Identity: Identity{
			Name: "Test.App", Version: "1.0.0.0", Publisher: "CN=Test",
		},
		Properties: Properties{
			DisplayName: "Test", PublisherDisplayName: "Test",
		},
		Dependencies: Dependencies{
			TargetDeviceFamilies: []TargetDeviceFamily{
				{Name: "Windows.Desktop", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources: []Resource{{Language: "en-us"}},
		Capabilities: Capabilities{
			Capabilities: []Capability{{Name: "internetClient"}},
			Restricted:   []RestrictedCapability{{Name: "runFullTrust"}},
		},
	}

	data, err := renderManifest(&m)
	if err != nil {
		t.Fatal(err)
	}

	s := string(data)

	if !strings.Contains(s, `<Capability Name="internetClient"`) {
		t.Fatal("missing internetClient capability")
	}
	if !strings.Contains(s, `rescap:Capability Name="runFullTrust"`) {
		t.Fatal("missing rescap:Capability")
	}
	if !strings.Contains(s, nsRescap) {
		t.Fatal("missing rescap namespace declaration")
	}
}

func TestRenderManifest_WithExtensions(t *testing.T) {
	m := Manifest{
		Identity: Identity{
			Name: "Test.App", Version: "1.0.0.0", Publisher: "CN=Test",
		},
		Properties: Properties{
			DisplayName: "Test", PublisherDisplayName: "Test",
		},
		Dependencies: Dependencies{
			TargetDeviceFamilies: []TargetDeviceFamily{
				{Name: "Windows.Desktop", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources: []Resource{{Language: "en-us"}},
		Applications: []Application{
			{
				ID: "App", Executable: "App.exe",
				VisualElements: VisualElements{
					DisplayName: "App", BackgroundColor: "#000000",
					Square150x150Logo: "a.png", Square44x44Logo: "b.png",
				},
				Extensions: []ApplicationExtension{
					{
						Category: "windows.protocol",
						Protocol: &Protocol{Name: "myapp"},
					},
					{
						Category: "windows.fileTypeAssociation",
						FileTypeAssociation: &FileTypeAssociation{
							Name:               "myfiles",
							SupportedFileTypes: []FileType{{Extension: ".myf"}},
						},
					},
					{
						Category: "windows.appExecutionAlias",
						AppExecutionAlias: &AppExecutionAlias{
							ExecutionAliases: []ExecutionAlias{{Alias: "myapp.exe"}},
						},
					},
				},
			},
		},
	}

	data, err := renderManifest(&m)
	if err != nil {
		t.Fatal(err)
	}

	s := string(data)

	// Check protocol.
	if !strings.Contains(s, `uap:Protocol Name="myapp"`) {
		t.Fatal("missing protocol extension")
	}

	// Check file type association.
	if !strings.Contains(s, "uap:FileTypeAssociation") {
		t.Fatal("missing FileTypeAssociation")
	}
	if !strings.Contains(s, ".myf") {
		t.Fatal("missing file extension")
	}

	// Check execution alias.
	if !strings.Contains(s, "uap5:AppExecutionAlias") {
		t.Fatal("missing AppExecutionAlias")
	}
	if !strings.Contains(s, `Alias="myapp.exe"`) {
		t.Fatal("missing alias")
	}

	// Check uap5 namespace declaration.
	if !strings.Contains(s, nsUAP5) {
		t.Fatal("missing uap5 namespace declaration")
	}
}

func TestRenderManifest_XmlEscaping(t *testing.T) {
	m := Manifest{
		Identity: Identity{
			Name: "Test.App", Version: "1.0.0.0",
			Publisher: `CN=Test & "Company" <Inc>`,
		},
		Properties: Properties{
			DisplayName: "Test & App", PublisherDisplayName: "Test",
		},
		Dependencies: Dependencies{
			TargetDeviceFamilies: []TargetDeviceFamily{
				{Name: "Windows.Desktop", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources: []Resource{{Language: "en-us"}},
	}

	data, err := renderManifest(&m)
	if err != nil {
		t.Fatal(err)
	}

	s := string(data)

	// Check escaping.
	if !strings.Contains(s, "&amp;") {
		t.Fatal("ampersand not escaped")
	}
	if !strings.Contains(s, "&lt;") {
		t.Fatal("less-than not escaped")
	}
	if !strings.Contains(s, "&gt;") {
		t.Fatal("greater-than not escaped")
	}
}

func TestManifestNamespaces_OnlyUsedNamespaces(t *testing.T) {
	// Minimal manifest should only have uap (for VisualElements in Applications).
	m := &Manifest{
		Applications: []Application{
			{ID: "App"},
		},
	}

	ns := manifestNamespaces(m)

	// Build a set of prefixes for easy lookup.
	prefixSet := make(map[string]bool, len(ns))
	for _, entry := range ns {
		prefixSet[entry.Prefix] = true
	}

	if !prefixSet["uap"] {
		t.Fatal("expected uap namespace when applications present")
	}
	if prefixSet["rescap"] {
		t.Fatal("rescap should not be present without restricted capabilities")
	}
	if prefixSet["desktop"] {
		t.Fatal("desktop should not be present without desktop extensions")
	}
}

func TestRenderManifest_NoApplications(t *testing.T) {
	m := Manifest{
		Identity: Identity{
			Name: "Test.Pkg", Version: "1.0.0.0", Publisher: "CN=Test",
		},
		Properties: Properties{
			DisplayName: "Test", PublisherDisplayName: "Test", Framework: true,
		},
		Dependencies: Dependencies{
			TargetDeviceFamilies: []TargetDeviceFamily{
				{Name: "Windows.Universal", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources: []Resource{{Language: "en-us"}},
	}

	data, err := renderManifest(&m)
	if err != nil {
		t.Fatal(err)
	}

	s := string(data)

	// Should not contain Applications element.
	if strings.Contains(s, "<Applications>") {
		t.Fatal("should not contain Applications for framework package")
	}

	// Should contain Framework property.
	if !strings.Contains(s, "<Framework>true</Framework>") {
		t.Fatal("missing Framework property")
	}
}
