package msix

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderManifest_Basic(t *testing.T) {
	m := manifestData{
		Identity: identityData{
			Name:                  "TestCompany.TestApp",
			Version:               "1.0.0.0",
			Publisher:             "CN=TestCompany",
			ProcessorArchitecture: "x64",
		},
		Properties: propertiesData{
			DisplayName:          "Test App",
			PublisherDisplayName: "Test Company",
			Logo:                 "Assets/logo.png",
		},
		Dependencies: dependenciesData{
			TargetDeviceFamilies: []targetDeviceFamilyData{
				{Name: "Windows.Desktop", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources: []resourceData{
			{Language: "en-us"},
		},
		Applications: []applicationData{
			{
				ID:         "App",
				Executable: "TestApp.exe",
				VisualElements: visualElementsData{
					DisplayName:       "Test App",
					BackgroundColor:   "#464646",
					Square150x150Logo: "Assets/150.png",
					Square44x44Logo:   "Assets/44.png",
				},
			},
		},
	}

	data, err := renderManifest(&m)
	require.NoError(t, err)
	s := string(data)

	assert.True(t, strings.HasPrefix(s, "<?xml"), "missing XML header")
	assert.Contains(t, s, nsFoundation, "missing foundation namespace")
	assert.Contains(t, s, `Name="TestCompany.TestApp"`)
	assert.Contains(t, s, `Version="1.0.0.0"`)
	assert.Contains(t, s, `Publisher="CN=TestCompany"`)
	assert.Contains(t, s, `ProcessorArchitecture="x64"`)
	assert.Contains(t, s, "<DisplayName>Test App</DisplayName>")
	assert.Contains(t, s, "<PublisherDisplayName>Test Company</PublisherDisplayName>")
	assert.Contains(t, s, `Name="Windows.Desktop"`)
	assert.Contains(t, s, `Language="en-us"`)
	assert.Contains(t, s, `Id="App"`)
	assert.Contains(t, s, `Executable="TestApp.exe"`)
	assert.Contains(t, s, "uap:VisualElements")
}

func TestRenderManifest_WithCapabilities(t *testing.T) {
	m := manifestData{
		Identity:   identityData{Name: "Test.App", Version: "1.0.0.0", Publisher: "CN=Test"},
		Properties: propertiesData{DisplayName: "Test", PublisherDisplayName: "Test"},
		Dependencies: dependenciesData{
			TargetDeviceFamilies: []targetDeviceFamilyData{
				{Name: "Windows.Desktop", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources: []resourceData{{Language: "en-us"}},
		Capabilities: capabilitiesData{
			Capabilities: []capabilityData{{Name: "internetClient"}},
			Restricted:   []restrictedCapabilityData{{Name: "runFullTrust"}},
		},
	}

	data, err := renderManifest(&m)
	require.NoError(t, err)
	s := string(data)

	assert.Contains(t, s, `<Capability Name="internetClient"`)
	assert.Contains(t, s, `rescap:Capability Name="runFullTrust"`)
	assert.Contains(t, s, nsRescap)
}

func TestRenderManifest_WithExtensions(t *testing.T) {
	m := manifestData{
		Identity:   identityData{Name: "Test.App", Version: "1.0.0.0", Publisher: "CN=Test"},
		Properties: propertiesData{DisplayName: "Test", PublisherDisplayName: "Test"},
		Dependencies: dependenciesData{
			TargetDeviceFamilies: []targetDeviceFamilyData{
				{Name: "Windows.Desktop", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources: []resourceData{{Language: "en-us"}},
		Applications: []applicationData{
			{
				ID: "App", Executable: "App.exe",
				VisualElements: visualElementsData{
					DisplayName: "App", BackgroundColor: "#000000",
					Square150x150Logo: "a.png", Square44x44Logo: "b.png",
				},
				Extensions: []appExtData{
					{
						Category: "windows.protocol",
						Protocol: &protocolData{Name: "myapp"},
					},
					{
						Category: "windows.fileTypeAssociation",
						FileTypeAssociation: &fileTypeAssociationData{
							Name:               "myfiles",
							SupportedFileTypes: []fileTypeData{{Extension: ".myf"}},
						},
					},
					{
						Category: "windows.appExecutionAlias",
						AppExecutionAlias: &appExecutionAliasData{
							ExecutionAliases: []executionAliasData{{Alias: "myapp.exe"}},
						},
					},
				},
			},
		},
	}

	data, err := renderManifest(&m)
	require.NoError(t, err)
	s := string(data)

	assert.Contains(t, s, `uap:Protocol Name="myapp"`)
	assert.Contains(t, s, "uap:FileTypeAssociation")
	assert.Contains(t, s, ".myf")
	assert.Contains(t, s, "uap5:AppExecutionAlias")
	assert.Contains(t, s, `Alias="myapp.exe"`)
	assert.Contains(t, s, nsUAP5)
}

func TestRenderManifest_XmlEscaping(t *testing.T) {
	m := manifestData{
		Identity: identityData{
			Name: "Test.App", Version: "1.0.0.0",
			Publisher: `CN=Test & "Company" <Inc>`,
		},
		Properties: propertiesData{DisplayName: "Test & App", PublisherDisplayName: "Test"},
		Dependencies: dependenciesData{
			TargetDeviceFamilies: []targetDeviceFamilyData{
				{Name: "Windows.Desktop", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources: []resourceData{{Language: "en-us"}},
	}

	data, err := renderManifest(&m)
	require.NoError(t, err)
	s := string(data)

	assert.Contains(t, s, "&amp;")
	assert.Contains(t, s, "&lt;")
	assert.Contains(t, s, "&gt;")
}

func TestManifestNamespaces_OnlyUsedNamespaces(t *testing.T) {
	m := &manifestData{
		Applications: []applicationData{{ID: "App"}},
	}

	ns := manifestNamespaces(m)
	prefixSet := make(map[string]bool, len(ns))
	for _, entry := range ns {
		prefixSet[entry.Prefix] = true
	}

	assert.True(t, prefixSet["uap"], "expected uap namespace when applications present")
	assert.False(t, prefixSet["rescap"], "rescap should not be present without restricted capabilities")
	assert.False(t, prefixSet["desktop"], "desktop should not be present without desktop extensions")
}

func TestRenderManifest_NoApplications(t *testing.T) {
	m := manifestData{
		Identity:   identityData{Name: "Test.Pkg", Version: "1.0.0.0", Publisher: "CN=Test"},
		Properties: propertiesData{DisplayName: "Test", PublisherDisplayName: "Test", Framework: true},
		Dependencies: dependenciesData{
			TargetDeviceFamilies: []targetDeviceFamilyData{
				{Name: "Windows.Universal", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources: []resourceData{{Language: "en-us"}},
	}

	data, err := renderManifest(&m)
	require.NoError(t, err)
	s := string(data)

	assert.NotContains(t, s, "<Applications>", "should not contain Applications for framework package")
	assert.Contains(t, s, "<Framework>true</Framework>")
}
