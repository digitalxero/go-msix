package msix_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	msix "go.digitalxero.dev/go-msix"
)

func auditIdentity() msix.IdentityBuilder {
	return msix.NewIdentity().WithName("Audit.App").WithVersion("1.2.3.0").WithPublisher("CN=Test").WithProcessorArchitecture("x64")
}
func auditProperties() msix.PropertiesBuilder {
	return msix.NewProperties().WithDisplayName("Audit").WithPublisherDisplayName("Audit").WithLogo("logo.png")
}
func auditVisualBuilder() msix.VisualElementsBuilder {
	return msix.NewVisualElements().WithDisplayName("Audit").WithDescription("Audit application").WithBackgroundColor("transparent").WithSquare150x150Logo("logo.png").WithSquare44x44Logo("logo.png")
}
func auditVisual() msix.VisualElements { return auditVisualBuilder().Build() }
func auditApp(id string, exts ...msix.ApplicationExtension) msix.Application {
	a := msix.NewApplication().WithID(id).WithExecutable("app.exe").WithEntryPoint("Windows.FullTrustApplication").WithVisualElements(auditVisual())
	for _, e := range exts {
		a.AddExtension(e)
	}
	return a.Build()
}
func auditBase() msix.Builder {
	return msix.NewBuilder().WithIdentity(auditIdentity().Build()).WithProperties(auditProperties().Build()).WithDependencies(msix.NewDependencies().AddTargetDeviceFamily("Windows.Desktop", "10.0.19645.0", "10.0.26100.0").Build()).AddFileFromBytes("app.exe", []byte("MZ audit")).AddFileFromBytes("logo.png", []byte("audit image"))
}
func auditBuild(b msix.Builder) ([]byte, error) {
	var buf bytes.Buffer
	err := b.Build(context.Background(), &buf)
	return buf.Bytes(), err
}
func auditManifest(t *testing.T, b msix.Builder) []byte {
	t.Helper()
	data, err := auditBuild(b)
	require.NoError(t, err)
	return unzip(t, data)["AppxManifest.xml"]
}
func auditElements(t *testing.T, data []byte, local string) []xml.StartElement {
	t.Helper()
	d := xml.NewDecoder(bytes.NewReader(data))
	var out []xml.StartElement
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if e, ok := tok.(xml.StartElement); ok && e.Name.Local == local {
			out = append(out, e)
		}
	}
	return out
}

// #6: every file-adder must enforce one owner per effective Windows path.
func TestAuditPayloadCollisions(t *testing.T) {
	pairs := [][]string{{"data.txt", "data.txt"}, {"data.txt", "DATA.TXT"}, {"dir/data.txt", `dir\data.txt`}, {"data", "DATA/sub.txt"}, {"DATA/sub.txt", "data"}, {"AppxManifest.xml"}, {"appxblockmap.XML"}, {"[CONTENT_TYPES].xml"}, {"AppxSignature.p7x"}, {"AppxStreamMap.xml"}, {"appxmanifest.xml/child"}, {"APPXMETADATA/codeintegrity.cat"}}
	for _, variant := range []string{"bytes", "disk", "reader", "source"} {
		t.Run(variant, func(t *testing.T) {
			disk := filepath.Join(t.TempDir(), "payload")
			require.NoError(t, os.WriteFile(disk, []byte("data"), 0600))
			for _, paths := range pairs {
				t.Run(strings.Join(paths, "+"), func(t *testing.T) {
					b := auditBase()
					for _, p := range paths {
						switch variant {
						case "bytes":
							b.AddFileFromBytes(p, []byte("data"))
						case "disk":
							b.AddFile(p, disk)
						case "reader":
							b.AddFileFromReader(p, strings.NewReader("data"))
						case "source":
							b.AddFileSource(p, func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("data")), nil })
						}
					}
					data, err := auditBuild(b)
					require.Error(t, err)
					assert.Empty(t, data)
					assert.Contains(t, err.Error(), paths[0])
				})
			}
		})
	}
	data, err := auditBuild(auditBase().AddFileFromBytes("Dir/A.txt", nil).AddFileFromBytes("Dir/B.txt", nil).AddFileFromBytes("AppxMetadata/CodeIntegrity.cat", []byte("catalog")))
	require.NoError(t, err)
	assert.Contains(t, unzip(t, data), "AppxMetadata/CodeIntegrity.cat")
}

// #7: a single leading slash remains supported; UNC/traversal/device aliases do not.
func TestAuditPayloadPaths(t *testing.T) {
	for _, p := range []string{"", "/", "../outside.txt", `dir\..\outside.txt`, "./data", "a//b", "a/./b", "a/", "//server/share", `\\server\share`, "C:/outside.txt", "NUL.txt", "NUL .txt", "con", "COM1.log", "Lpt9", "COM¹.txt", strings.Repeat("a", 256), strings.Repeat("😀", 128), "aux/data", "readme.txt.", "readme.txt ", "file.txt:stream", `a<b`, `a|b`, `a?b`, `a*b`, `a"b`, "a\x00b", "a\x1fb", string([]byte{0xff})} {
		t.Run(p, func(t *testing.T) {
			data, err := auditBuild(auditBase().AddFileFromBytes(p, nil))
			require.Error(t, err)
			assert.Empty(t, data)
		})
	}
	for _, p := range []string{"/Root.txt", `\Root.txt`, "café/日本語.txt", "nulled.txt", "COM10.txt", "a.b/c.d.txt"} {
		t.Run(p, func(t *testing.T) {
			data, err := auditBuild(auditBase().AddFileFromBytes(p, []byte("ok")))
			require.NoError(t, err)
			assert.Contains(t, unzip(t, data), strings.TrimPrefix(strings.ReplaceAll(p, `\`, "/"), "/"))
		})
	}
}

// #8: direct API values are validated before writing any package bytes.
func TestAuditCoreManifest(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(msix.Builder)
	}{
		{"malformed version", func(b msix.Builder) { b.WithIdentity(auditIdentity().WithVersion("1.x.3.0").Build()) }},
		{"negative version", func(b msix.Builder) { b.WithIdentity(auditIdentity().WithVersion("-1.2.3.0").Build()) }},
		{"overflow", func(b msix.Builder) { b.WithIdentity(auditIdentity().WithVersion("65536.0.0.0").Build()) }},
		{"short version", func(b msix.Builder) { b.WithIdentity(auditIdentity().WithVersion("1.2.3").Build()) }},
		{"leading zero", func(b msix.Builder) { b.WithIdentity(auditIdentity().WithVersion("01.2.3.0").Build()) }},
		{"name", func(b msix.Builder) { b.WithIdentity(auditIdentity().WithName("bad package name").Build()) }},
		{"resource exclusive qualifiers", func(b msix.Builder) {
			b.AddResource(msix.NewResource().WithScale("100").WithDXFeatureLevel("dx9").Build())
		}},
		{"resource architecture", func(b msix.Builder) {
			b.WithIdentity(auditIdentity().WithResourceID("en-us").Build()).WithProperties(auditProperties().WithResourcePackage(true).Build())
		}},
		{"architecture", func(b msix.Builder) { b.WithIdentity(auditIdentity().WithProcessorArchitecture("bogus").Build()) }},
		{"resource id", func(b msix.Builder) { b.WithIdentity(auditIdentity().WithResourceID("bad id").Build()) }},
		{"publisher", func(b msix.Builder) { b.WithIdentity(auditIdentity().WithPublisher("not a DN").Build()) }},
		{"dependency version", func(b msix.Builder) {
			b.WithDependencies(msix.NewDependencies().AddTargetDeviceFamily("Windows.Desktop", "bad", "10.0.26100.0").Build())
		}},
		{"dependency missing", func(b msix.Builder) { b.WithDependencies(msix.NewDependencies().Build()) }},
		{"description control", func(b msix.Builder) { b.WithProperties(auditProperties().WithDescription("a\tb").Build()) }},

		{"background color", func(b msix.Builder) {
			b.AddApplication(msix.NewApplication().WithID("App").WithExecutable("app.exe").WithVisualElements(auditVisualBuilder().WithBackgroundColor("bogus").Build()).Build())
		}},
		{"percent manifest path", func(b msix.Builder) {
			b.AddFileFromBytes("percent%.exe", nil).AddApplication(msix.NewApplication().WithID("App").WithExecutable("percent%.exe").WithVisualElements(auditVisual()).Build())
		}},
		{"local start page", func(b msix.Builder) {
			b.AddApplication(msix.NewApplication().WithID("Web").WithStartPage("missing.html").WithVisualElements(auditVisual()).Build())
		}},
		{"properties required", func(b msix.Builder) { b.WithProperties(msix.NewProperties().Build()) }},
		{"padded name", func(b msix.Builder) { b.WithProperties(auditProperties().WithDisplayName(" Padded ").Build()) }},
		{"missing logo", func(b msix.Builder) { b.WithProperties(auditProperties().WithLogo("missing.png").Build()) }},
		{"missing executable", func(b msix.Builder) {
			b.AddApplication(msix.NewApplication().WithID("Missing").WithExecutable("missing.exe").WithVisualElements(auditVisual()).Build())
		}},
		{"application id", func(b msix.Builder) { b.AddApplication(auditApp("bad-id")) }},
		{"executable type", func(b msix.Builder) {
			b.AddApplication(msix.NewApplication().WithID("Script").WithExecutable("app.cmd").WithVisualElements(auditVisual()).Build())
		}},
		{"visual asset", func(b msix.Builder) {
			b.AddApplication(msix.NewApplication().WithID("App").WithExecutable("app.exe").WithVisualElements(msix.NewVisualElements().WithDisplayName("App").WithDescription("App").WithBackgroundColor("transparent").WithSquare150x150Logo("missing.png").WithSquare44x44Logo("logo.png").Build()).Build())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := auditBase()
			tc.configure(b)
			data, err := auditBuild(b)
			require.Error(t, err)
			assert.Empty(t, data)
		})
	}
	for _, version := range []string{"0.0.0.0", "65535.65535.65535.65535"} {
		_, err := auditBuild(auditBase().WithIdentity(auditIdentity().WithVersion(version).Build()))
		require.NoError(t, err)
	}
	// Optional executable is legal for hosted/activation-only apps.
	_, err := auditBuild(auditBase().AddApplication(msix.NewApplication().WithID("Hosted").WithStartPage("https://example.com").WithVisualElements(auditVisual()).Build()))
	require.NoError(t, err)
	_, err = auditBuild(auditBase().AddApplication(msix.NewApplication().WithID("LocalWeb").WithStartPage("index.html").WithVisualElements(auditVisual()).Build()).AddFileFromBytes("index.html", []byte("<html></html>")))
	require.NoError(t, err)
	// Resource references are resolved by MRT; qualified image variants satisfy base references.
	_, err = auditBuild(auditBase().WithProperties(auditProperties().WithLogo("Assets/Logo.png").Build()).AddFileFromBytes("Assets/en-us/Logo.scale-200.png", nil))
	require.NoError(t, err)
	_, err = auditBuild(auditBase().WithProperties(auditProperties().WithDisplayName("ms-resource:DisplayName").Build()))
	require.NoError(t, err)
}

// #9: identifiers have field-specific comparison rules.
func TestAuditRegistrationIdentities(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b msix.Application
	}{
		{"application", auditApp("App"), auditApp("App")},
		{"protocol", auditApp("One", msix.NewProtocol().WithName("audit").Build()), auditApp("Two", msix.NewProtocol().WithName("audit").Build())},
		{"service", auditApp("One", msix.NewService().WithName("AuditService").Build()), auditApp("Two", msix.NewServiceDesktop7().WithName("auditservice").Build())},
		{"shortcut", auditApp("One", msix.NewShortcut().WithFile(`$(Desktop)\Audit.lnk`).WithIcon("app.exe").Build()), auditApp("Two", msix.NewShortcut().WithFile(`$(Desktop)/audit.lnk`).WithIcon("app.exe").Build())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := auditBuild(auditBase().AddApplication(tc.a).AddApplication(tc.b))
			require.Error(t, err)
			assert.Empty(t, data)
		})
	}
	_, err := auditBuild(auditBase().AddApplication(auditApp("One", msix.NewProtocol().WithName("audit-one").Build())).AddApplication(auditApp("Two", msix.NewProtocol().WithName("audit-two").Build())))
	require.NoError(t, err)
	_, err = auditBuild(auditBase().AddApplication(auditApp("App")).AddApplication(auditApp("app")))
	require.NoError(t, err, "Application Id has schema case-sensitive uniqueness")
	_, err = auditBuild(auditBase().AddApplication(auditApp("One", msix.NewShortcut().WithFile(`$(Desktop)\Alias.lnk`).WithIcon("app.exe").Build())).AddApplication(auditApp("Two", msix.NewShortcut().WithFile(`$(desktop)/ALIAS.LNK`).WithIcon("app.exe").Build())))
	require.Error(t, err)
	_, err = auditBuild(auditBase().AddApplication(auditApp("One", msix.NewShortcut().WithFile(`$(Programs)\Distinct.lnk`).WithIcon("app.exe").Build())).AddApplication(auditApp("Two", msix.NewShortcut().WithFile(`$(Common Programs)\Distinct.lnk`).WithIcon("app.exe").Build())))
	require.NoError(t, err)
	_, err = auditBuild(auditBase().AddApplication(auditApp("App", msix.NewProtocol().WithName("audit").Build(), msix.NewProtocolUap10().WithName("audit").Build())))
	require.Error(t, err)

}

// #11-14: assert decoded XML names and values, not just substrings.
func TestAuditManifestSerialization(t *testing.T) {
	const uap = "http://schemas.microsoft.com/appx/manifest/uap/windows10"
	const desktop10 = "http://schemas.microsoft.com/appx/manifest/desktop/windows10/10"
	t.Run("protocol", func(t *testing.T) {
		data := auditManifest(t, auditBase().AddApplication(auditApp("App", msix.NewProtocol().WithName("audit").WithDisplayName(`Audit & <Protocol>`).WithLogo("logo.png").Build())))
		logos := auditElements(t, data, "Logo")
		var protocolLogo bool
		for _, l := range logos {
			if l.Name.Space == uap {
				protocolLogo = true
			}
		}
		assert.True(t, protocolLogo, "protocol logo must be retained")
		protocols := auditElements(t, data, "Protocol")
		require.Len(t, protocols, 1)
		for _, a := range protocols[0].Attr {
			assert.NotEqual(t, "DesktopAppInfo", a.Name.Local)
		}
		var found bool
		d := xml.NewDecoder(bytes.NewReader(data))
		for {
			tok, err := d.Token()
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			if e, ok := tok.(xml.StartElement); ok && e.Name == (xml.Name{Space: uap, Local: "DisplayName"}) {
				var s string
				require.NoError(t, d.DecodeElement(&s, &e))
				assert.Equal(t, `Audit & <Protocol>`, s)
				found = true
			}
		}
		assert.True(t, found)
	})
	t.Run("shortcut", func(t *testing.T) {
		args := "--name=\"A & B\"\tline\r\nnext"
		name := "Audit & shortcut"
		data := auditManifest(t, auditBase().AddApplication(auditApp("App", msix.NewShortcut().WithFile(`$(Desktop)\Audit.lnk`).WithIcon("app.exe").WithArguments(args).WithDisplayName(name).Build())))
		es := auditElements(t, data, "Shortcut")
		require.Len(t, es, 1)
		attrs := map[xml.Name]string{}
		for _, a := range es[0].Attr {
			attrs[a.Name] = a.Value
		}
		assert.Equal(t, args, attrs[xml.Name{Local: "Arguments"}])
		assert.Equal(t, name, attrs[xml.Name{Space: desktop10, Local: "DisplayName"}])
		assert.NotContains(t, attrs, xml.Name{Local: "DisplayName"})
	})
	t.Run("shortcut unset", func(t *testing.T) {
		data := auditManifest(t, auditBase().AddApplication(auditApp("App", msix.NewShortcut().WithFile(`$(Desktop)\Audit.lnk`).WithIcon("app.exe").Build())))
		es := auditElements(t, data, "Shortcut")
		require.Len(t, es, 1)
		for _, a := range es[0].Attr {
			assert.NotEqual(t, "Arguments", a.Name.Local)
			assert.NotEqual(t, "DisplayName", a.Name.Local)
		}
		assert.NotContains(t, string(data), "xmlns:desktop10=")
	})

	for _, mode := range []string{"unset", "false", "true"} {
		t.Run("allow execution "+mode, func(t *testing.T) {
			p := auditProperties()
			if mode != "unset" {
				p.WithAllowExecution(mode == "true")
			}
			data := auditManifest(t, auditBase().WithProperties(p.Build()))
			es := auditElements(t, data, "AllowExecution")
			if mode == "unset" {
				assert.Empty(t, es)
			} else {
				require.Len(t, es, 1)
				assert.Equal(t, uap+"/6", es[0].Name.Space)
				assert.Contains(t, string(data), ">"+mode+"</uap6:AllowExecution>")
			}
		})
	}
	for _, mode := range []string{"scale", "dx", "both"} {
		t.Run("resource "+mode, func(t *testing.T) {
			r := msix.NewResource()
			if mode != "dx" {
				r.WithScale("100")
			}
			if mode == "dx" {
				r.WithDXFeatureLevel("dx9")
			}
			b := auditBase().WithIdentity(auditIdentity().WithResourceID("resources").WithProcessorArchitecture("").Build()).WithProperties(auditProperties().WithResourcePackage(true).Build()).AddResource(r.Build())
			if mode == "both" {
				b.WithIdentity(auditIdentity().Build()).WithProperties(auditProperties().WithFramework(true).Build())
				b.AddResource(msix.NewResource().WithDXFeatureLevel("dx9").Build())
			}
			data := auditManifest(t, b)
			es := auditElements(t, data, "Resource")
			for _, e := range es {
				for _, a := range e.Attr {
					if a.Name.Local == "Scale" || a.Name.Local == "DXFeatureLevel" {
						assert.Equal(t, uap, a.Name.Space)
					}
				}
			}
		})
	}
}

// #15: invalid UTF-8 and XML controls must fail without replacing identity text.
func TestAuditXMLCharacters(t *testing.T) {
	for _, value := range []string{"x\x00y", "x\x01y", "x\x1fy", "x\ufffey", string([]byte{'x', 0xff})} {
		for _, field := range []string{"description", "publisher", "protocol"} {
			t.Run(field+value, func(t *testing.T) {
				b := auditBase()
				switch field {
				case "description":
					b.WithProperties(auditProperties().WithDescription(value).Build())
				case "publisher":
					b.WithIdentity(auditIdentity().WithPublisher("CN=" + value).Build())
				case "protocol":
					b.AddApplication(auditApp("App", msix.NewProtocol().WithName("audit").WithDisplayName(value).Build()))
				}
				data, err := auditBuild(b)
				require.Error(t, err)
				assert.Empty(t, data)
			})
		}
	}
	data := auditManifest(t, auditBase().WithProperties(auditProperties().WithDescription("日本語 & <text> 😀").Build()))
	assert.NotEmpty(t, auditElements(t, data, "Description"))
}

// #16: one source snapshot must drive metadata, signed digests, and final ZIP.
func TestAuditChangingSources(t *testing.T) {
	for _, signed := range []bool{false, true} {
		for _, contents := range [][2]string{{"", "now nonempty"}, {"first", "other"}, {"long source", "x"}, {"x", "expanded source"}, {"", ""}} {
			t.Run(strings.Join(contents[:], "->")+map[bool]string{true: " signed", false: " unsigned"}[signed], func(t *testing.T) {
				opens := 0
				b := auditBase().AddFileSource("changing.bin", func() (io.ReadCloser, error) {
					value := contents[0]
					if opens > 0 {
						value = contents[1]
					}
					opens++
					return io.NopCloser(strings.NewReader(value)), nil
				})
				if signed {
					cert, key := selfSignedCert(t)
					b.WithSigning(msix.NewSigning().WithCertificate(cert).WithPrivateKey(key).Build())
				}
				data, err := auditBuild(b)
				require.NoError(t, err)
				zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
				require.NoError(t, err)
				for _, f := range zr.File {
					r, err := f.Open()
					require.NoError(t, err)
					_, err = io.Copy(io.Discard, r)
					require.NoError(t, err)
					require.NoError(t, r.Close())
				}
				assert.Equal(t, contents[0], string(unzip(t, data)["changing.bin"]))
				assert.Equal(t, 1, opens)
			})
		}
	}
}

func TestAuditServiceExecutableContext(t *testing.T) {
	for _, ext := range []msix.ApplicationExtension{msix.NewService().WithName("AuditService").WithStartupType("manual").WithStartAccount("localSystem").Build(), msix.NewServiceDesktop7().WithName("AuditService").WithStartupType("manual").WithStartAccount("localSystem").Build()} {
		data := auditManifest(t, auditBase().AddApplication(auditApp("Service", ext)))
		var found bool
		for _, e := range auditElements(t, data, "Extension") {
			attrs := map[string]string{}
			for _, a := range e.Attr {
				attrs[a.Name.Local] = a.Value
			}
			if attrs["Category"] == "windows.service" {
				found = true
				assert.Equal(t, "app.exe", attrs["Executable"])
				assert.Equal(t, "Windows.FullTrustApplication", attrs["EntryPoint"])
			}
		}
		assert.True(t, found)
	}
}
