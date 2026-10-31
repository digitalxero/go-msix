//go:build windows

package msix_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"image"
	"image/png"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	msix "go.digitalxero.dev/go-msix"
)

// This oracle goes through the public signed builder; no formatter result is
// supplied by the implementation under test.
func TestAuditPublisherWindows(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, tc := range auditSubjects() {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := asn1.Marshal(tc.rdns)
			require.NoError(t, err)
			publisher := nativePublisher(t, raw)
			assert.Equal(t, tc.publisher, publisher)
			cert := auditCert(t, key, raw)
			_, err = auditBuild(auditBase().WithIdentity(auditIdentity().WithPublisher(publisher).Build()).WithSigning(msix.NewSigning().WithCertificate(cert).WithPrivateKey(key).Build()))
			require.NoError(t, err)
		})
	}
}
func nativePublisher(t *testing.T, raw []byte) string {
	t.Helper()
	proc := syscall.NewLazyDLL("crypt32.dll").NewProc("CertNameToStrW")
	blob := struct {
		size uint32
		data *byte
	}{uint32(len(raw)), &raw[0]}
	const flags = 3 | 0x02000000
	n, _, err := proc.Call(1, uintptr(unsafe.Pointer(&blob)), flags, 0, 0)
	require.NotZero(t, n, "CertNameToStrW: %v", err)
	buf := make([]uint16, n)
	written, _, err := proc.Call(1, uintptr(unsafe.Pointer(&blob)), flags, uintptr(unsafe.Pointer(&buf[0])), n)
	require.Equal(t, n, written, "CertNameToStrW: %v", err)
	return string(utf16.Decode(buf[:n-1]))
}
func nativeTool(t *testing.T, name string) string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(os.Getenv("ProgramFiles(x86)"), "Windows Kits", "10", "bin", "*", "x64", name+".exe"))
	require.NoError(t, err)
	if len(paths) == 0 {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("Windows SDK %s is required", name)
		}
		t.Skip("Windows SDK " + name + " unavailable")
	}
	sort.Strings(paths)
	t.Logf("SDK tool: %s", paths[len(paths)-1])
	return paths[len(paths)-1]
}
func nativePNG(t *testing.T, size int) []byte {
	t.Helper()
	var out bytes.Buffer
	require.NoError(t, png.Encode(&out, image.NewNRGBA(image.Rect(0, 0, size, size))))
	return out.Bytes()
}
func nativeBase(t *testing.T, name string) msix.Builder {
	t.Helper()
	return msix.NewBuilder().WithIdentity(auditIdentity().WithName(name).Build()).WithProperties(auditProperties().Build()).WithDependencies(msix.NewDependencies().AddTargetDeviceFamily("Windows.Desktop", "10.0.19645.0", "10.0.26100.0").Build()).AddFileFromBytes("logo.png", nativePNG(t, 50)).AddFileFromBytes("large.png", nativePNG(t, 150)).AddFileFromBytes("small.png", nativePNG(t, 44))
}
func nativeVisual() msix.VisualElements {
	return msix.NewVisualElements().WithDisplayName("Audit").WithDescription("Audit native validation").WithBackgroundColor("transparent").WithSquare150x150Logo("large.png").WithSquare44x44Logo("small.png").Build()
}
func nativeApp(id string, exts ...msix.ApplicationExtension) msix.Application {
	a := msix.NewApplication().WithID(id).WithExecutable("app.exe").WithEntryPoint("Windows.FullTrustApplication").WithVisualElements(nativeVisual())
	for _, e := range exts {
		a.AddExtension(e)
	}
	return a.Build()
}

// SDK controls mutate only the extracted manifest, after valid public Build, so
// the SDK negative controls cannot pass merely because our validator rejected it.
func TestAuditSDKWindows(t *testing.T) {
	tool := nativeTool(t, "makeappx")
	cases := []struct {
		name                     string
		b                        func() msix.Builder
		negativeOld, negativeNew string
	}{
		{"protocol", func() msix.Builder {
			return nativeBase(t, "Audit.SDK").WithCapabilities(msix.NewCapabilities().AddRestricted("runFullTrust").Build()).AddResource(msix.NewResource().WithLanguage("en-us").Build()).AddFileFromBytes("app.exe", []byte("MZ")).AddApplication(nativeApp("App", msix.NewProtocol().WithName("go-msix-audit").WithDisplayName("Audit & Protocol").WithLogo("logo.png").Build()))
		}, `<uap:Protocol Name="go-msix-audit">`, `<uap:Protocol Name="go-msix-audit" DesktopAppInfo="bad">`},
		{"shortcut", func() msix.Builder {
			return nativeBase(t, "Audit.SDK").WithCapabilities(msix.NewCapabilities().AddRestricted("runFullTrust").Build()).AddResource(msix.NewResource().WithLanguage("en-us").Build()).AddFileFromBytes("app.exe", []byte("MZ")).AddApplication(nativeApp("App", msix.NewShortcut().WithFile(`$(Desktop)\GoMsixAudit.lnk`).WithIcon("app.exe").WithArguments(`--audit "A & B"`).WithDisplayName("Audit shortcut").Build()))
		}, `desktop10:DisplayName="Audit shortcut"`, `DisplayName="Audit shortcut"`},
		{"allow false", func() msix.Builder {
			return nativeBase(t, "Audit.Assets").WithProperties(auditProperties().WithAllowExecution(false).WithFramework(true).Build())
		}, `uap6:AllowExecution`, `AllowExecution`},
		{"allow true", func() msix.Builder {
			return nativeBase(t, "Audit.Assets").WithProperties(auditProperties().WithAllowExecution(true).WithFramework(true).Build())
		}, `uap6:AllowExecution`, `AllowExecution`},
		{"allow unset", func() msix.Builder {
			return nativeBase(t, "Audit.Assets").WithProperties(auditProperties().WithFramework(true).Build())
		}, `Version="1.2.3.0"`, `Version="1.x.3.0"`},
		{"resource scale", func() msix.Builder {
			return nativeBase(t, "Audit.Resources").WithIdentity(auditIdentity().WithName("Audit.Resources").WithResourceID("scale100").WithProcessorArchitecture("").Build()).WithProperties(auditProperties().WithResourcePackage(true).Build()).AddResource(msix.NewResource().WithScale("100").Build())
		}, `uap:Scale="100"`, `uap:Scale="invalid"`},
		{"resource dx", func() msix.Builder {
			return nativeBase(t, "Audit.Resources").WithIdentity(auditIdentity().WithName("Audit.Resources").WithResourceID("dx9").WithProcessorArchitecture("").Build()).WithProperties(auditProperties().WithResourcePackage(true).Build()).AddResource(msix.NewResource().WithDXFeatureLevel("dx9").Build())
		}, `uap:DXFeatureLevel="dx9"`, `uap:DXFeatureLevel="invalid"`},
		{"resource both", func() msix.Builder {
			return nativeBase(t, "Audit.Resources").WithIdentity(auditIdentity().WithName("Audit.Resources").WithResourceID("both").WithProcessorArchitecture("").Build()).WithProperties(auditProperties().WithResourcePackage(true).Build()).AddResource(msix.NewResource().WithScale("100").WithDXFeatureLevel("dx9").Build())
		}, `uap:Scale="100"`, `uap:Scale="invalid"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := auditBuild(tc.b())
			require.NoError(t, err)
			parts := unzip(t, data)
			for _, valid := range []bool{true, false} {
				t.Run(fmt.Sprint(valid), func(t *testing.T) {
					dir := t.TempDir()
					for name, body := range parts {
						if name == "AppxBlockMap.xml" || name == "[Content_Types].xml" {
							continue
						}
						if name == "AppxManifest.xml" && !valid {
							require.Contains(t, string(body), tc.negativeOld)
							body = []byte(strings.ReplaceAll(string(body), tc.negativeOld, tc.negativeNew))
						}
						p := filepath.Join(dir, filepath.FromSlash(name))
						require.NoError(t, os.MkdirAll(filepath.Dir(p), 0755))
						require.NoError(t, os.WriteFile(p, body, 0600))
					}
					cmd := exec.CommandContext(context.Background(), tool, "pack", "/d", dir, "/p", filepath.Join(t.TempDir(), "validated.msix"), "/o")
					out, err := cmd.CombinedOutput()
					t.Logf("MakeAppx %s valid=%t: %s", tc.name, valid, out)
					if valid {
						require.NoError(t, err)
					} else {
						require.Error(t, err, "SDK must reject the negative manifest")
					}
				})
			}
		})
	}
}

func nativePowerShell(t *testing.T, script string, args ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "check.ps1")
	require.NoError(t, os.WriteFile(path, []byte(strings.Replace(strings.TrimSpace(script), "\n", "\n$ErrorActionPreference='Stop'\n", 1)), 0600))
	cmd := exec.Command("powershell.exe", append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path}, args...)...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	t.Logf("%s", out)
	return string(out)
}

// Native deployment is opt-in locally and mandatory in its dedicated CI job.
// SDK/XML success is deliberately separate from trust, registration, and launch.
func TestAuditDeploymentWindows(t *testing.T) {
	if os.Getenv("MSIX_WINDOWS_AUDIT") != "1" {
		t.Skip("set MSIX_WINDOWS_AUDIT=1 for native deployment/shortcut/service validation")
	}
	makeappx := nativeTool(t, "makeappx")
	signtool := nativeTool(t, "signtool")
	dir := t.TempDir()
	exe := filepath.Join(dir, "app.exe")
	cmd := exec.Command("go", "build", "-o", exe, "./internal/auditfixture")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	payload, err := os.ReadFile(exe)
	require.NoError(t, err)
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rootT := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "go-msix audit root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootT, rootT, rootKey.Public(), rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	leafT := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "Test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafT, root, leafKey.Public(), rootKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.cer"), rootDER, 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "leaf.cer"), leafDER, 0600))
	// Native commands own only these unique names and throwaway certificates.
	id := fmt.Sprintf("GoMsix.Audit%d", time.Now().UnixNano())
	protocol := strings.ToLower(strings.ReplaceAll(id, ".", "-"))
	shortcutName := id + ".lnk"
	serviceName := strings.ReplaceAll(id, ".", "")
	result := filepath.Join(dir, "shortcut-args.txt")
	shortcut := msix.NewShortcut().WithFile(`$(Desktop)\` + shortcutName).WithIcon("app.exe").WithArguments(`--audit-output "` + result + `" "A & B"`).WithDisplayName("go-msix Audit shortcut").Build()
	signing := msix.NewSigning().WithCertificate(leaf).WithPrivateKey(leafKey).WithCertChain(root).Build()
	b := nativeBase(t, id).WithSigning(signing).WithCapabilities(msix.NewCapabilities().AddRestricted("runFullTrust").AddRestricted("localSystemServices").Build()).AddResource(msix.NewResource().WithLanguage("en-us").Build()).AddFileFromBytes("app.exe", payload).AddApplication(nativeApp("App", shortcut, msix.NewProtocol().WithName(protocol).WithDisplayName("Audit protocol").Build())).AddApplication(nativeApp("Service", msix.NewService().WithName(serviceName).WithStartupType("manual").WithStartAccount("localSystem").Build()))
	data, err := auditBuild(b)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "signed.msix"), data, 0600))
	if artifacts := os.Getenv("MSIX_AUDIT_ARTIFACTS"); artifacts != "" {
		require.NoError(t, os.MkdirAll(artifacts, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(artifacts, "audit-signed.msix"), data, 0600))
	}
	// The service dispatcher uses the SCM-supplied name, so no fixed global service
	// or package identity can collide with another runner/job.
	asset := nativeBase(t, id+"Assets").WithSigning(signing).WithProperties(auditProperties().WithAllowExecution(false).WithFramework(true).Build()).AddFileFromBytes("app.exe", payload)
	data, err = auditBuild(asset)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "assets.msix"), data, 0600))
	nativePowerShell(t, `
param($dir,$id,$shortcutName,$serviceName,$result,$signtool,$protocol,$makeappx)
$root=$null; $leaf=$null
try {
 $root=Import-Certificate -FilePath "$dir\root.cer" -CertStoreLocation Cert:\LocalMachine\Root
 $leaf=Import-Certificate -FilePath "$dir\leaf.cer" -CertStoreLocation Cert:\LocalMachine\TrustedPeople
 & $makeappx unpack /p "$dir\signed.msix" /d "$dir\unpacked" /o /nv
 if ($LASTEXITCODE -ne 0) {throw 'native unpack failed'}
 & $makeappx pack /d "$dir\unpacked" /p "$dir\sdk-validated.msix" /o
 if ($LASTEXITCODE -ne 0) {throw 'native SDK deployment fixture validation failed'}
 & $signtool verify /debug /pa "$dir\signed.msix"
 $signtoolExit=$LASTEXITCODE
 $sig=Get-AuthenticodeSignature "$dir\signed.msix"
 if ($sig.Status -ne 'Valid') {throw "signature status: $($sig.Status) $($sig.StatusMessage)"}
 if ($signtoolExit -ne 0) {throw 'signtool verification failed'}
 Add-AppxPackage "$dir\signed.msix"
 $pkg=Get-AppxPackage -Name $id
 if (-not $pkg) {throw 'package missing after deployment'}
 $path=Join-Path ([Environment]::GetFolderPath('Desktop')) $shortcutName
 if (-not (Test-Path $path)) {throw "shortcut missing: $path"}
 $shell=New-Object -ComObject WScript.Shell
 $link=$shell.CreateShortcut($path)
 if ($link.Arguments -notmatch 'A & B') {throw "shortcut lost arguments: $($link.Arguments)"}
 Start-Process $path
 $deadline=(Get-Date).AddSeconds(30)
 while (-not (Test-Path $result) -and (Get-Date) -lt $deadline) {Start-Sleep -Milliseconds 200}
 if (-not (Test-Path $result)) {throw 'shortcut launch produced no receipt'}
 if ((Get-Content -Raw $result) -ne 'A & B') {throw 'actual shortcut launch arguments differ'}
 $protocolResult=Join-Path $dir 'protocol.txt'
 Start-Process ($protocol+':?out='+[uri]::EscapeDataString($protocolResult))
 $deadline=(Get-Date).AddSeconds(30)
 while (-not (Test-Path $protocolResult) -and (Get-Date) -lt $deadline) {Start-Sleep -Milliseconds 200}
 if (-not (Test-Path $protocolResult)) {throw 'protocol activation produced no receipt'}
 if ((Get-Content -Raw $protocolResult) -ne 'protocol') {throw 'protocol activation receipt differs'}
 $svc=Get-Service -Name $serviceName -ErrorAction Stop
 Start-Service $serviceName
 (Get-Service $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
 Stop-Service $serviceName
 (Get-Service $serviceName).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
 Remove-AppxPackage $pkg.PackageFullName
 if (Test-Path $path) {throw 'shortcut survived package removal'}
 if (Get-Service $serviceName -ErrorAction SilentlyContinue) {throw 'service survived package removal'}
 Add-AppxPackage "$dir\assets.msix"
 $assets=Get-AppxPackage -Name ($id+'Assets')
 if (-not $assets) {throw 'asset package missing'}
 $blocked=$false
 try {Start-Process -FilePath (Join-Path $assets.InstallLocation 'app.exe') -ArgumentList @('--audit-output',"$dir\blocked.txt",'unexpected') -Wait -ErrorAction Stop} catch {$blocked=$true}
 if (Test-Path "$dir\blocked.txt") {throw 'AllowExecution=false payload executed'}
 if (-not $blocked) {throw 'non-executable asset launch was not explicitly rejected'}
 Write-Host 'PASS: signature, deployment, shortcut arguments/launch, service start/stop/removal, non-executable assets'
} finally {
 Get-AppxPackage -Name $id | Remove-AppxPackage
 Get-AppxPackage -Name ($id+'Assets') | Remove-AppxPackage
 if ($leaf) {Remove-Item ("Cert:\LocalMachine\TrustedPeople\"+$leaf.Thumbprint)}
 if ($root) {Remove-Item ("Cert:\LocalMachine\Root\"+$root.Thumbprint)}
}
`, dir, id, shortcutName, serviceName, result, signtool, protocol, makeappx)
}
