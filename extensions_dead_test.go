package msix_test

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	msix "go.digitalxero.dev/go-msix"
)

// baseExtBuilder returns a minimal valid builder (no application) for extension tests.
func baseExtBuilder() msix.Builder {
	return msix.NewBuilder().
		WithIdentity(msix.NewIdentity().
			WithName("Ext.Test").WithVersion("1.0.0.0").WithPublisher("CN=Test").Build()).
		WithProperties(msix.NewProperties().
			WithDisplayName("Ext Test").WithPublisherDisplayName("Test").Build()).
		WithDependencies(msix.NewDependencies().
			AddTargetDeviceFamily("Windows.Desktop", "10.0.17763.0", "10.0.22621.0").Build())
}

func extManifestXML(t *testing.T, b msix.Builder) string {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, b.Build(context.Background(), &buf))
	r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)
	for _, f := range r.File {
		if f.Name == "AppxManifest.xml" {
			rc, err := f.Open()
			require.NoError(t, err)
			data, err := io.ReadAll(rc)
			rc.Close()
			require.NoError(t, err)
			return string(data)
		}
	}
	t.Fatal("AppxManifest.xml not found")
	return ""
}

var ignorableRe = regexp.MustCompile(`IgnorableNamespaces="([^"]*)"`)

// assertNamespace checks that prefix is declared (xmlns:prefix=) and listed in
// IgnorableNamespaces. An empty prefix (foundation default namespace) is skipped.
func assertNamespace(t *testing.T, xml, prefix string) {
	t.Helper()
	if prefix == "" {
		return
	}
	require.Contains(t, xml, "xmlns:"+prefix+"=", "missing xmlns declaration for %q", prefix)
	m := ignorableRe.FindStringSubmatch(xml)
	require.Len(t, m, 2, "IgnorableNamespaces attribute not found")
	require.Contains(t, strings.Fields(m[1]), prefix, "%q not in IgnorableNamespaces", prefix)
}

func TestDeadApplicationExtensions(t *testing.T) {
	cases := []struct {
		name     string
		prefix   string
		ext      msix.ApplicationExtension
		contains []string
	}{
		{"FileOpenPicker", "uap", msix.NewFileOpenPicker().AddSupportedFileType(msix.NewFileType().WithExtension(".a").Build()).Build(),
			[]string{`Category="windows.fileOpenPicker"`, `<uap:FileOpenPicker>`, `<uap:FileType>.a</uap:FileType>`}},
		{"FileSavePicker", "uap", msix.NewFileSavePicker().AddSupportedFileType(msix.NewFileType().WithExtension(".b").Build()).Build(),
			[]string{`Category="windows.fileSavePicker"`, `<uap:FileSavePicker>`, `<uap:FileType>.b</uap:FileType>`}},
		{"AutoPlayContent", "uap", msix.NewAutoPlayContent().AddLaunchAction("v", "disp", "evt").Build(),
			[]string{`Category="windows.autoPlayContent"`, `<uap:AutoPlayContent>`, `<uap:LaunchAction Verb="v" ActionDisplayName="disp" ContentEvent="evt" />`}},
		{"AutoPlayDevice", "uap", msix.NewAutoPlayDevice().AddLaunchAction("v", "disp", "devt").Build(),
			[]string{`Category="windows.autoPlayDevice"`, `<uap:AutoPlayDevice>`, `DeviceEvent="devt"`}},
		{"DialProtocol", "uap", msix.NewDialProtocol().WithName("d").Build(),
			[]string{`Category="windows.dialProtocol"`, `<uap:DialProtocol Name="d" />`}},
		{"VoipCall", "uap", msix.NewVoipCall().Build(),
			[]string{`Category="windows.voipCall"`, `<uap:VoipCall />`}},
		{"AppointmentDataProvider", "uap3", msix.NewAppointmentDataProvider().WithServerName("s").Build(),
			[]string{`<uap3:AppointmentDataProvider ServerName="s" />`}},
		{"EmailDataProvider", "uap3", msix.NewEmailDataProvider().WithServerName("s").Build(),
			[]string{`<uap3:EmailDataProvider ServerName="s" />`}},
		{"ContactDataProvider", "uap3", msix.NewContactDataProvider().WithServerName("s").Build(),
			[]string{`<uap3:ContactDataProvider ServerName="s" />`}},
		{"SharedFonts", "uap4", msix.NewSharedFonts().AddFont("f.ttf").Build(),
			[]string{`Category="windows.sharedFonts"`, `<uap4:SharedFonts>`, `<uap4:Font File="f.ttf" />`}},
		{"ContactPanel", "uap4", msix.NewContactPanel().WithSupportsUnknownContacts(true).Build(),
			[]string{`<uap4:ContactPanel SupportsUnknownContacts="true" />`}},
		{"MediaCodec", "uap4", msix.NewMediaCodec().WithDisplayName("m").AddMediaType("st").Build(),
			[]string{`<uap4:MediaCodec DisplayName="m">`, `<uap4:MediaType SubType="st" />`}},
		{"LoopbackAccessRules", "uap4", msix.NewLoopbackAccessRules().AddRule("out").Build(),
			[]string{`<uap4:LoopbackAccessRules>`, `<uap4:Rule Direction="out" />`}},
		{"DevicePortalProvider", "uap4", msix.NewDevicePortalProvider().WithDisplayName("d").WithAppServiceName("svc").Build(),
			[]string{`<uap4:DevicePortalProvider DisplayName="d" AppServiceName="svc"`}},
		{"UserDataTaskDataProvider", "uap4", msix.NewUserDataTaskDataProvider().WithServerName("s").Build(),
			[]string{`<uap4:UserDataTaskDataProvider ServerName="s" />`}},
		{"UserActivity", "uap5", msix.NewUserActivity().WithActivitySourceHost("h").Build(),
			[]string{`<uap5:UserActivity ActivitySourceHost="h" />`}},
		{"MediaSource", "uap5", msix.NewMediaSource().WithDisplayName("m").AddMediaType("st").Build(),
			[]string{`<uap5:MediaSource DisplayName="m">`, `<uap5:MediaType SubType="st" />`}},
		{"VideoRendererEffect", "uap5", msix.NewVideoRendererEffect().WithDisplayName("v").WithActivatableClassID("c").Build(),
			[]string{`<uap5:VideoRendererEffect DisplayName="v" ActivatableClassId="c" />`}},
		{"BarcodeScannerProvider", "uap6", msix.NewBarcodeScannerProvider().Build(),
			[]string{`<uap6:BarcodeScannerProvider />`}},
		{"SharedFontsUap7", "uap7", msix.NewSharedFontsUap7().AddFont("f.otf").Build(),
			[]string{`<uap7:SharedFonts>`, `<uap7:Font File="f.otf" />`}},
		{"EnterpriseDataProtection", "uap7", msix.NewEnterpriseDataProtection().AddProtectionDomain("d").Build(),
			[]string{`<uap7:EnterpriseDataProtection>`, `<uap7:ProtectionDomain Name="d" />`}},
		{"ProtocolUap10", "uap10", msix.NewProtocolUap10().WithName("p").WithParameters("x").Build(),
			[]string{`<uap10:Protocol Name="p" Parameters="x" />`}},
		{"DesktopStartupTask", "desktop", msix.NewDesktopStartupTask().WithTaskID("t").WithEnabled(true).Build(),
			[]string{`<desktop:StartupTask TaskId="t" Enabled="true" />`}},
		{"SearchProtocolHandler", "desktop", msix.NewSearchProtocolHandler().WithDisplayName("d").Build(),
			[]string{`<desktop:SearchProtocolHandler DisplayName="d" />`}},
		{"AppPrinter", "desktop2", msix.NewAppPrinter().WithDisplayName("d").WithParameters("p").Build(),
			[]string{`<desktop2:AppPrinter DisplayName="d" Parameters="p" />`}},
		{"SearchFilterHandler", "desktop2", msix.NewSearchFilterHandler().WithCLSID("c").WithDisplayName("d").Build(),
			[]string{`<desktop2:SearchFilterHandler Clsid="c" DisplayName="d" />`}},
		{"SearchPropertyHandler", "desktop2", msix.NewSearchPropertyHandler().WithCLSID("c").Build(),
			[]string{`<desktop2:SearchPropertyHandler Clsid="c"`}},
		{"FirewallRules", "desktop2", msix.NewFirewallRules().AddRule(msix.NewFirewallRule().WithDirection("in").WithProtocol("TCP").WithProfile("all").Build()).Build(),
			[]string{`<desktop2:FirewallRules>`, `<desktop2:Rule Direction="in" IPProtocol="TCP" Profile="all" />`}},
		{"DesktopEventLogging", "desktop2", msix.NewDesktopEventLogging().WithProviderGUID("g").AddChannel("ch").Build(),
			[]string{`<desktop2:DesktopEventLogging ProviderGuid="g">`, `<desktop2:Channel Name="ch" />`}},
		{"AutoPlayHandler", "desktop3", msix.NewAutoPlayHandler().AddInvokeAction(msix.NewInvokeAction().WithActionDisplayName("a").WithProviderCLSID("c").Build()).Build(),
			[]string{`<desktop3:AutoPlayHandler>`, `<desktop3:InvokeAction ActionDisplayName="a" ProviderClsid="c" />`}},
		{"CloudFiles", "desktop3", msix.NewCloudFiles().WithIconResource("i").WithCustomStateHandler("c").Build(),
			[]string{`<desktop3:CloudFiles IconResource="i">`, `<desktop3:CustomStateHandler Clsid="c" />`}},
		{"ApprovedShellExtension", "desktop7", msix.NewApprovedShellExtension().WithCLSID("c").Build(),
			[]string{`<desktop7:ApprovedShellExtension Clsid="c" />`}},
		{"ControlPanelItem", "desktop7", msix.NewControlPanelItem().WithSystemApplicationName("n").Build(),
			[]string{`<desktop7:ControlPanelItem SystemApplicationName="n" />`}},
		{"ServiceDesktop7", "desktop7", msix.NewServiceDesktop7().WithName("n").WithArguments("a").Build(),
			[]string{`<desktop7:Service Name="n"`, `Arguments="a"`}},
		{"ApplicationRegistration", "desktop7", msix.NewApplicationRegistration().Build(),
			[]string{`<desktop7:ApplicationRegistration />`}},
		{"DesktopAppMigration", "desktop7", msix.NewDesktopAppMigration().AddDesktopApp("aum", "path").Build(),
			[]string{`<desktop7:DesktopAppMigration>`, `<desktop7:DesktopApp AumId="aum" ShortcutPath="path" />`}},
		{"SystemFileAssociation", "desktop7", msix.NewSystemFileAssociation().WithExtension(".x").WithFullDetails("fd").Build(),
			[]string{`<desktop7:SystemFileAssociation Extension=".x" FullDetails="fd" />`}},
		{"FileExplorerClassicContextMenuHandler", "desktop9", msix.NewFileExplorerClassicContextMenuHandler().WithCLSID("c").Build(),
			[]string{`<desktop9:FileExplorerClassicContextMenuHandler Clsid="c" />`}},
		{"FileExplorerClassicDragDropContextMenuHandler", "desktop9", msix.NewFileExplorerClassicDragDropContextMenuHandler().WithCLSID("c").Build(),
			[]string{`<desktop9:FileExplorerClassicDragDropContextMenuHandler Clsid="c" />`}},
		{"DesktopAppMigrationRescap", "rescap3", msix.NewDesktopAppMigrationRescap().AddDesktopApp("aum", "path").Build(),
			[]string{`<rescap3:DesktopAppMigration>`, `<rescap3:DesktopApp AumId="aum" ShortcutPath="path" />`}},
		{"MobileMultiScreenProperties", "mobile", msix.NewMobileMultiScreenProperties().WithRestoreFromOtherDisplayOnReactivation(true).Build(),
			[]string{`<mobile:MobileMultiScreenProperties RestoreFromOtherDisplayOnReactivation="true" />`}},
		{"CommunicationBlockingProvider", "mobile", msix.NewCommunicationBlockingProvider().Build(),
			[]string{`<mobile:CommunicationBlockingProvider />`}},
		{"PhoneCallOriginProvider", "mobile", msix.NewPhoneCallOriginProvider().Build(),
			[]string{`<mobile:PhoneCallOriginProvider />`}},
		{"PrintSupportSettingsUI", "printsupport", msix.NewPrintSupportSettingsUI().Build(),
			[]string{`<printsupport:PrintSupportSettingsUI />`}},
		{"PrintSupportExtension", "printsupport", msix.NewPrintSupportExtension().Build(),
			[]string{`<printsupport:PrintSupportExtension />`}},
		{"PrintSupportJobUI", "printsupport", msix.NewPrintSupportJobUI().Build(),
			[]string{`<printsupport:PrintSupportJobUI />`}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := baseExtBuilder().AddApplication(
				msix.NewApplication().WithID("App").WithExecutable("App.exe").
					WithVisualElements(msix.NewVisualElements().
						WithDisplayName("App").WithBackgroundColor("#000").
						WithSquare150x150Logo("a.png").WithSquare44x44Logo("b.png").Build()).
					AddExtension(c.ext).Build())
			xml := extManifestXML(t, b)
			assertNamespace(t, xml, c.prefix)
			for _, want := range c.contains {
				require.Contains(t, xml, want, "manifest missing %q\n%s", want, xml)
			}
		})
	}
}

func TestDeadPackageExtensions(t *testing.T) {
	cases := []struct {
		name     string
		prefix   string
		ext      msix.PackageExtension
		contains []string
	}{
		{"PkgInProcessServer", "", msix.NewPkgInProcessServer().WithPath("p.dll").AddActivatableClass("C", "both").Build(),
			[]string{`Category="windows.activatableClass.inProcessServer"`, `<InProcessServer>`, `<Path>p.dll</Path>`, `<ActivatableClass ActivatableClassId="C" ThreadingModel="both" />`}},
		{"PkgOutOfProcessServer", "", msix.NewPkgOutOfProcessServer().WithServerName("s").WithExecutable("e.exe").AddActivatableClass("C", "STA").Build(),
			[]string{`Category="windows.activatableClass.outOfProcessServer"`, `<OutOfProcessServer ServerName="s"`, `<Path>e.exe</Path>`, `<ActivatableClass ActivatableClassId="C" ThreadingModel="STA" />`}},
		{"ProxyStubPkg", "", msix.NewProxyStubPkg().WithPath("p.dll").WithCLSID("c").Build(),
			[]string{`Category="windows.activatableClass.proxyStub"`, `<ProxyStub ClassId="c">`, `<Path>p.dll</Path>`}},
		{"PublisherCacheFolders", "", msix.NewPublisherCacheFolders().AddFolder("f").Build(),
			[]string{`Category="windows.publisherCacheFolders"`, `<PublisherCacheFolders>`, `<Folder Name="f" />`}},
		{"LoaderSearchPathOverride", "uap6", msix.NewLoaderSearchPathOverride().AddEntry("dir").Build(),
			[]string{`<uap6:LoaderSearchPathOverride>`, `<uap6:LoaderSearchPathEntry FolderPath="dir" />`}},
		{"ComInterfacePkg", "com", msix.NewComInterfacePkg().AddInterface(msix.NewInterfaceEntry().WithID("iid").Build()).Build(),
			[]string{`<com:ComInterface>`, `<com:Interface Id="iid" />`}},
		{"DesktopAppMigrationPkg", "rescap3", msix.NewDesktopAppMigrationPkg().AddDesktopApp("aum", "path").Build(),
			[]string{`<rescap3:DesktopAppMigration>`, `<rescap3:DesktopApp AumId="aum" ShortcutPath="path" />`}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := baseExtBuilder().AddApplication(
				msix.NewApplication().WithID("App").WithExecutable("App.exe").
					WithVisualElements(msix.NewVisualElements().
						WithDisplayName("App").WithBackgroundColor("#000").
						WithSquare150x150Logo("a.png").WithSquare44x44Logo("b.png").Build()).
					Build()).
				AddPackageExtension(c.ext)
			xml := extManifestXML(t, b)
			assertNamespace(t, xml, c.prefix)
			for _, want := range c.contains {
				require.Contains(t, xml, want, "manifest missing %q\n%s", want, xml)
			}
		})
	}
}
