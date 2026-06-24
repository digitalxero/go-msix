package msix

import (
	"bytes"
	"sort"
	"strings"
	"text/template"
)

// nsEntry is a namespace prefix/URI pair, used for deterministic ordering.
type nsEntry struct {
	Prefix string
	URI    string
}

// Namespace URIs.
const (
	nsFoundation = "http://schemas.microsoft.com/appx/manifest/foundation/windows10"
	nsUAP        = "http://schemas.microsoft.com/appx/manifest/uap/windows10"
	nsUAP2       = "http://schemas.microsoft.com/appx/manifest/uap/windows10/2"
	nsUAP3       = "http://schemas.microsoft.com/appx/manifest/uap/windows10/3"
	nsUAP4       = "http://schemas.microsoft.com/appx/manifest/uap/windows10/4"
	nsUAP5       = "http://schemas.microsoft.com/appx/manifest/uap/windows10/5"
	nsUAP6       = "http://schemas.microsoft.com/appx/manifest/uap/windows10/6"
	nsUAP7       = "http://schemas.microsoft.com/appx/manifest/uap/windows10/7"
	nsUAP10      = "http://schemas.microsoft.com/appx/manifest/uap/windows10/10"
	nsDesktop    = "http://schemas.microsoft.com/appx/manifest/desktop/windows10"
	nsDesktop2   = "http://schemas.microsoft.com/appx/manifest/desktop/windows10/2"
	nsDesktop3   = "http://schemas.microsoft.com/appx/manifest/desktop/windows10/3"
	nsDesktop4   = "http://schemas.microsoft.com/appx/manifest/desktop/windows10/4"
	nsDesktop6   = "http://schemas.microsoft.com/appx/manifest/desktop/windows10/6"
	nsDesktop7   = "http://schemas.microsoft.com/appx/manifest/desktop/windows10/7"
	nsDesktop9   = "http://schemas.microsoft.com/appx/manifest/desktop/windows10/9"
	nsCom        = "http://schemas.microsoft.com/appx/manifest/com/windows10"
	nsCom2       = "http://schemas.microsoft.com/appx/manifest/com/windows10/2"
	nsCom4       = "http://schemas.microsoft.com/appx/manifest/com/windows10/4"
	nsRescap     = "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
	nsRescap3    = "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities/3"
	nsRescap4    = "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities/4"
	nsRescap6    = "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities/6"
	nsMobile     = "http://schemas.microsoft.com/appx/manifest/mobile/windows10"
	// TODO(verify-xsd): confirm the printSupport namespace URI/prefix.
	nsPrintSupport = "http://schemas.microsoft.com/appx/manifest/printsupport/windows10"
)

// manifestNamespaces determines which namespace prefixes are needed for the manifest.
// Returns a sorted slice of nsEntry for deterministic output.
func manifestNamespaces(m *manifestData) []nsEntry {
	ns := make(map[string]string)

	// Always have foundation as default namespace (handled separately).

	// Check if uap is needed (VisualElements, capabilities, etc.).
	if len(m.Applications) > 0 {
		ns["uap"] = nsUAP
	}
	if len(m.Capabilities.UAP) > 0 {
		ns["uap"] = nsUAP
	}

	// Check rescap.
	if len(m.Capabilities.Restricted) > 0 {
		ns["rescap"] = nsRescap
	}

	// Check uap4 (custom capabilities).
	if len(m.Capabilities.Custom) > 0 {
		ns["uap4"] = nsUAP4
	}

	// Check rescap6 (ModificationPackage).
	if m.Properties.ModificationPackage {
		ns["rescap6"] = nsRescap6
	}

	// Scan application extensions.
	for _, app := range m.Applications {
		for _, ext := range app.Extensions {
			addExtensionNamespaces(ext, ns)
		}
	}

	// Scan package extensions.
	for _, ext := range m.Extensions {
		addPackageExtensionNamespaces(ext, ns)
	}

	// Convert to sorted slice for deterministic output.
	prefixes := make([]string, 0, len(ns))
	for prefix := range ns {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)

	entries := make([]nsEntry, len(prefixes))
	for i, prefix := range prefixes {
		entries[i] = nsEntry{Prefix: prefix, URI: ns[prefix]}
	}
	return entries
}

func addExtensionNamespaces(ext appExtData, ns map[string]string) {
	// uap
	if ext.Protocol != nil || ext.FileTypeAssociation != nil || ext.ShareTarget != nil ||
		ext.FileOpenPicker != nil || ext.FileSavePicker != nil ||
		ext.AutoPlayContent != nil || ext.AutoPlayDevice != nil ||
		ext.AppService != nil || ext.DialProtocol != nil || ext.VoipCall != nil {
		ns["uap"] = nsUAP
	}

	// uap3
	if ext.AppUriHandler != nil || ext.AppExtensionHost != nil || ext.AppExtension != nil ||
		ext.AppointmentDataProvider != nil || ext.EmailDataProvider != nil || ext.ContactDataProvider != nil {
		ns["uap3"] = nsUAP3
	}

	// uap4
	if ext.SharedFonts != nil || ext.ContactPanel != nil || ext.MediaCodec != nil ||
		ext.LoopbackAccessRules != nil || ext.DevicePortalProvider != nil || ext.UserDataTaskDataProvider != nil {
		ns["uap4"] = nsUAP4
	}

	// uap5
	if ext.UserActivity != nil || ext.MediaSource != nil || ext.VideoRendererEffect != nil ||
		ext.StartupTask != nil || ext.AppExecutionAlias != nil {
		ns["uap5"] = nsUAP5
	}

	// uap6
	if ext.BarcodeScannerProvider != nil {
		ns["uap6"] = nsUAP6
	}

	// uap7
	if ext.SharedFontsUap7 != nil || ext.EnterpriseDataProtection != nil {
		ns["uap7"] = nsUAP7
	}

	// uap10
	if ext.ProtocolUap10 != nil || ext.HostRuntime != nil || ext.PackageIntegrity != nil {
		ns["uap10"] = nsUAP10
	}

	// desktop
	if ext.FullTrustProcess != nil || ext.DesktopStartupTask != nil ||
		ext.ToastNotificationActivation != nil || ext.SearchProtocolHandler != nil {
		ns["desktop"] = nsDesktop
	}

	// desktop2
	if ext.AppPrinter != nil || ext.SearchFilterHandler != nil || ext.SearchPropertyHandler != nil ||
		ext.FirewallRules != nil || ext.DesktopEventLogging != nil {
		ns["desktop2"] = nsDesktop2
	}

	// desktop3
	if ext.AutoPlayHandler != nil || ext.CloudFiles != nil {
		ns["desktop3"] = nsDesktop3
	}

	// desktop4
	if ext.FileExplorerContextMenus != nil {
		ns["desktop4"] = nsDesktop4
	}

	// desktop6
	if ext.Service != nil {
		ns["desktop6"] = nsDesktop6
	}

	// desktop7
	if ext.ApprovedShellExtension != nil || ext.ControlPanelItem != nil || ext.ServiceDesktop7 != nil ||
		ext.Shortcut != nil || ext.ApplicationRegistration != nil || ext.DesktopAppMigration != nil ||
		ext.SystemFileAssociation != nil {
		ns["desktop7"] = nsDesktop7
	}

	// desktop9
	if ext.FileExplorerClassicContextMenuHandler != nil || ext.FileExplorerClassicDragDropContextMenuHandler != nil {
		ns["desktop9"] = nsDesktop9
	}

	// com
	if ext.ComServer != nil || ext.ComInterface != nil {
		ns["com"] = nsCom
	}

	// rescap3 (application-level DesktopAppMigration)
	if ext.DesktopAppMigrationRescap != nil {
		ns["rescap3"] = nsRescap3
	}

	// mobile
	if ext.MobileMultiScreenProperties != nil || ext.CommunicationBlockingProvider != nil ||
		ext.PhoneCallOriginProvider != nil {
		ns["mobile"] = nsMobile
	}

	// printSupport
	if ext.PrintSupportSettingsUI != nil || ext.PrintSupportExtension != nil ||
		ext.PrintSupportJobUI != nil {
		ns["printsupport"] = nsPrintSupport
	}
}

func addPackageExtensionNamespaces(ext pkgExtData, ns map[string]string) {
	if ext.ComServerPkg != nil || ext.ComInterfacePkg != nil {
		ns["com"] = nsCom
	}
	if ext.LoaderSearchPathOverride != nil {
		ns["uap6"] = nsUAP6
	}
	if ext.DesktopAppMigrationPkg != nil {
		ns["rescap3"] = nsRescap3
	}
}

// renderManifest renders the AppxManifest.xml for the given manifest.
func renderManifest(m *manifestData) ([]byte, error) {
	ns := manifestNamespaces(m)

	// Build a lookup set for hasNS template function.
	nsSet := make(map[string]bool, len(ns))
	for _, entry := range ns {
		nsSet[entry.Prefix] = true
	}

	data := struct {
		Manifest   *manifestData
		Namespaces []nsEntry
		NSSet      map[string]bool
	}{
		Manifest:   m,
		Namespaces: ns,
		NSSet:      nsSet,
	}

	tmpl, err := template.New("manifest").Funcs(templateFuncs).Parse(manifestTemplate)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

var templateFuncs = template.FuncMap{
	"hasNS": func(nsSet map[string]bool, prefix string) bool {
		return nsSet[prefix]
	},
	"xmlEscape": func(s string) string {
		s = strings.ReplaceAll(s, "&", "&amp;")
		s = strings.ReplaceAll(s, "<", "&lt;")
		s = strings.ReplaceAll(s, ">", "&gt;")
		s = strings.ReplaceAll(s, "\"", "&quot;")
		s = strings.ReplaceAll(s, "'", "&apos;")
		return s
	},
	"hasCaps": func(c capabilitiesData) bool {
		return len(c.Capabilities) > 0 || len(c.DeviceCapabilities) > 0 ||
			len(c.Restricted) > 0 || len(c.UAP) > 0 || len(c.Custom) > 0
	},
	"hasAppExtensions": func(exts []appExtData) bool {
		return len(exts) > 0
	},
	"hasPkgExtensions": func(exts []pkgExtData) bool {
		return len(exts) > 0
	},
}

const manifestTemplate = `<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
{{- range .Namespaces }}
  xmlns:{{ .Prefix }}="{{ .URI }}"
{{- end }}
  IgnorableNamespaces="{{ range $i, $ns := .Namespaces }}{{ if $i }} {{ end }}{{ $ns.Prefix }}{{ end }}">

  <Identity
    Name="{{ xmlEscape .Manifest.Identity.Name }}"
    Version="{{ xmlEscape .Manifest.Identity.Version }}"
    Publisher="{{ xmlEscape .Manifest.Identity.Publisher }}"
{{- if .Manifest.Identity.ProcessorArchitecture }}
    ProcessorArchitecture="{{ xmlEscape .Manifest.Identity.ProcessorArchitecture }}"
{{- end }}
{{- if .Manifest.Identity.ResourceID }}
    ResourceId="{{ xmlEscape .Manifest.Identity.ResourceID }}"
{{- end }}
  />

  <Properties>
    <DisplayName>{{ xmlEscape .Manifest.Properties.DisplayName }}</DisplayName>
    <PublisherDisplayName>{{ xmlEscape .Manifest.Properties.PublisherDisplayName }}</PublisherDisplayName>
{{- if .Manifest.Properties.Logo }}
    <Logo>{{ xmlEscape .Manifest.Properties.Logo }}</Logo>
{{- end }}
{{- if .Manifest.Properties.Description }}
    <Description>{{ xmlEscape .Manifest.Properties.Description }}</Description>
{{- end }}
{{- if .Manifest.Properties.Framework }}
    <Framework>true</Framework>
{{- end }}
{{- if .Manifest.Properties.ResourcePackage }}
    <ResourcePackage>true</ResourcePackage>
{{- end }}
{{- if .Manifest.Properties.AllowExecution }}
    <AllowExecution>true</AllowExecution>
{{- end }}
{{- if .Manifest.Properties.ModificationPackage }}
    <rescap6:ModificationPackage>true</rescap6:ModificationPackage>
{{- end }}
  </Properties>

  <Dependencies>
{{- range .Manifest.Dependencies.TargetDeviceFamilies }}
    <TargetDeviceFamily
      Name="{{ xmlEscape .Name }}"
      MinVersion="{{ xmlEscape .MinVersion }}"
      MaxVersionTested="{{ xmlEscape .MaxVersionTested }}"
    />
{{- end }}
{{- range .Manifest.Dependencies.PackageDependencies }}
    <PackageDependency
      Name="{{ xmlEscape .Name }}"
{{- if .Publisher }}
      Publisher="{{ xmlEscape .Publisher }}"
{{- end }}
{{- if .MinVersion }}
      MinVersion="{{ xmlEscape .MinVersion }}"
{{- end }}
    />
{{- end }}
  </Dependencies>

  <Resources>
{{- range .Manifest.Resources }}
    <Resource{{ if .Language }} Language="{{ xmlEscape .Language }}"{{ end }}{{ if .Scale }} uap:Scale="{{ xmlEscape .Scale }}"{{ end }}{{ if .DXFeatureLevel }} uap:DXFeatureLevel="{{ xmlEscape .DXFeatureLevel }}"{{ end }} />
{{- end }}
  </Resources>

{{- if hasCaps .Manifest.Capabilities }}

  <Capabilities>
{{- range .Manifest.Capabilities.Capabilities }}
    <Capability Name="{{ xmlEscape .Name }}" />
{{- end }}
{{- range .Manifest.Capabilities.UAP }}
    <uap:Capability Name="{{ xmlEscape .Name }}" />
{{- end }}
{{- range .Manifest.Capabilities.Restricted }}
    <rescap:Capability Name="{{ xmlEscape .Name }}" />
{{- end }}
{{- range .Manifest.Capabilities.Custom }}
    <uap4:CustomCapability Name="{{ xmlEscape .Name }}" />
{{- end }}
{{- range .Manifest.Capabilities.DeviceCapabilities }}
    <DeviceCapability Name="{{ xmlEscape .Name }}">
{{- range .Devices }}
      <Device Id="{{ xmlEscape .ID }}">
{{- range .Functions }}
        <Function Type="{{ xmlEscape .Type }}" />
{{- end }}
      </Device>
{{- end }}
    </DeviceCapability>
{{- end }}
  </Capabilities>
{{- end }}

{{- if .Manifest.Applications }}

  <Applications>
{{- range .Manifest.Applications }}
    <Application
      Id="{{ xmlEscape .ID }}"
{{- if .Executable }}
      Executable="{{ xmlEscape .Executable }}"
{{- end }}
{{- if .EntryPoint }}
      EntryPoint="{{ xmlEscape .EntryPoint }}"
{{- end }}
{{- if .StartPage }}
      StartPage="{{ xmlEscape .StartPage }}"
{{- end }}
{{- if .ResourceGroup }}
      ResourceGroup="{{ xmlEscape .ResourceGroup }}"
{{- end }}
    >
      <uap:VisualElements
        DisplayName="{{ xmlEscape .VisualElements.DisplayName }}"
{{- if .VisualElements.Description }}
        Description="{{ xmlEscape .VisualElements.Description }}"
{{- end }}
        BackgroundColor="{{ xmlEscape .VisualElements.BackgroundColor }}"
        Square150x150Logo="{{ xmlEscape .VisualElements.Square150x150Logo }}"
        Square44x44Logo="{{ xmlEscape .VisualElements.Square44x44Logo }}"
{{- if .VisualElements.AppListEntry }}
        AppListEntry="{{ xmlEscape .VisualElements.AppListEntry }}"
{{- end }}
      >
{{- if .VisualElements.DefaultTile }}
        <uap:DefaultTile
{{- if .VisualElements.DefaultTile.Wide310x150Logo }}
          Wide310x150Logo="{{ xmlEscape .VisualElements.DefaultTile.Wide310x150Logo }}"
{{- end }}
{{- if .VisualElements.DefaultTile.Square71x71Logo }}
          Square71x71Logo="{{ xmlEscape .VisualElements.DefaultTile.Square71x71Logo }}"
{{- end }}
{{- if .VisualElements.DefaultTile.Square310x310Logo }}
          Square310x310Logo="{{ xmlEscape .VisualElements.DefaultTile.Square310x310Logo }}"
{{- end }}
{{- if .VisualElements.DefaultTile.ShortName }}
          ShortName="{{ xmlEscape .VisualElements.DefaultTile.ShortName }}"
{{- end }}
{{- if .VisualElements.DefaultTile.ShowNameOnTiles }}
          ShowNameOnTiles="{{ xmlEscape .VisualElements.DefaultTile.ShowNameOnTiles }}"
{{- end }}
        />
{{- end }}
{{- if .VisualElements.SplashScreen }}
        <uap:SplashScreen
          Image="{{ xmlEscape .VisualElements.SplashScreen.Image }}"
{{- if .VisualElements.SplashScreen.BackgroundColor }}
          BackgroundColor="{{ xmlEscape .VisualElements.SplashScreen.BackgroundColor }}"
{{- end }}
        />
{{- end }}
      </uap:VisualElements>
{{- if hasAppExtensions .Extensions }}
      <Extensions>
{{- range .Extensions }}
{{- template "appExtension" . }}
{{- end }}
      </Extensions>
{{- end }}
    </Application>
{{- end }}
  </Applications>
{{- end }}

{{- if hasPkgExtensions .Manifest.Extensions }}

  <Extensions>
{{- range .Manifest.Extensions }}
{{- template "pkgExtension" . }}
{{- end }}
  </Extensions>
{{- end }}

</Package>
{{- define "appExtension" }}
{{- if .Protocol }}
        <uap:Extension Category="{{ xmlEscape .Category }}">
          <uap:Protocol Name="{{ xmlEscape .Protocol.Name }}"{{ if .Protocol.DisplayName }} DesktopAppInfo="{{ xmlEscape .Protocol.DisplayName }}"{{ end }}>
{{- if .Protocol.Logo }}
            <uap:Logo>{{ xmlEscape .Protocol.Logo }}</uap:Logo>
{{- end }}
          </uap:Protocol>
        </uap:Extension>
{{- end }}
{{- if .FileTypeAssociation }}
        <uap:Extension Category="{{ xmlEscape .Category }}">
          <uap:FileTypeAssociation Name="{{ xmlEscape .FileTypeAssociation.Name }}">
{{- if .FileTypeAssociation.DisplayName }}
            <uap:DisplayName>{{ xmlEscape .FileTypeAssociation.DisplayName }}</uap:DisplayName>
{{- end }}
{{- if .FileTypeAssociation.Logo }}
            <uap:Logo>{{ xmlEscape .FileTypeAssociation.Logo }}</uap:Logo>
{{- end }}
{{- if .FileTypeAssociation.InfoTip }}
            <uap:InfoTip>{{ xmlEscape .FileTypeAssociation.InfoTip }}</uap:InfoTip>
{{- end }}
            <uap:SupportedFileTypes>
{{- range .FileTypeAssociation.SupportedFileTypes }}
              <uap:FileType{{ if .ContentType }} ContentType="{{ xmlEscape .ContentType }}"{{ end }}>{{ xmlEscape .Extension }}</uap:FileType>
{{- end }}
            </uap:SupportedFileTypes>
          </uap:FileTypeAssociation>
        </uap:Extension>
{{- end }}
{{- if .ShareTarget }}
        <uap:Extension Category="{{ xmlEscape .Category }}">
          <uap:ShareTarget>
{{- if .ShareTarget.SupportedFileTypes }}
            <uap:SupportedFileTypes>
{{- range .ShareTarget.SupportedFileTypes }}
              <uap:FileType>{{ xmlEscape .Extension }}</uap:FileType>
{{- end }}
            </uap:SupportedFileTypes>
{{- end }}
{{- range .ShareTarget.DataFormats }}
            <uap:DataFormat>{{ xmlEscape .Format }}</uap:DataFormat>
{{- end }}
          </uap:ShareTarget>
        </uap:Extension>
{{- end }}
{{- if .AppService }}
        <uap:Extension Category="{{ xmlEscape .Category }}">
          <uap:AppService Name="{{ xmlEscape .AppService.Name }}"{{ if .AppService.ServerName }} uap4:ServerName="{{ xmlEscape .AppService.ServerName }}"{{ end }} />
        </uap:Extension>
{{- end }}
{{- if .AppExecutionAlias }}
        <uap5:Extension Category="{{ xmlEscape .Category }}">
          <uap5:AppExecutionAlias>
{{- range .AppExecutionAlias.ExecutionAliases }}
            <uap5:ExecutionAlias Alias="{{ xmlEscape .Alias }}" />
{{- end }}
          </uap5:AppExecutionAlias>
        </uap5:Extension>
{{- end }}
{{- if .StartupTask }}
        <uap5:Extension Category="{{ xmlEscape .Category }}">
          <uap5:StartupTask TaskId="{{ xmlEscape .StartupTask.TaskID }}"{{ if .StartupTask.DisplayName }} DisplayName="{{ xmlEscape .StartupTask.DisplayName }}"{{ end }} />
        </uap5:Extension>
{{- end }}
{{- if .AppUriHandler }}
        <uap3:Extension Category="{{ xmlEscape .Category }}">
          <uap3:AppUriHandler>
{{- range .AppUriHandler.Hosts }}
            <uap3:Host Name="{{ xmlEscape .Name }}" />
{{- end }}
          </uap3:AppUriHandler>
        </uap3:Extension>
{{- end }}
{{- if .AppExtensionHost }}
        <uap3:Extension Category="{{ xmlEscape .Category }}">
          <uap3:AppExtensionHost>
{{- range .AppExtensionHost.Names }}
            <uap3:Name>{{ xmlEscape .Name }}</uap3:Name>
{{- end }}
          </uap3:AppExtensionHost>
        </uap3:Extension>
{{- end }}
{{- if .AppExtension }}
        <uap3:Extension Category="{{ xmlEscape .Category }}">
          <uap3:AppExtension
            Name="{{ xmlEscape .AppExtension.Name }}"
            Id="{{ xmlEscape .AppExtension.ID }}"
            DisplayName="{{ xmlEscape .AppExtension.DisplayName }}"
{{- if .AppExtension.Description }}
            Description="{{ xmlEscape .AppExtension.Description }}"
{{- end }}
{{- if .AppExtension.PublicFolder }}
            PublicFolder="{{ xmlEscape .AppExtension.PublicFolder }}"
{{- end }}
          />
        </uap3:Extension>
{{- end }}
{{- if .FullTrustProcess }}
        <desktop:Extension Category="{{ xmlEscape .Category }}">
          <desktop:FullTrustProcess{{ if .FullTrustProcess.GroupID }} GroupId="{{ xmlEscape .FullTrustProcess.GroupID }}"{{ end }} />
        </desktop:Extension>
{{- end }}
{{- if .ToastNotificationActivation }}
        <desktop:Extension Category="{{ xmlEscape .Category }}">
          <desktop:ToastNotificationActivation ToastActivatorCLSID="{{ xmlEscape .ToastNotificationActivation.ToastActivatorCLSID }}" />
        </desktop:Extension>
{{- end }}
{{- if .ComServer }}
        <com:Extension Category="{{ xmlEscape .Category }}">
          <com:ComServer>
{{- if .ComServer.ExeServer }}
            <com:ExeServer Executable="{{ xmlEscape .ComServer.ExeServer.Executable }}"{{ if .ComServer.ExeServer.DisplayName }} DisplayName="{{ xmlEscape .ComServer.ExeServer.DisplayName }}"{{ end }}>
{{- range .ComServer.ExeServer.Classes }}
              <com:Class Id="{{ xmlEscape .ID }}"{{ if .DisplayName }} DisplayName="{{ xmlEscape .DisplayName }}"{{ end }} />
{{- end }}
            </com:ExeServer>
{{- end }}
{{- if .ComServer.SurrogateServer }}
            <com:SurrogateServer{{ if .ComServer.SurrogateServer.DisplayName }} DisplayName="{{ xmlEscape .ComServer.SurrogateServer.DisplayName }}"{{ end }}>
{{- range .ComServer.SurrogateServer.Classes }}
              <com:Class Id="{{ xmlEscape .ID }}"{{ if .DisplayName }} DisplayName="{{ xmlEscape .DisplayName }}"{{ end }}{{ if .ThreadingModel }} ThreadingModel="{{ xmlEscape .ThreadingModel }}"{{ end }} />
{{- end }}
            </com:SurrogateServer>
{{- end }}
{{- if .ComServer.InProcessServer }}
            <com:InProcessServer Path="{{ xmlEscape .ComServer.InProcessServer.Path }}">
{{- range .ComServer.InProcessServer.Classes }}
              <com:Class Id="{{ xmlEscape .ID }}"{{ if .DisplayName }} DisplayName="{{ xmlEscape .DisplayName }}"{{ end }}{{ if .ThreadingModel }} ThreadingModel="{{ xmlEscape .ThreadingModel }}"{{ end }} />
{{- end }}
            </com:InProcessServer>
{{- end }}
          </com:ComServer>
        </com:Extension>
{{- end }}
{{- if .ComInterface }}
        <com:Extension Category="{{ xmlEscape .Category }}">
          <com:ComInterface>
{{- range .ComInterface.ProxyStubs }}
            <com:ProxyStub Id="{{ xmlEscape .ID }}"{{ if .DisplayName }} DisplayName="{{ xmlEscape .DisplayName }}"{{ end }}{{ if .Path }} Path="{{ xmlEscape .Path }}"{{ end }} />
{{- end }}
{{- range .ComInterface.Interfaces }}
            <com:Interface Id="{{ xmlEscape .ID }}"{{ if .ProxyStubCLSID }} ProxyStubClsid="{{ xmlEscape .ProxyStubCLSID }}"{{ end }} />
{{- end }}
          </com:ComInterface>
        </com:Extension>
{{- end }}
{{- if .Service }}
        <desktop6:Extension Category="{{ xmlEscape .Category }}">
          <desktop6:Service Name="{{ xmlEscape .Service.Name }}" StartupType="{{ xmlEscape .Service.StartupType }}" StartAccount="{{ xmlEscape .Service.StartAccount }}" />
        </desktop6:Extension>
{{- end }}
{{- if .FileExplorerContextMenus }}
        <desktop4:Extension Category="{{ xmlEscape .Category }}">
          <desktop4:FileExplorerContextMenus>
{{- range .FileExplorerContextMenus.ItemTypes }}
            <desktop4:ItemType Type="{{ xmlEscape .Type }}">
{{- range .Verbs }}
              <desktop4:Verb Id="{{ xmlEscape .ID }}" Clsid="{{ xmlEscape .CLSID }}" />
{{- end }}
            </desktop4:ItemType>
{{- end }}
          </desktop4:FileExplorerContextMenus>
        </desktop4:Extension>
{{- end }}
{{- if .BackgroundTasks }}
        <Extension Category="{{ xmlEscape .Category }}">
          <BackgroundTasks>
{{- range .BackgroundTasks.Tasks }}
            <Task Type="{{ xmlEscape .Type }}" />
{{- end }}
          </BackgroundTasks>
        </Extension>
{{- end }}
{{- if .HostRuntime }}
        <uap10:Extension Category="{{ xmlEscape .Category }}">
          <uap10:HostRuntime Id="{{ xmlEscape .HostRuntime.ID }}" RuntimeBehavior="{{ xmlEscape .HostRuntime.RuntimeBehavior }}" />
        </uap10:Extension>
{{- end }}
{{- if .PackageIntegrity }}
        <uap10:Extension Category="{{ xmlEscape .Category }}">
          <uap10:PackageIntegrity>
{{- if .PackageIntegrity.Content }}
            <uap10:Content Enforcement="{{ xmlEscape .PackageIntegrity.Content.Enforcement }}" />
{{- end }}
          </uap10:PackageIntegrity>
        </uap10:Extension>
{{- end }}
{{- if .Shortcut }}
        <desktop7:Extension Category="{{ xmlEscape .Category }}">
          <desktop7:Shortcut
            File="{{ xmlEscape .Shortcut.File }}"
{{- if .Shortcut.Icon }}
            Icon="{{ xmlEscape .Shortcut.Icon }}"
{{- end }}
{{- if .Shortcut.DisplayName }}
            DisplayName="{{ xmlEscape .Shortcut.DisplayName }}"
{{- end }}
{{- if .Shortcut.Description }}
            Description="{{ xmlEscape .Shortcut.Description }}"
{{- end }}
          />
        </desktop7:Extension>
{{- end }}
{{- if .FileOpenPicker }}
        <uap:Extension Category="{{ xmlEscape .Category }}">
          <uap:FileOpenPicker>
            <uap:SupportedFileTypes>
{{- range .FileOpenPicker.SupportedFileTypes }}
              <uap:FileType>{{ xmlEscape .Extension }}</uap:FileType>
{{- end }}
            </uap:SupportedFileTypes>
          </uap:FileOpenPicker>
        </uap:Extension>
{{- end }}
{{- if .FileSavePicker }}
        <uap:Extension Category="{{ xmlEscape .Category }}">
          <uap:FileSavePicker>
            <uap:SupportedFileTypes>
{{- range .FileSavePicker.SupportedFileTypes }}
              <uap:FileType>{{ xmlEscape .Extension }}</uap:FileType>
{{- end }}
            </uap:SupportedFileTypes>
          </uap:FileSavePicker>
        </uap:Extension>
{{- end }}
{{- if .AutoPlayContent }}
        <uap:Extension Category="{{ xmlEscape .Category }}">
          <uap:AutoPlayContent>
{{- range .AutoPlayContent.LaunchActions }}
            <uap:LaunchAction Verb="{{ xmlEscape .Verb }}" ActionDisplayName="{{ xmlEscape .ActionDisplayName }}" ContentEvent="{{ xmlEscape .ContentEvent }}" />
{{- end }}
          </uap:AutoPlayContent>
        </uap:Extension>
{{- end }}
{{- if .AutoPlayDevice }}
        <uap:Extension Category="{{ xmlEscape .Category }}">
          <uap:AutoPlayDevice>
{{- range .AutoPlayDevice.LaunchActions }}
            <uap:LaunchAction Verb="{{ xmlEscape .Verb }}" ActionDisplayName="{{ xmlEscape .ActionDisplayName }}" DeviceEvent="{{ xmlEscape .DeviceEvent }}" />
{{- end }}
          </uap:AutoPlayDevice>
        </uap:Extension>
{{- end }}
{{- if .DialProtocol }}
        <uap:Extension Category="{{ xmlEscape .Category }}">
          <uap:DialProtocol Name="{{ xmlEscape .DialProtocol.Name }}" />
        </uap:Extension>
{{- end }}
{{- if .VoipCall }}
        <uap:Extension Category="{{ xmlEscape .Category }}">
          <uap:VoipCall />
        </uap:Extension>
{{- end }}
{{- if .AppointmentDataProvider }}
        <uap3:Extension Category="{{ xmlEscape .Category }}">
          <uap3:AppointmentDataProvider ServerName="{{ xmlEscape .AppointmentDataProvider.ServerName }}" />
        </uap3:Extension>
{{- end }}
{{- if .EmailDataProvider }}
        <uap3:Extension Category="{{ xmlEscape .Category }}">
          <uap3:EmailDataProvider ServerName="{{ xmlEscape .EmailDataProvider.ServerName }}" />
        </uap3:Extension>
{{- end }}
{{- if .ContactDataProvider }}
        <uap3:Extension Category="{{ xmlEscape .Category }}">
          <uap3:ContactDataProvider ServerName="{{ xmlEscape .ContactDataProvider.ServerName }}" />
        </uap3:Extension>
{{- end }}
{{- if .SharedFonts }}
        <uap4:Extension Category="{{ xmlEscape .Category }}">
          <uap4:SharedFonts>
{{- range .SharedFonts.Fonts }}
            <uap4:Font File="{{ xmlEscape .File }}" />
{{- end }}
          </uap4:SharedFonts>
        </uap4:Extension>
{{- end }}
{{- if .ContactPanel }}
        <uap4:Extension Category="{{ xmlEscape .Category }}">
          <uap4:ContactPanel SupportsUnknownContacts="{{ if .ContactPanel.SupportsUnknownContacts }}true{{ else }}false{{ end }}" />
        </uap4:Extension>
{{- end }}
{{- if .MediaCodec }}
        <uap4:Extension Category="{{ xmlEscape .Category }}">
          <uap4:MediaCodec{{ if .MediaCodec.DisplayName }} DisplayName="{{ xmlEscape .MediaCodec.DisplayName }}"{{ end }}{{ if .MediaCodec.Description }} Description="{{ xmlEscape .MediaCodec.Description }}"{{ end }}{{ if .MediaCodec.Category }} Category="{{ xmlEscape .MediaCodec.Category }}"{{ end }}>
{{- range .MediaCodec.MediaTypes }}
            <uap4:MediaType SubType="{{ xmlEscape .SubType }}" />
{{- end }}
          </uap4:MediaCodec>
        </uap4:Extension>
{{- end }}
{{- if .LoopbackAccessRules }}
        <uap4:Extension Category="{{ xmlEscape .Category }}">
          <uap4:LoopbackAccessRules>
{{- range .LoopbackAccessRules.Rules }}
            <uap4:Rule Direction="{{ xmlEscape .Direction }}" />
{{- end }}
          </uap4:LoopbackAccessRules>
        </uap4:Extension>
{{- end }}
{{- if .DevicePortalProvider }}
        <uap4:Extension Category="{{ xmlEscape .Category }}">
          <uap4:DevicePortalProvider DisplayName="{{ xmlEscape .DevicePortalProvider.DisplayName }}" AppServiceName="{{ xmlEscape .DevicePortalProvider.AppServiceName }}"{{ if .DevicePortalProvider.ContentRoute }} ContentRoute="{{ xmlEscape .DevicePortalProvider.ContentRoute }}"{{ end }}{{ if .DevicePortalProvider.HandlerRoute }} HandlerRoute="{{ xmlEscape .DevicePortalProvider.HandlerRoute }}"{{ end }} />
        </uap4:Extension>
{{- end }}
{{- if .UserDataTaskDataProvider }}
        <uap4:Extension Category="{{ xmlEscape .Category }}">
          <uap4:UserDataTaskDataProvider ServerName="{{ xmlEscape .UserDataTaskDataProvider.ServerName }}" />
        </uap4:Extension>
{{- end }}
{{- if .UserActivity }}
        <uap5:Extension Category="{{ xmlEscape .Category }}">
          <uap5:UserActivity ActivitySourceHost="{{ xmlEscape .UserActivity.ActivitySourceHost }}" />
        </uap5:Extension>
{{- end }}
{{- if .MediaSource }}
        <uap5:Extension Category="{{ xmlEscape .Category }}">
          <uap5:MediaSource{{ if .MediaSource.DisplayName }} DisplayName="{{ xmlEscape .MediaSource.DisplayName }}"{{ end }}>
{{- range .MediaSource.MediaTypes }}
            <uap5:MediaType SubType="{{ xmlEscape .SubType }}" />
{{- end }}
          </uap5:MediaSource>
        </uap5:Extension>
{{- end }}
{{- if .VideoRendererEffect }}
        <uap5:Extension Category="{{ xmlEscape .Category }}">
          <uap5:VideoRendererEffect DisplayName="{{ xmlEscape .VideoRendererEffect.DisplayName }}" ActivatableClassId="{{ xmlEscape .VideoRendererEffect.ActivatableClassID }}" />
        </uap5:Extension>
{{- end }}
{{- if .BarcodeScannerProvider }}
        <uap6:Extension Category="{{ xmlEscape .Category }}">
          <uap6:BarcodeScannerProvider />
        </uap6:Extension>
{{- end }}
{{- if .SharedFontsUap7 }}
        <uap7:Extension Category="{{ xmlEscape .Category }}">
          <uap7:SharedFonts>
{{- range .SharedFontsUap7.Fonts }}
            <uap7:Font File="{{ xmlEscape .File }}" />
{{- end }}
          </uap7:SharedFonts>
        </uap7:Extension>
{{- end }}
{{- if .EnterpriseDataProtection }}
        <uap7:Extension Category="{{ xmlEscape .Category }}">
          <uap7:EnterpriseDataProtection>
{{- range .EnterpriseDataProtection.ProtectionDomains }}
            <uap7:ProtectionDomain Name="{{ xmlEscape .Name }}" />
{{- end }}
          </uap7:EnterpriseDataProtection>
        </uap7:Extension>
{{- end }}
{{- if .ProtocolUap10 }}
        <uap10:Extension Category="{{ xmlEscape .Category }}">
          <uap10:Protocol Name="{{ xmlEscape .ProtocolUap10.Name }}"{{ if .ProtocolUap10.Parameters }} Parameters="{{ xmlEscape .ProtocolUap10.Parameters }}"{{ end }} />
        </uap10:Extension>
{{- end }}
{{- if .DesktopStartupTask }}
        <desktop:Extension Category="{{ xmlEscape .Category }}">
          <desktop:StartupTask TaskId="{{ xmlEscape .DesktopStartupTask.TaskID }}" Enabled="{{ if .DesktopStartupTask.Enabled }}true{{ else }}false{{ end }}" />
        </desktop:Extension>
{{- end }}
{{- if .SearchProtocolHandler }}
        <desktop:Extension Category="{{ xmlEscape .Category }}">
          <desktop:SearchProtocolHandler DisplayName="{{ xmlEscape .SearchProtocolHandler.DisplayName }}" />
        </desktop:Extension>
{{- end }}
{{- if .AppPrinter }}
        <desktop2:Extension Category="{{ xmlEscape .Category }}">
          <desktop2:AppPrinter DisplayName="{{ xmlEscape .AppPrinter.DisplayName }}"{{ if .AppPrinter.Parameters }} Parameters="{{ xmlEscape .AppPrinter.Parameters }}"{{ end }} />
        </desktop2:Extension>
{{- end }}
{{- if .SearchFilterHandler }}
        <desktop2:Extension Category="{{ xmlEscape .Category }}">
          <desktop2:SearchFilterHandler Clsid="{{ xmlEscape .SearchFilterHandler.CLSID }}"{{ if .SearchFilterHandler.DisplayName }} DisplayName="{{ xmlEscape .SearchFilterHandler.DisplayName }}"{{ end }} />
        </desktop2:Extension>
{{- end }}
{{- if .SearchPropertyHandler }}
        <desktop2:Extension Category="{{ xmlEscape .Category }}">
          <desktop2:SearchPropertyHandler Clsid="{{ xmlEscape .SearchPropertyHandler.CLSID }}"{{ if .SearchPropertyHandler.DisplayName }} DisplayName="{{ xmlEscape .SearchPropertyHandler.DisplayName }}"{{ end }} />
        </desktop2:Extension>
{{- end }}
{{- if .FirewallRules }}
        <desktop2:Extension Category="{{ xmlEscape .Category }}">
          <desktop2:FirewallRules>
{{- range .FirewallRules.Rules }}
            <desktop2:Rule Direction="{{ xmlEscape .Direction }}" IPProtocol="{{ xmlEscape .Protocol }}"{{ if .Profile }} Profile="{{ xmlEscape .Profile }}"{{ end }}{{ if .LocalPortMin }} LocalPortMin="{{ xmlEscape .LocalPortMin }}"{{ end }}{{ if .LocalPortMax }} LocalPortMax="{{ xmlEscape .LocalPortMax }}"{{ end }}{{ if .RemotePortMin }} RemotePortMin="{{ xmlEscape .RemotePortMin }}"{{ end }}{{ if .RemotePortMax }} RemotePortMax="{{ xmlEscape .RemotePortMax }}"{{ end }} />
{{- end }}
          </desktop2:FirewallRules>
        </desktop2:Extension>
{{- end }}
{{- if .DesktopEventLogging }}
        <desktop2:Extension Category="{{ xmlEscape .Category }}">
          <desktop2:DesktopEventLogging{{ if .DesktopEventLogging.ProviderGUID }} ProviderGuid="{{ xmlEscape .DesktopEventLogging.ProviderGUID }}"{{ end }}>
{{- range .DesktopEventLogging.Channels }}
            <desktop2:Channel Name="{{ xmlEscape .Name }}" />
{{- end }}
          </desktop2:DesktopEventLogging>
        </desktop2:Extension>
{{- end }}
{{- if .AutoPlayHandler }}
        <desktop3:Extension Category="{{ xmlEscape .Category }}">
          <desktop3:AutoPlayHandler>
{{- range .AutoPlayHandler.InvokeActions }}
            <desktop3:InvokeAction ActionDisplayName="{{ xmlEscape .ActionDisplayName }}" ProviderClsid="{{ xmlEscape .ProviderCLSID }}"{{ if .ContentEvent }} ContentEvent="{{ xmlEscape .ContentEvent }}"{{ end }}{{ if .DeviceEvent }} DeviceEvent="{{ xmlEscape .DeviceEvent }}"{{ end }} />
{{- end }}
          </desktop3:AutoPlayHandler>
        </desktop3:Extension>
{{- end }}
{{- if .CloudFiles }}
        <desktop3:Extension Category="{{ xmlEscape .Category }}">
          <desktop3:CloudFiles{{ if .CloudFiles.IconResource }} IconResource="{{ xmlEscape .CloudFiles.IconResource }}"{{ end }}>
{{- if .CloudFiles.CustomStateHandler }}
            <desktop3:CustomStateHandler Clsid="{{ xmlEscape .CloudFiles.CustomStateHandler.CLSID }}" />
{{- end }}
{{- if .CloudFiles.ThumbnailProviderHandler }}
            <desktop3:ThumbnailProviderHandler Clsid="{{ xmlEscape .CloudFiles.ThumbnailProviderHandler.CLSID }}" />
{{- end }}
{{- if .CloudFiles.ExtendedPropertyHandler }}
            <desktop3:ExtendedPropertyHandler Clsid="{{ xmlEscape .CloudFiles.ExtendedPropertyHandler.CLSID }}" />
{{- end }}
{{- if .CloudFiles.BannersHandler }}
            <desktop3:BannersHandler Clsid="{{ xmlEscape .CloudFiles.BannersHandler.CLSID }}" />
{{- end }}
{{- if .CloudFiles.ContentUriSource }}
            <desktop3:ContentUriSource Clsid="{{ xmlEscape .CloudFiles.ContentUriSource.CLSID }}" />
{{- end }}
          </desktop3:CloudFiles>
        </desktop3:Extension>
{{- end }}
{{- if .ApprovedShellExtension }}
        <desktop7:Extension Category="{{ xmlEscape .Category }}">
          <desktop7:ApprovedShellExtension Clsid="{{ xmlEscape .ApprovedShellExtension.CLSID }}" />
        </desktop7:Extension>
{{- end }}
{{- if .ControlPanelItem }}
        <desktop7:Extension Category="{{ xmlEscape .Category }}">
          <desktop7:ControlPanelItem SystemApplicationName="{{ xmlEscape .ControlPanelItem.SystemApplicationName }}" />
        </desktop7:Extension>
{{- end }}
{{- if .ServiceDesktop7 }}
        <desktop7:Extension Category="{{ xmlEscape .Category }}">
          <desktop7:Service Name="{{ xmlEscape .ServiceDesktop7.Name }}"{{ if .ServiceDesktop7.StartupType }} StartupType="{{ xmlEscape .ServiceDesktop7.StartupType }}"{{ end }}{{ if .ServiceDesktop7.StartAccount }} StartAccount="{{ xmlEscape .ServiceDesktop7.StartAccount }}"{{ end }}{{ if .ServiceDesktop7.Arguments }} Arguments="{{ xmlEscape .ServiceDesktop7.Arguments }}"{{ end }} />
        </desktop7:Extension>
{{- end }}
{{- if .ApplicationRegistration }}
        <desktop7:Extension Category="{{ xmlEscape .Category }}">
          <desktop7:ApplicationRegistration />
        </desktop7:Extension>
{{- end }}
{{- if .DesktopAppMigration }}
        <desktop7:Extension Category="{{ xmlEscape .Category }}">
          <desktop7:DesktopAppMigration>
{{- range .DesktopAppMigration.DesktopApps }}
            <desktop7:DesktopApp AumId="{{ xmlEscape .AumID }}" ShortcutPath="{{ xmlEscape .ShortcutPath }}" />
{{- end }}
          </desktop7:DesktopAppMigration>
        </desktop7:Extension>
{{- end }}
{{- if .SystemFileAssociation }}
        <desktop7:Extension Category="{{ xmlEscape .Category }}">
          <desktop7:SystemFileAssociation Extension="{{ xmlEscape .SystemFileAssociation.Extension }}"{{ if .SystemFileAssociation.FullDetails }} FullDetails="{{ xmlEscape .SystemFileAssociation.FullDetails }}"{{ end }}{{ if .SystemFileAssociation.PreviewDetails }} PreviewDetails="{{ xmlEscape .SystemFileAssociation.PreviewDetails }}"{{ end }}{{ if .SystemFileAssociation.PreviewTitle }} PreviewTitle="{{ xmlEscape .SystemFileAssociation.PreviewTitle }}"{{ end }}{{ if .SystemFileAssociation.TileInfo }} TileInfo="{{ xmlEscape .SystemFileAssociation.TileInfo }}"{{ end }} />
        </desktop7:Extension>
{{- end }}
{{- if .FileExplorerClassicContextMenuHandler }}
        <desktop9:Extension Category="{{ xmlEscape .Category }}">
          <desktop9:FileExplorerClassicContextMenuHandler Clsid="{{ xmlEscape .FileExplorerClassicContextMenuHandler.CLSID }}" />
        </desktop9:Extension>
{{- end }}
{{- if .FileExplorerClassicDragDropContextMenuHandler }}
        <desktop9:Extension Category="{{ xmlEscape .Category }}">
          <desktop9:FileExplorerClassicDragDropContextMenuHandler Clsid="{{ xmlEscape .FileExplorerClassicDragDropContextMenuHandler.CLSID }}" />
        </desktop9:Extension>
{{- end }}
{{- if .DesktopAppMigrationRescap }}
        <rescap3:Extension Category="{{ xmlEscape .Category }}">
          <rescap3:DesktopAppMigration>
{{- range .DesktopAppMigrationRescap.DesktopApps }}
            <rescap3:DesktopApp AumId="{{ xmlEscape .AumID }}" ShortcutPath="{{ xmlEscape .ShortcutPath }}" />
{{- end }}
          </rescap3:DesktopAppMigration>
        </rescap3:Extension>
{{- end }}
{{- if .MobileMultiScreenProperties }}
        <mobile:Extension Category="{{ xmlEscape .Category }}">
          <mobile:MobileMultiScreenProperties RestoreFromOtherDisplayOnReactivation="{{ if .MobileMultiScreenProperties.RestoreFromOtherDisplayOnReactivation }}true{{ else }}false{{ end }}" />
        </mobile:Extension>
{{- end }}
{{- if .CommunicationBlockingProvider }}
        <mobile:Extension Category="{{ xmlEscape .Category }}">
          <mobile:CommunicationBlockingProvider />
        </mobile:Extension>
{{- end }}
{{- if .PhoneCallOriginProvider }}
        <mobile:Extension Category="{{ xmlEscape .Category }}">
          <mobile:PhoneCallOriginProvider />
        </mobile:Extension>
{{- end }}
{{- if .PrintSupportSettingsUI }}
        <printsupport:Extension Category="{{ xmlEscape .Category }}">
          <printsupport:PrintSupportSettingsUI />
        </printsupport:Extension>
{{- end }}
{{- if .PrintSupportExtension }}
        <printsupport:Extension Category="{{ xmlEscape .Category }}">
          <printsupport:PrintSupportExtension />
        </printsupport:Extension>
{{- end }}
{{- if .PrintSupportJobUI }}
        <printsupport:Extension Category="{{ xmlEscape .Category }}">
          <printsupport:PrintSupportJobUI />
        </printsupport:Extension>
{{- end }}
{{- end }}
{{- define "pkgExtension" }}
{{- if .Certificates }}
        <Extension Category="{{ xmlEscape .Category }}">
          <Certificates>
{{- range .Certificates.Certificate }}
            <Certificate StoreName="{{ xmlEscape .StoreName }}" Content="{{ xmlEscape .Content }}" />
{{- end }}
          </Certificates>
        </Extension>
{{- end }}
{{- if .ComServerPkg }}
        <com:Extension Category="{{ xmlEscape .Category }}">
          <com:ComServer>
{{- if .ComServerPkg.ExeServer }}
            <com:ExeServer Executable="{{ xmlEscape .ComServerPkg.ExeServer.Executable }}"{{ if .ComServerPkg.ExeServer.DisplayName }} DisplayName="{{ xmlEscape .ComServerPkg.ExeServer.DisplayName }}"{{ end }}>
{{- range .ComServerPkg.ExeServer.Classes }}
              <com:Class Id="{{ xmlEscape .ID }}"{{ if .DisplayName }} DisplayName="{{ xmlEscape .DisplayName }}"{{ end }} />
{{- end }}
            </com:ExeServer>
{{- end }}
          </com:ComServer>
        </com:Extension>
{{- end }}
{{- if .InProcessServer }}
        <Extension Category="{{ xmlEscape .Category }}">
          <InProcessServer>
            <Path>{{ xmlEscape .InProcessServer.Path }}</Path>
{{- range .InProcessServer.ActivatableClasses }}
            <ActivatableClass ActivatableClassId="{{ xmlEscape .ActivatableClassID }}"{{ if .ThreadingModel }} ThreadingModel="{{ xmlEscape .ThreadingModel }}"{{ end }} />
{{- end }}
          </InProcessServer>
        </Extension>
{{- end }}
{{- if .OutOfProcessServer }}
        <Extension Category="{{ xmlEscape .Category }}">
          <OutOfProcessServer ServerName="{{ xmlEscape .OutOfProcessServer.ServerName }}"{{ if .OutOfProcessServer.Instancing }} Instancing="{{ xmlEscape .OutOfProcessServer.Instancing }}"{{ end }}>
            <Path>{{ xmlEscape .OutOfProcessServer.Executable }}</Path>
{{- if .OutOfProcessServer.Arguments }}
            <Arguments>{{ xmlEscape .OutOfProcessServer.Arguments }}</Arguments>
{{- end }}
{{- range .OutOfProcessServer.ActivatableClasses }}
            <ActivatableClass ActivatableClassId="{{ xmlEscape .ActivatableClassID }}"{{ if .ThreadingModel }} ThreadingModel="{{ xmlEscape .ThreadingModel }}"{{ end }} />
{{- end }}
          </OutOfProcessServer>
        </Extension>
{{- end }}
{{- if .ProxyStubPkg }}
        <Extension Category="{{ xmlEscape .Category }}">
          <ProxyStub ClassId="{{ xmlEscape .ProxyStubPkg.CLSID }}">
            <Path>{{ xmlEscape .ProxyStubPkg.Path }}</Path>
          </ProxyStub>
        </Extension>
{{- end }}
{{- if .PublisherCacheFolders }}
        <Extension Category="{{ xmlEscape .Category }}">
          <PublisherCacheFolders>
{{- range .PublisherCacheFolders.Folders }}
            <Folder Name="{{ xmlEscape .Name }}" />
{{- end }}
          </PublisherCacheFolders>
        </Extension>
{{- end }}
{{- if .LoaderSearchPathOverride }}
        <uap6:Extension Category="{{ xmlEscape .Category }}">
          <uap6:LoaderSearchPathOverride>
{{- range .LoaderSearchPathOverride.Entries }}
            <uap6:LoaderSearchPathEntry FolderPath="{{ xmlEscape .FolderPath }}" />
{{- end }}
          </uap6:LoaderSearchPathOverride>
        </uap6:Extension>
{{- end }}
{{- if .ComInterfacePkg }}
        <com:Extension Category="{{ xmlEscape .Category }}">
          <com:ComInterface>
{{- range .ComInterfacePkg.ProxyStubs }}
            <com:ProxyStub Id="{{ xmlEscape .ID }}"{{ if .DisplayName }} DisplayName="{{ xmlEscape .DisplayName }}"{{ end }}{{ if .Path }} Path="{{ xmlEscape .Path }}"{{ end }} />
{{- end }}
{{- range .ComInterfacePkg.Interfaces }}
            <com:Interface Id="{{ xmlEscape .ID }}"{{ if .ProxyStubCLSID }} ProxyStubClsid="{{ xmlEscape .ProxyStubCLSID }}"{{ end }} />
{{- end }}
          </com:ComInterface>
        </com:Extension>
{{- end }}
{{- if .DesktopAppMigrationPkg }}
        <rescap3:Extension Category="{{ xmlEscape .Category }}">
          <rescap3:DesktopAppMigration>
{{- range .DesktopAppMigrationPkg.DesktopApps }}
            <rescap3:DesktopApp AumId="{{ xmlEscape .AumID }}" ShortcutPath="{{ xmlEscape .ShortcutPath }}" />
{{- end }}
          </rescap3:DesktopAppMigration>
        </rescap3:Extension>
{{- end }}
{{- end }}
`
