package msix

// --- uap namespace extensions ---

// Protocol represents uap:Protocol for protocol activation.
type Protocol struct {
	Name        string
	DisplayName string
	Logo        string
	// uap3 parameters support
	Parameters string
}

// FileTypeAssociation represents uap:FileTypeAssociation.
type FileTypeAssociation struct {
	Name               string
	DisplayName        string
	Logo               string
	InfoTip            string
	SupportedFileTypes []FileType
	// uap4 additions
	DesiredView string
}

// FileType represents a supported file type within a FileTypeAssociation.
type FileType struct {
	Extension   string // e.g., ".myf"
	ContentType string // MIME type, optional
}

// ShareTarget represents uap:ShareTarget.
type ShareTarget struct {
	SupportedFileTypes []FileType
	DataFormats        []DataFormat
}

// DataFormat represents a data format within ShareTarget.
type DataFormat struct {
	Format string // e.g., "Text", "URI", "Bitmap", "HTML", "StorageItems"
}

// FileOpenPicker represents uap:FileOpenPicker.
type FileOpenPicker struct {
	SupportedFileTypes []FileType
}

// FileSavePicker represents uap:FileSavePicker.
type FileSavePicker struct {
	SupportedFileTypes []FileType
}

// AutoPlayContent represents uap:AutoPlayContent.
type AutoPlayContent struct {
	LaunchActions []AutoPlayLaunchAction
}

// AutoPlayDevice represents uap:AutoPlayDevice.
type AutoPlayDevice struct {
	LaunchActions []AutoPlayDeviceLaunchAction
}

// AutoPlayLaunchAction represents an action within AutoPlayContent.
type AutoPlayLaunchAction struct {
	Verb        string
	ActionDisplayName string
	ContentEvent string
}

// AutoPlayDeviceLaunchAction represents an action within AutoPlayDevice.
type AutoPlayDeviceLaunchAction struct {
	Verb        string
	ActionDisplayName string
	DeviceEvent string
}

// AppService represents uap:AppService / uap3:AppService.
type AppService struct {
	Name            string
	ServerName      string
	SupportsRemoteSystemsEnum bool // uap4
}

// DialProtocol represents uap:DialProtocol.
type DialProtocol struct {
	Name string
}

// VoipCall represents uap:VoipCall.
type VoipCall struct{}

// --- uap3 namespace extensions ---

// AppUriHandler represents uap3:AppUriHandler.
type AppUriHandler struct {
	Hosts []AppUriHandlerHost
}

// AppUriHandlerHost represents a host within AppUriHandler.
type AppUriHandlerHost struct {
	Name string
}

// AppExtensionHost represents uap3:AppExtensionHost.
type AppExtensionHost struct {
	Names []AppExtensionName
}

// AppExtensionName is a name entry in AppExtensionHost.
type AppExtensionName struct {
	Name string
}

// AppExtension represents uap3:AppExtension.
type AppExtension struct {
	Name        string
	ID          string
	DisplayName string
	Description string
	PublicFolder string
}

// AppointmentDataProvider represents uap3:AppointmentDataProvider.
type AppointmentDataProvider struct {
	ServerName string
}

// EmailDataProvider represents uap3:EmailDataProvider.
type EmailDataProvider struct {
	ServerName string
}

// ContactDataProvider represents uap3:ContactDataProvider.
type ContactDataProvider struct {
	ServerName string
}

// --- uap4 namespace extensions ---

// SharedFonts represents uap4:SharedFonts.
type SharedFonts struct {
	Fonts []Font
}

// Font represents a uap4:Font entry.
type Font struct {
	File string
}

// ContactPanel represents uap4:ContactPanel.
type ContactPanel struct {
	SupportsUnknownContacts bool
}

// MediaCodec represents uap4:MediaCodec.
type MediaCodec struct {
	DisplayName string
	Description string
	Category    string // "audioDecoder", "audioEncoder", "videoDecoder", "videoEncoder"
	MediaTypes  []MediaType
}

// MediaType within MediaCodec.
type MediaType struct {
	SubType string
}

// LoopbackAccessRules represents uap4:LoopbackAccessRules.
type LoopbackAccessRules struct {
	Rules []LoopbackRule
}

// LoopbackRule represents a single rule.
type LoopbackRule struct {
	Direction string // "out"
}

// DevicePortalProvider represents uap4:DevicePortalProvider.
type DevicePortalProvider struct {
	DisplayName string
	AppServiceName string
	ContentRoute string
	HandlerRoute string
}

// UserDataTaskDataProvider represents uap4:UserDataTaskDataProvider.
type UserDataTaskDataProvider struct {
	ServerName string
}

// --- uap5 namespace extensions ---

// UserActivity represents uap5:UserActivity.
type UserActivity struct {
	ActivitySourceHost string
}

// MediaSource represents uap5:MediaSource.
type MediaSource struct {
	DisplayName string
	MediaTypes  []MediaSourceMediaType
}

// MediaSourceMediaType is a media type for MediaSource.
type MediaSourceMediaType struct {
	SubType string
}

// VideoRendererEffect represents uap5:VideoRendererEffect.
type VideoRendererEffect struct {
	DisplayName   string
	ActivatableClassID string
}

// StartupTask represents uap5:StartupTask / desktop:StartupTask.
type StartupTask struct {
	TaskID     string
	Enabled    bool
	DisplayName string
}

// AppExecutionAlias represents uap5:AppExecutionAlias.
type AppExecutionAlias struct {
	ExecutionAliases []ExecutionAlias
}

// ExecutionAlias represents a single execution alias entry.
type ExecutionAlias struct {
	Alias string
}

// --- uap6 namespace extensions ---

// BarcodeScannerProvider represents uap6:BarcodeScannerProvider.
type BarcodeScannerProvider struct{}

// --- uap7 namespace extensions ---

// SharedFontsUap7 represents uap7:SharedFonts.
type SharedFontsUap7 struct {
	Fonts []Font
}

// EnterpriseDataProtection represents uap7:EnterpriseDataProtection.
type EnterpriseDataProtection struct {
	ProtectionDomains []ProtectionDomain
}

// ProtectionDomain within EnterpriseDataProtection.
type ProtectionDomain struct {
	Name string
}

// --- uap10 namespace extensions ---

// ProtocolUap10 represents uap10:Protocol.
type ProtocolUap10 struct {
	Name       string
	Parameters string
}

// HostRuntime represents uap10:HostRuntime.
type HostRuntime struct {
	ID         string
	RuntimeBehavior string // "packagedClassicApp", "windowsApp"
}

// PackageIntegrity represents uap10:PackageIntegrity.
type PackageIntegrity struct {
	Content *PackageIntegrityContent
}

// PackageIntegrityContent contains content integrity info.
type PackageIntegrityContent struct {
	Enforcement string // "on", "default"
}
