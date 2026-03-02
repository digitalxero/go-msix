package msix

// Application represents a single application entry in the manifest.
type Application struct {
	ID              string
	Executable      string
	EntryPoint      string
	StartPage       string // For JavaScript apps
	ResourceGroup   string
	VisualElements  VisualElements
	Extensions      []ApplicationExtension
}

// VisualElements represents the uap:VisualElements for an application.
type VisualElements struct {
	DisplayName       string
	Description       string
	BackgroundColor   string
	Square150x150Logo string
	Square44x44Logo   string
	AppListEntry      string // "default", "none"
	DefaultTile       *DefaultTile
	SplashScreen      *SplashScreen
}

// DefaultTile represents uap:DefaultTile within VisualElements.
type DefaultTile struct {
	Wide310x150Logo   string
	Square71x71Logo   string
	Square310x310Logo string
	ShortName         string
	ShowNameOnTiles   string // "showOn150x150Logo", "showOnWide310x150Logo", etc.
}

// SplashScreen represents uap:SplashScreen within VisualElements.
type SplashScreen struct {
	Image           string
	BackgroundColor string
}

// ApplicationExtension represents an extension within an Application.
// Only one of the typed fields should be non-nil, corresponding to the Category.
type ApplicationExtension struct {
	Category string

	// uap extensions
	Protocol             *Protocol
	FileTypeAssociation  *FileTypeAssociation
	ShareTarget          *ShareTarget
	FileOpenPicker       *FileOpenPicker
	FileSavePicker       *FileSavePicker
	AutoPlayContent      *AutoPlayContent
	AutoPlayDevice       *AutoPlayDevice
	AppService           *AppService
	DialProtocol         *DialProtocol
	VoipCall             *VoipCall

	// uap3 extensions
	AppUriHandler          *AppUriHandler
	AppExtensionHost       *AppExtensionHost
	AppExtension           *AppExtension
	AppointmentDataProvider *AppointmentDataProvider
	EmailDataProvider      *EmailDataProvider
	ContactDataProvider    *ContactDataProvider

	// uap4 extensions
	SharedFonts            *SharedFonts
	ContactPanel           *ContactPanel
	MediaCodec             *MediaCodec
	LoopbackAccessRules    *LoopbackAccessRules
	DevicePortalProvider   *DevicePortalProvider
	UserDataTaskDataProvider *UserDataTaskDataProvider

	// uap5 extensions
	UserActivity       *UserActivity
	MediaSource        *MediaSource
	VideoRendererEffect *VideoRendererEffect
	StartupTask        *StartupTask
	AppExecutionAlias  *AppExecutionAlias

	// uap6 extensions
	BarcodeScannerProvider *BarcodeScannerProvider

	// uap7 extensions
	SharedFontsUap7             *SharedFontsUap7
	EnterpriseDataProtection    *EnterpriseDataProtection

	// uap10 extensions
	ProtocolUap10   *ProtocolUap10
	HostRuntime     *HostRuntime
	PackageIntegrity *PackageIntegrity

	// desktop extensions
	FullTrustProcess                *FullTrustProcess
	DesktopStartupTask              *DesktopStartupTask
	ToastNotificationActivation     *ToastNotificationActivation
	SearchProtocolHandler           *SearchProtocolHandler

	// desktop2 extensions
	AppPrinter            *AppPrinter
	SearchFilterHandler   *SearchFilterHandler
	SearchPropertyHandler *SearchPropertyHandler
	FirewallRules         *FirewallRules
	DesktopEventLogging   *DesktopEventLogging

	// desktop3 extensions
	AutoPlayHandler *AutoPlayHandler
	CloudFiles      *CloudFiles

	// desktop4 extensions
	FileExplorerContextMenus *FileExplorerContextMenus

	// desktop6 extensions
	Service *DesktopService

	// desktop7 extensions
	ApprovedShellExtension  *ApprovedShellExtension
	ControlPanelItem        *ControlPanelItem
	ServiceDesktop7         *ServiceDesktop7
	Shortcut                *Shortcut
	ApplicationRegistration *ApplicationRegistration
	DesktopAppMigration     *DesktopAppMigration
	SystemFileAssociation   *SystemFileAssociation

	// desktop9 extensions
	FileExplorerClassicContextMenuHandler            *FileExplorerClassicContextMenuHandler
	FileExplorerClassicDragDropContextMenuHandler     *FileExplorerClassicDragDropContextMenuHandler

	// com extensions
	ComServer    *ComServer
	ComInterface *ComInterface

	// rescap extensions
	DesktopAppMigrationRescap *DesktopAppMigrationRescap

	// Background tasks
	BackgroundTasks *BackgroundTasks

	// printSupport extensions
	PrintSupportSettingsUI  *PrintSupportSettingsUI
	PrintSupportExtension   *PrintSupportExtension
	PrintSupportJobUI       *PrintSupportJobUI

	// mobile extensions
	MobileMultiScreenProperties   *MobileMultiScreenProperties
	CommunicationBlockingProvider *CommunicationBlockingProvider
	PhoneCallOriginProvider       *PhoneCallOriginProvider
}

// AppointmentsProvider represents uap:AppointmentsProvider.
type AppointmentsProvider struct {
	LaunchActionVerbs []LaunchActionVerb
}

// LaunchActionVerb is a single verb entry.
type LaunchActionVerb struct {
	Verb string
}

// WebAccountProvider represents uap:WebAccountProvider.
type WebAccountProvider struct {
	URL        string
	BackgroundEntryPoint string
}
