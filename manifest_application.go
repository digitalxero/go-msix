package msix

// applicationData represents a single application entry in the manifest.
type applicationData struct {
	ID             string
	Executable     string
	EntryPoint     string
	StartPage      string // For JavaScript apps
	ResourceGroup  string
	VisualElements visualElementsData
	Extensions     []appExtData
}

// visualElementsData represents the uap:VisualElements for an application.
type visualElementsData struct {
	DisplayName       string
	Description       string
	BackgroundColor   string
	Square150x150Logo string
	Square44x44Logo   string
	AppListEntry      string // "default", "none"
	DefaultTile       *defaultTileData
	SplashScreen      *splashScreenData
}

// defaultTileData represents uap:DefaultTile within VisualElements.
type defaultTileData struct {
	Wide310x150Logo   string
	Square71x71Logo   string
	Square310x310Logo string
	ShortName         string
	ShowNameOnTiles   string // "showOn150x150Logo", "showOnWide310x150Logo", etc.
}

// splashScreenData represents uap:SplashScreen within VisualElements.
type splashScreenData struct {
	Image           string
	BackgroundColor string
}

// appExtData represents an extension within an Application.
// Only one of the typed fields should be non-nil, corresponding to the Category.
type appExtData struct {
	Category string

	// uap extensions
	Protocol            *protocolData
	FileTypeAssociation *fileTypeAssociationData
	ShareTarget         *shareTargetData
	FileOpenPicker      *fileOpenPickerData
	FileSavePicker      *fileSavePickerData
	AutoPlayContent     *autoPlayContentData
	AutoPlayDevice      *autoPlayDeviceData
	AppService          *appServiceData
	DialProtocol        *dialProtocolData
	VoipCall            *voipCallData

	// uap3 extensions
	AppUriHandler           *appUriHandlerData
	AppExtensionHost        *appExtensionHostData
	AppExtension            *appExtensionData
	AppointmentDataProvider *appointmentDataProviderData
	EmailDataProvider       *emailDataProviderData
	ContactDataProvider     *contactDataProviderData

	// uap4 extensions
	SharedFonts              *sharedFontsData
	ContactPanel             *contactPanelData
	MediaCodec               *mediaCodecData
	LoopbackAccessRules      *loopbackAccessRulesData
	DevicePortalProvider     *devicePortalProviderData
	UserDataTaskDataProvider *userDataTaskDataProviderData

	// uap5 extensions
	UserActivity        *userActivityData
	MediaSource         *mediaSourceData
	VideoRendererEffect *videoRendererEffectData
	StartupTask         *startupTaskData
	AppExecutionAlias   *appExecutionAliasData

	// uap6 extensions
	BarcodeScannerProvider *barcodeScannerProviderData

	// uap7 extensions
	SharedFontsUap7          *sharedFontsUap7Data
	EnterpriseDataProtection *enterpriseDataProtectionData

	// uap10 extensions
	ProtocolUap10    *protocolUap10Data
	HostRuntime      *hostRuntimeData
	PackageIntegrity *packageIntegrityData

	// desktop extensions
	FullTrustProcess            *fullTrustProcessData
	DesktopStartupTask          *desktopStartupTaskData
	ToastNotificationActivation *toastNotificationActivationData
	SearchProtocolHandler       *searchProtocolHandlerData

	// desktop2 extensions
	AppPrinter            *appPrinterData
	SearchFilterHandler   *searchFilterHandlerData
	SearchPropertyHandler *searchPropertyHandlerData
	FirewallRules         *firewallRulesData
	DesktopEventLogging   *desktopEventLoggingData

	// desktop3 extensions
	AutoPlayHandler *autoPlayHandlerData
	CloudFiles      *cloudFilesData

	// desktop4 extensions
	FileExplorerContextMenus *fileExplorerContextMenusData

	// desktop6 extensions
	Service *desktopServiceData

	// desktop7 extensions
	ApprovedShellExtension  *approvedShellExtensionData
	ControlPanelItem        *controlPanelItemData
	ServiceDesktop7         *serviceDesktop7Data
	Shortcut                *shortcutData
	ApplicationRegistration *applicationRegistrationData
	DesktopAppMigration     *desktopAppMigrationData
	SystemFileAssociation   *systemFileAssociationData

	// desktop9 extensions
	FileExplorerClassicContextMenuHandler         *fileExplorerClassicContextMenuHandlerData
	FileExplorerClassicDragDropContextMenuHandler *fileExplorerClassicDragDropContextMenuHandlerData

	// com extensions
	ComServer    *comServerData
	ComInterface *comInterfaceData

	// rescap extensions
	DesktopAppMigrationRescap *desktopAppMigrationRescapData

	// Background tasks
	BackgroundTasks *backgroundTasksData

	// printSupport extensions
	PrintSupportSettingsUI *printSupportSettingsUIData
	PrintSupportExtension  *printSupportExtensionData
	PrintSupportJobUI      *printSupportJobUIData

	// mobile extensions
	MobileMultiScreenProperties   *mobileMultiScreenPropertiesData
	CommunicationBlockingProvider *communicationBlockingProviderData
	PhoneCallOriginProvider       *phoneCallOriginProviderData
}

// appointmentsProviderData represents uap:AppointmentsProvider.
type appointmentsProviderData struct {
	LaunchActionVerbs []launchActionVerbData
}

// launchActionVerbData is a single verb entry.
type launchActionVerbData struct {
	Verb string
}

// webAccountProviderData represents uap:WebAccountProvider.
type webAccountProviderData struct {
	URL                  string
	BackgroundEntryPoint string
}
