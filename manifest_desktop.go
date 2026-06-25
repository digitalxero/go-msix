package msix

// --- desktop namespace extensions ---

// fullTrustProcessData represents desktop:FullTrustProcess.
type fullTrustProcessData struct {
	GroupID        string
	ParameterGroup *parameterGroupData
}

// parameterGroupData within FullTrustProcess.
type parameterGroupData struct {
	GroupID    string
	Parameters string
}

// desktopStartupTaskData represents desktop:StartupTask.
type desktopStartupTaskData struct {
	TaskID  string
	Enabled bool
}

// toastNotificationActivationData represents desktop:ToastNotificationActivation.
type toastNotificationActivationData struct {
	ToastActivatorCLSID string
}

// searchProtocolHandlerData represents desktop:SearchProtocolHandler.
type searchProtocolHandlerData struct {
	DisplayName string
}

// --- desktop2 namespace extensions ---

// appPrinterData represents desktop2:AppPrinter.
type appPrinterData struct {
	DisplayName string
	Parameters  string
}

// searchFilterHandlerData represents desktop2:SearchFilterHandler.
type searchFilterHandlerData struct {
	CLSID       string
	DisplayName string
}

// searchPropertyHandlerData represents desktop2:SearchPropertyHandler.
type searchPropertyHandlerData struct {
	CLSID       string
	DisplayName string
}

// firewallRulesData represents desktop2:FirewallRules.
type firewallRulesData struct {
	Rules []firewallRuleData
}

// firewallRuleData within FirewallRules.
type firewallRuleData struct {
	Direction     string // "in", "out"
	Protocol      string // "TCP", "UDP"
	Profile       string // "domain", "private", "public", "all"
	LocalPortMin  string
	LocalPortMax  string
	RemotePortMin string
	RemotePortMax string
}

// desktopEventLoggingData represents desktop2:DesktopEventLogging.
type desktopEventLoggingData struct {
	ProviderGUID string
	Channels     []eventLogChannelData
}

// eventLogChannelData within DesktopEventLogging.
type eventLogChannelData struct {
	Name string
}

// --- desktop3 namespace extensions ---

// autoPlayHandlerData represents desktop3:AutoPlayHandler.
type autoPlayHandlerData struct {
	InvokeActions []invokeActionData
}

// invokeActionData within AutoPlayHandler.
type invokeActionData struct {
	ActionDisplayName string
	ProviderCLSID     string
	ContentEvent      string
	DeviceEvent       string
}

// cloudFilesData represents desktop3:CloudFiles.
type cloudFilesData struct {
	IconResource             string
	CustomStateHandler       *customStateHandlerData
	ThumbnailProviderHandler *thumbnailProviderHandlerData
	ExtendedPropertyHandler  *extendedPropertyHandlerData
	BannersHandler           *bannersHandlerData
	ContentUriSource         *contentUriSourceData
}

// customStateHandlerData within CloudFiles.
type customStateHandlerData struct {
	CLSID string
}

// thumbnailProviderHandlerData within CloudFiles.
type thumbnailProviderHandlerData struct {
	CLSID string
}

// extendedPropertyHandlerData within CloudFiles.
type extendedPropertyHandlerData struct {
	CLSID string
}

// bannersHandlerData within CloudFiles.
type bannersHandlerData struct {
	CLSID string
}

// contentUriSourceData within CloudFiles.
type contentUriSourceData struct {
	CLSID string
}

// --- desktop4 namespace extensions ---

// fileExplorerContextMenusData represents desktop4:FileExplorerContextMenus.
type fileExplorerContextMenusData struct {
	ItemTypes []fileExplorerItemTypeData
}

// fileExplorerItemTypeData within FileExplorerContextMenus.
type fileExplorerItemTypeData struct {
	Type  string // file extension or "*"
	Verbs []verbData
}

// verbData within FileExplorerItemType.
type verbData struct {
	ID    string
	CLSID string
}

// --- desktop6 namespace extensions ---

// desktopServiceData represents desktop6:Service.
type desktopServiceData struct {
	Name         string
	StartupType  string // "auto", "manual", "disabled"
	StartAccount string // "localSystem", "localService", "networkService"
}

// --- desktop7 namespace extensions ---

// approvedShellExtensionData represents desktop7:ApprovedShellExtension.
type approvedShellExtensionData struct {
	CLSID string
}

// controlPanelItemData represents desktop7:ControlPanelItem.
type controlPanelItemData struct {
	SystemApplicationName string
}

// serviceDesktop7Data represents desktop7:Service.
type serviceDesktop7Data struct {
	Name         string
	StartupType  string
	StartAccount string
	Arguments    string
}

// shortcutData represents desktop7:Shortcut.
type shortcutData struct {
	File        string
	Icon        string
	Arguments   string
	DisplayName string
	Description string
}

// applicationRegistrationData represents desktop7:ApplicationRegistration.
type applicationRegistrationData struct{}

// desktopAppMigrationData represents desktop7:DesktopAppMigration.
type desktopAppMigrationData struct {
	DesktopApps []desktopAppData
}

// desktopAppData within DesktopAppMigration.
type desktopAppData struct {
	AumID        string
	ShortcutPath string
}

// systemFileAssociationData represents desktop7:SystemFileAssociation.
type systemFileAssociationData struct {
	Extension      string
	FullDetails    string
	PreviewDetails string
	PreviewTitle   string
	TileInfo       string
}

// --- desktop9 namespace extensions ---

// fileExplorerClassicContextMenuHandlerData represents desktop9:FileExplorerClassicContextMenuHandler.
type fileExplorerClassicContextMenuHandlerData struct {
	CLSID string
}

// fileExplorerClassicDragDropContextMenuHandlerData represents desktop9:FileExplorerClassicDragDropContextMenuHandler.
type fileExplorerClassicDragDropContextMenuHandlerData struct {
	CLSID string
}
