package msix

// --- desktop namespace extensions ---

// FullTrustProcess represents desktop:FullTrustProcess.
type FullTrustProcess struct {
	GroupID     string
	ParameterGroup *ParameterGroup
}

// ParameterGroup within FullTrustProcess.
type ParameterGroup struct {
	GroupID    string
	Parameters string
}

// DesktopStartupTask represents desktop:StartupTask.
type DesktopStartupTask struct {
	TaskID  string
	Enabled bool
}

// ToastNotificationActivation represents desktop:ToastNotificationActivation.
type ToastNotificationActivation struct {
	ToastActivatorCLSID string
}

// SearchProtocolHandler represents desktop:SearchProtocolHandler.
type SearchProtocolHandler struct {
	DisplayName string
}

// --- desktop2 namespace extensions ---

// AppPrinter represents desktop2:AppPrinter.
type AppPrinter struct {
	DisplayName     string
	Parameters      string
}

// SearchFilterHandler represents desktop2:SearchFilterHandler.
type SearchFilterHandler struct {
	CLSID       string
	DisplayName string
}

// SearchPropertyHandler represents desktop2:SearchPropertyHandler.
type SearchPropertyHandler struct {
	CLSID       string
	DisplayName string
}

// FirewallRules represents desktop2:FirewallRules.
type FirewallRules struct {
	Rules []FirewallRule
}

// FirewallRule within FirewallRules.
type FirewallRule struct {
	Direction string // "in", "out"
	Protocol  string // "TCP", "UDP"
	Profile   string // "domain", "private", "public", "all"
	LocalPortMin string
	LocalPortMax string
	RemotePortMin string
	RemotePortMax string
}

// DesktopEventLogging represents desktop2:DesktopEventLogging.
type DesktopEventLogging struct {
	ProviderGUID string
	Channels     []EventLogChannel
}

// EventLogChannel within DesktopEventLogging.
type EventLogChannel struct {
	Name string
}

// --- desktop3 namespace extensions ---

// AutoPlayHandler represents desktop3:AutoPlayHandler.
type AutoPlayHandler struct {
	InvokeActions []InvokeAction
}

// InvokeAction within AutoPlayHandler.
type InvokeAction struct {
	ActionDisplayName string
	ProviderCLSID     string
	ContentEvent      string
	DeviceEvent       string
}

// CloudFiles represents desktop3:CloudFiles.
type CloudFiles struct {
	IconResource        string
	CustomStateHandler  *CustomStateHandler
	ThumbnailProviderHandler *ThumbnailProviderHandler
	ExtendedPropertyHandler *ExtendedPropertyHandler
	BannersHandler      *BannersHandler
	ContentUriSource    *ContentUriSource
}

// CustomStateHandler within CloudFiles.
type CustomStateHandler struct {
	CLSID string
}

// ThumbnailProviderHandler within CloudFiles.
type ThumbnailProviderHandler struct {
	CLSID string
}

// ExtendedPropertyHandler within CloudFiles.
type ExtendedPropertyHandler struct {
	CLSID string
}

// BannersHandler within CloudFiles.
type BannersHandler struct {
	CLSID string
}

// ContentUriSource within CloudFiles.
type ContentUriSource struct {
	CLSID string
}

// --- desktop4 namespace extensions ---

// FileExplorerContextMenus represents desktop4:FileExplorerContextMenus.
type FileExplorerContextMenus struct {
	ItemTypes []FileExplorerItemType
}

// FileExplorerItemType within FileExplorerContextMenus.
type FileExplorerItemType struct {
	Type string // file extension or "*"
	Verbs []Verb
}

// Verb within FileExplorerItemType.
type Verb struct {
	ID          string
	CLSID       string
}

// --- desktop6 namespace extensions ---

// DesktopService represents desktop6:Service.
type DesktopService struct {
	Name        string
	StartupType string // "auto", "manual", "disabled"
	StartAccount string // "localSystem", "localService", "networkService"
}

// --- desktop7 namespace extensions ---

// ApprovedShellExtension represents desktop7:ApprovedShellExtension.
type ApprovedShellExtension struct {
	CLSID string
}

// ControlPanelItem represents desktop7:ControlPanelItem.
type ControlPanelItem struct {
	SystemApplicationName string
}

// ServiceDesktop7 represents desktop7:Service.
type ServiceDesktop7 struct {
	Name        string
	StartupType string
	StartAccount string
	Arguments   string
}

// Shortcut represents desktop7:Shortcut.
type Shortcut struct {
	File         string
	Icon         string
	Arguments    string
	DisplayName  string
	Description  string
}

// ApplicationRegistration represents desktop7:ApplicationRegistration.
type ApplicationRegistration struct{}

// DesktopAppMigration represents desktop7:DesktopAppMigration.
type DesktopAppMigration struct {
	DesktopApps []DesktopApp
}

// DesktopApp within DesktopAppMigration.
type DesktopApp struct {
	AumID       string
	ShortcutPath string
}

// SystemFileAssociation represents desktop7:SystemFileAssociation.
type SystemFileAssociation struct {
	Extension string
	FullDetails string
	PreviewDetails string
	PreviewTitle string
	TileInfo string
}

// --- desktop9 namespace extensions ---

// FileExplorerClassicContextMenuHandler represents desktop9:FileExplorerClassicContextMenuHandler.
type FileExplorerClassicContextMenuHandler struct {
	CLSID string
}

// FileExplorerClassicDragDropContextMenuHandler represents desktop9:FileExplorerClassicDragDropContextMenuHandler.
type FileExplorerClassicDragDropContextMenuHandler struct {
	CLSID string
}
