package msix

// This file defines the public builder API for the application and package
// extensions that the manifest template renders today. Extensions are modeled as
// sealed polymorphic unions: ApplicationExtension / PackageExtension are marker
// interfaces whose unexported method both seals the set and performs translation
// into the internal appExtData / pkgExtData consumed by the template.

// ApplicationExtension is implemented by every application-level extension.
type ApplicationExtension interface {
	toAppExtData() appExtData
}

// PackageExtension is implemented by every package-level extension.
type PackageExtension interface {
	toPkgExtData() pkgExtData
}

// --- shared nested builders ---

// FileType is a supported file type within a file-type association / picker.
type FileType interface{ isFileType() }

// FileTypeBuilder builds a FileType.
type FileTypeBuilder interface {
	WithExtension(string) FileTypeBuilder
	WithContentType(string) FileTypeBuilder
	Build() FileType
}

// NewFileType returns a new FileTypeBuilder.
func NewFileType() FileTypeBuilder { return &fileType{} }

type fileType struct{ d fileTypeData }

func (f *fileType) WithExtension(s string) FileTypeBuilder   { f.d.Extension = s; return f }
func (f *fileType) WithContentType(s string) FileTypeBuilder { f.d.ContentType = s; return f }
func (f *fileType) Build() FileType                          { return f }
func (f *fileType) isFileType()                              {}
func (f *fileType) data() fileTypeData                       { return f.d }

// ComClass is a COM class registration within a COM server.
type ComClass interface{ isComClass() }

// ComClassBuilder builds a ComClass.
type ComClassBuilder interface {
	WithID(string) ComClassBuilder
	WithDisplayName(string) ComClassBuilder
	WithProgID(string) ComClassBuilder
	WithThreadingModel(string) ComClassBuilder
	WithVersionIndependentProgID(string) ComClassBuilder
	AddVerb(id int, displayName string) ComClassBuilder
	Build() ComClass
}

// NewComClass returns a new ComClassBuilder.
func NewComClass() ComClassBuilder { return &comClass{} }

type comClass struct{ d comClassData }

func (c *comClass) WithID(s string) ComClassBuilder          { c.d.ID = s; return c }
func (c *comClass) WithDisplayName(s string) ComClassBuilder { c.d.DisplayName = s; return c }
func (c *comClass) WithProgID(s string) ComClassBuilder      { c.d.ProgID = s; return c }
func (c *comClass) WithThreadingModel(s string) ComClassBuilder {
	c.d.ThreadingModel = s
	return c
}
func (c *comClass) WithVersionIndependentProgID(s string) ComClassBuilder {
	c.d.VersionIndependentProgID = s
	return c
}
func (c *comClass) AddVerb(id int, displayName string) ComClassBuilder {
	c.d.Verbs = append(c.d.Verbs, comVerbData{ID: id, DisplayName: displayName})
	return c
}
func (c *comClass) Build() ComClass    { return c }
func (c *comClass) isComClass()        {}
func (c *comClass) data() comClassData { return c.d }

func comClassDatas(classes []ComClass) []comClassData {
	var out []comClassData
	for _, c := range classes {
		out = append(out, c.(*comClass).data())
	}
	return out
}

// ExeServer is a com:ExeServer within a COM server.
type ExeServer interface{ isExeServer() }

// ExeServerBuilder builds an ExeServer.
type ExeServerBuilder interface {
	WithExecutable(string) ExeServerBuilder
	WithDisplayName(string) ExeServerBuilder
	WithLaunchAndActivationPermission(string) ExeServerBuilder
	AddClass(ComClass) ExeServerBuilder
	Build() ExeServer
}

// NewExeServer returns a new ExeServerBuilder.
func NewExeServer() ExeServerBuilder { return &exeServer{} }

type exeServer struct {
	executable string
	display    string
	perm       string
	classes    []ComClass
}

func (s *exeServer) WithExecutable(v string) ExeServerBuilder  { s.executable = v; return s }
func (s *exeServer) WithDisplayName(v string) ExeServerBuilder { s.display = v; return s }
func (s *exeServer) WithLaunchAndActivationPermission(v string) ExeServerBuilder {
	s.perm = v
	return s
}
func (s *exeServer) AddClass(c ComClass) ExeServerBuilder { s.classes = append(s.classes, c); return s }
func (s *exeServer) Build() ExeServer                     { return s }
func (s *exeServer) isExeServer()                         {}
func (s *exeServer) data() exeServerData {
	return exeServerData{
		Executable:                    s.executable,
		DisplayName:                   s.display,
		LaunchAndActivationPermission: s.perm,
		Classes:                       comClassDatas(s.classes),
	}
}

// SurrogateServer is a com:SurrogateServer within a COM server.
type SurrogateServer interface{ isSurrogateServer() }

// SurrogateServerBuilder builds a SurrogateServer.
type SurrogateServerBuilder interface {
	WithDisplayName(string) SurrogateServerBuilder
	WithAppID(string) SurrogateServerBuilder
	AddClass(ComClass) SurrogateServerBuilder
	Build() SurrogateServer
}

// NewSurrogateServer returns a new SurrogateServerBuilder.
func NewSurrogateServer() SurrogateServerBuilder { return &surrogateServer{} }

type surrogateServer struct {
	display string
	appID   string
	classes []ComClass
}

func (s *surrogateServer) WithDisplayName(v string) SurrogateServerBuilder { s.display = v; return s }
func (s *surrogateServer) WithAppID(v string) SurrogateServerBuilder       { s.appID = v; return s }
func (s *surrogateServer) AddClass(c ComClass) SurrogateServerBuilder {
	s.classes = append(s.classes, c)
	return s
}
func (s *surrogateServer) Build() SurrogateServer { return s }
func (s *surrogateServer) isSurrogateServer()     {}
func (s *surrogateServer) data() surrogateServerData {
	return surrogateServerData{DisplayName: s.display, AppID: s.appID, Classes: comClassDatas(s.classes)}
}

// InProcessServer is a com:InProcessServer within a COM server.
type InProcessServer interface{ isInProcessServer() }

// InProcessServerBuilder builds an InProcessServer.
type InProcessServerBuilder interface {
	WithPath(string) InProcessServerBuilder
	AddClass(ComClass) InProcessServerBuilder
	Build() InProcessServer
}

// NewInProcessServer returns a new InProcessServerBuilder.
func NewInProcessServer() InProcessServerBuilder { return &inProcessServer{} }

type inProcessServer struct {
	path    string
	classes []ComClass
}

func (s *inProcessServer) WithPath(v string) InProcessServerBuilder { s.path = v; return s }
func (s *inProcessServer) AddClass(c ComClass) InProcessServerBuilder {
	s.classes = append(s.classes, c)
	return s
}
func (s *inProcessServer) Build() InProcessServer { return s }
func (s *inProcessServer) isInProcessServer()     {}
func (s *inProcessServer) data() inProcessServerData {
	return inProcessServerData{Path: s.path, Classes: comClassDatas(s.classes)}
}

// comServerCommon holds the shared one-of for ComServer (app) and ComServerPkg.
type comServerCommon struct {
	exe       ExeServer
	surrogate SurrogateServer
	inproc    InProcessServer
}

func (c *comServerCommon) data() comServerData {
	out := comServerData{}
	if c.exe != nil {
		d := c.exe.(*exeServer).data()
		out.ExeServer = &d
	}
	if c.surrogate != nil {
		d := c.surrogate.(*surrogateServer).data()
		out.SurrogateServer = &d
	}
	if c.inproc != nil {
		d := c.inproc.(*inProcessServer).data()
		out.InProcessServer = &d
	}
	return out
}

// InterfaceEntry is a com:Interface registration.
type InterfaceEntry interface{ isInterfaceEntry() }

// InterfaceEntryBuilder builds an InterfaceEntry.
type InterfaceEntryBuilder interface {
	WithID(string) InterfaceEntryBuilder
	WithProxyStubCLSID(string) InterfaceEntryBuilder
	WithProxyStubCLSID32(string) InterfaceEntryBuilder
	WithTypeLibID(string) InterfaceEntryBuilder
	WithTypeLibVersion(string) InterfaceEntryBuilder
	Build() InterfaceEntry
}

// NewInterfaceEntry returns a new InterfaceEntryBuilder.
func NewInterfaceEntry() InterfaceEntryBuilder { return &interfaceEntry{} }

type interfaceEntry struct{ d interfaceEntryData }

func (e *interfaceEntry) WithID(s string) InterfaceEntryBuilder { e.d.ID = s; return e }
func (e *interfaceEntry) WithProxyStubCLSID(s string) InterfaceEntryBuilder {
	e.d.ProxyStubCLSID = s
	return e
}
func (e *interfaceEntry) WithProxyStubCLSID32(s string) InterfaceEntryBuilder {
	e.d.ProxyStubCLSID32 = s
	return e
}
func (e *interfaceEntry) WithTypeLibID(s string) InterfaceEntryBuilder { e.d.TypeLibID = s; return e }
func (e *interfaceEntry) WithTypeLibVersion(s string) InterfaceEntryBuilder {
	e.d.TypeLibVersion = s
	return e
}
func (e *interfaceEntry) Build() InterfaceEntry    { return e }
func (e *interfaceEntry) isInterfaceEntry()        {}
func (e *interfaceEntry) data() interfaceEntryData { return e.d }

// ProxyStub is a com:ProxyStub registration.
type ProxyStub interface{ isProxyStub() }

// ProxyStubBuilder builds a ProxyStub.
type ProxyStubBuilder interface {
	WithID(string) ProxyStubBuilder
	WithDisplayName(string) ProxyStubBuilder
	WithPath(string) ProxyStubBuilder
	WithPath32(string) ProxyStubBuilder
	Build() ProxyStub
}

// NewProxyStub returns a new ProxyStubBuilder.
func NewProxyStub() ProxyStubBuilder { return &proxyStub{} }

type proxyStub struct{ d proxyStubData }

func (p *proxyStub) WithID(s string) ProxyStubBuilder          { p.d.ID = s; return p }
func (p *proxyStub) WithDisplayName(s string) ProxyStubBuilder { p.d.DisplayName = s; return p }
func (p *proxyStub) WithPath(s string) ProxyStubBuilder        { p.d.Path = s; return p }
func (p *proxyStub) WithPath32(s string) ProxyStubBuilder      { p.d.Path32 = s; return p }
func (p *proxyStub) Build() ProxyStub                          { return p }
func (p *proxyStub) isProxyStub()                              {}
func (p *proxyStub) data() proxyStubData                       { return p.d }

// Verb is a desktop4 file-explorer context-menu verb.
type Verb interface{ isVerb() }

// VerbBuilder builds a Verb.
type VerbBuilder interface {
	WithID(string) VerbBuilder
	WithCLSID(string) VerbBuilder
	Build() Verb
}

// NewVerb returns a new VerbBuilder.
func NewVerb() VerbBuilder { return &verb{} }

type verb struct{ d verbData }

func (v *verb) WithID(s string) VerbBuilder    { v.d.ID = s; return v }
func (v *verb) WithCLSID(s string) VerbBuilder { v.d.CLSID = s; return v }
func (v *verb) Build() Verb                    { return v }
func (v *verb) isVerb()                        {}
func (v *verb) data() verbData                 { return v.d }

// FileExplorerItemType is an item type within a file-explorer context menu.
type FileExplorerItemType interface{ isFileExplorerItemType() }

// FileExplorerItemTypeBuilder builds a FileExplorerItemType.
type FileExplorerItemTypeBuilder interface {
	WithType(string) FileExplorerItemTypeBuilder
	AddVerb(Verb) FileExplorerItemTypeBuilder
	Build() FileExplorerItemType
}

// NewFileExplorerItemType returns a new FileExplorerItemTypeBuilder.
func NewFileExplorerItemType() FileExplorerItemTypeBuilder { return &fileExplorerItemType{} }

type fileExplorerItemType struct {
	typ   string
	verbs []Verb
}

func (t *fileExplorerItemType) WithType(s string) FileExplorerItemTypeBuilder { t.typ = s; return t }
func (t *fileExplorerItemType) AddVerb(v Verb) FileExplorerItemTypeBuilder {
	t.verbs = append(t.verbs, v)
	return t
}
func (t *fileExplorerItemType) Build() FileExplorerItemType { return t }
func (t *fileExplorerItemType) isFileExplorerItemType()     {}
func (t *fileExplorerItemType) data() fileExplorerItemTypeData {
	out := fileExplorerItemTypeData{Type: t.typ}
	for _, v := range t.verbs {
		out.Verbs = append(out.Verbs, v.(*verb).data())
	}
	return out
}

// --- application extensions (rendered) ---

// Protocol is the uap:Protocol application extension.
type Protocol interface{ ApplicationExtension }

// ProtocolBuilder builds a Protocol extension.
type ProtocolBuilder interface {
	WithName(string) ProtocolBuilder
	WithDisplayName(string) ProtocolBuilder
	WithLogo(string) ProtocolBuilder
	Build() Protocol
}

// NewProtocol returns a new ProtocolBuilder.
func NewProtocol() ProtocolBuilder { return &protocolExt{} }

type protocolExt struct{ d protocolData }

func (p *protocolExt) WithName(s string) ProtocolBuilder        { p.d.Name = s; return p }
func (p *protocolExt) WithDisplayName(s string) ProtocolBuilder { p.d.DisplayName = s; return p }
func (p *protocolExt) WithLogo(s string) ProtocolBuilder        { p.d.Logo = s; return p }
func (p *protocolExt) Build() Protocol                          { return p }
func (p *protocolExt) toAppExtData() appExtData {
	d := p.d
	return appExtData{Category: "windows.protocol", Protocol: &d}
}

// FileTypeAssociation is the uap:FileTypeAssociation application extension.
type FileTypeAssociation interface{ ApplicationExtension }

// FileTypeAssociationBuilder builds a FileTypeAssociation extension.
type FileTypeAssociationBuilder interface {
	WithName(string) FileTypeAssociationBuilder
	WithDisplayName(string) FileTypeAssociationBuilder
	WithLogo(string) FileTypeAssociationBuilder
	WithInfoTip(string) FileTypeAssociationBuilder
	WithDesiredView(string) FileTypeAssociationBuilder
	AddSupportedFileType(FileType) FileTypeAssociationBuilder
	Build() FileTypeAssociation
}

// NewFileTypeAssociation returns a new FileTypeAssociationBuilder.
func NewFileTypeAssociation() FileTypeAssociationBuilder { return &fileTypeAssociationExt{} }

type fileTypeAssociationExt struct {
	d         fileTypeAssociationData
	fileTypes []FileType
}

func (f *fileTypeAssociationExt) WithName(s string) FileTypeAssociationBuilder {
	f.d.Name = s
	return f
}
func (f *fileTypeAssociationExt) WithDisplayName(s string) FileTypeAssociationBuilder {
	f.d.DisplayName = s
	return f
}
func (f *fileTypeAssociationExt) WithLogo(s string) FileTypeAssociationBuilder {
	f.d.Logo = s
	return f
}
func (f *fileTypeAssociationExt) WithInfoTip(s string) FileTypeAssociationBuilder {
	f.d.InfoTip = s
	return f
}
func (f *fileTypeAssociationExt) WithDesiredView(s string) FileTypeAssociationBuilder {
	f.d.DesiredView = s
	return f
}
func (f *fileTypeAssociationExt) AddSupportedFileType(t FileType) FileTypeAssociationBuilder {
	f.fileTypes = append(f.fileTypes, t)
	return f
}
func (f *fileTypeAssociationExt) Build() FileTypeAssociation { return f }
func (f *fileTypeAssociationExt) toAppExtData() appExtData {
	d := f.d
	for _, t := range f.fileTypes {
		d.SupportedFileTypes = append(d.SupportedFileTypes, t.(*fileType).data())
	}
	return appExtData{Category: "windows.fileTypeAssociation", FileTypeAssociation: &d}
}

// ShareTarget is the uap:ShareTarget application extension.
type ShareTarget interface{ ApplicationExtension }

// ShareTargetBuilder builds a ShareTarget extension.
type ShareTargetBuilder interface {
	AddSupportedFileType(FileType) ShareTargetBuilder
	AddDataFormat(format string) ShareTargetBuilder
	Build() ShareTarget
}

// NewShareTarget returns a new ShareTargetBuilder.
func NewShareTarget() ShareTargetBuilder { return &shareTargetExt{} }

type shareTargetExt struct {
	fileTypes []FileType
	formats   []string
}

func (s *shareTargetExt) AddSupportedFileType(t FileType) ShareTargetBuilder {
	s.fileTypes = append(s.fileTypes, t)
	return s
}
func (s *shareTargetExt) AddDataFormat(format string) ShareTargetBuilder {
	s.formats = append(s.formats, format)
	return s
}
func (s *shareTargetExt) Build() ShareTarget { return s }
func (s *shareTargetExt) toAppExtData() appExtData {
	d := shareTargetData{}
	for _, t := range s.fileTypes {
		d.SupportedFileTypes = append(d.SupportedFileTypes, t.(*fileType).data())
	}
	for _, f := range s.formats {
		d.DataFormats = append(d.DataFormats, dataFormatData{Format: f})
	}
	return appExtData{Category: "windows.shareTarget", ShareTarget: &d}
}

// AppService is the uap:AppService application extension.
type AppService interface{ ApplicationExtension }

// AppServiceBuilder builds an AppService extension.
type AppServiceBuilder interface {
	WithName(string) AppServiceBuilder
	WithServerName(string) AppServiceBuilder
	WithSupportsRemoteSystemsEnum(bool) AppServiceBuilder
	Build() AppService
}

// NewAppService returns a new AppServiceBuilder.
func NewAppService() AppServiceBuilder { return &appServiceExt{} }

type appServiceExt struct{ d appServiceData }

func (a *appServiceExt) WithName(s string) AppServiceBuilder       { a.d.Name = s; return a }
func (a *appServiceExt) WithServerName(s string) AppServiceBuilder { a.d.ServerName = s; return a }
func (a *appServiceExt) WithSupportsRemoteSystemsEnum(v bool) AppServiceBuilder {
	a.d.SupportsRemoteSystemsEnum = v
	return a
}
func (a *appServiceExt) Build() AppService { return a }
func (a *appServiceExt) toAppExtData() appExtData {
	d := a.d
	return appExtData{Category: "windows.appService", AppService: &d}
}

// AppExecutionAlias is the uap5:AppExecutionAlias application extension.
type AppExecutionAlias interface{ ApplicationExtension }

// AppExecutionAliasBuilder builds an AppExecutionAlias extension.
type AppExecutionAliasBuilder interface {
	AddAlias(alias string) AppExecutionAliasBuilder
	Build() AppExecutionAlias
}

// NewAppExecutionAlias returns a new AppExecutionAliasBuilder.
func NewAppExecutionAlias() AppExecutionAliasBuilder { return &appExecutionAliasExt{} }

type appExecutionAliasExt struct{ aliases []string }

func (a *appExecutionAliasExt) AddAlias(alias string) AppExecutionAliasBuilder {
	a.aliases = append(a.aliases, alias)
	return a
}
func (a *appExecutionAliasExt) Build() AppExecutionAlias { return a }
func (a *appExecutionAliasExt) toAppExtData() appExtData {
	d := appExecutionAliasData{}
	for _, al := range a.aliases {
		d.ExecutionAliases = append(d.ExecutionAliases, executionAliasData{Alias: al})
	}
	return appExtData{Category: "windows.appExecutionAlias", AppExecutionAlias: &d}
}

// StartupTask is the uap5:StartupTask application extension.
type StartupTask interface{ ApplicationExtension }

// StartupTaskBuilder builds a StartupTask extension.
type StartupTaskBuilder interface {
	WithTaskID(string) StartupTaskBuilder
	WithEnabled(bool) StartupTaskBuilder
	WithDisplayName(string) StartupTaskBuilder
	Build() StartupTask
}

// NewStartupTask returns a new StartupTaskBuilder.
func NewStartupTask() StartupTaskBuilder { return &startupTaskExt{} }

type startupTaskExt struct{ d startupTaskData }

func (s *startupTaskExt) WithTaskID(v string) StartupTaskBuilder { s.d.TaskID = v; return s }
func (s *startupTaskExt) WithEnabled(v bool) StartupTaskBuilder  { s.d.Enabled = v; return s }
func (s *startupTaskExt) WithDisplayName(v string) StartupTaskBuilder {
	s.d.DisplayName = v
	return s
}
func (s *startupTaskExt) Build() StartupTask { return s }
func (s *startupTaskExt) toAppExtData() appExtData {
	d := s.d
	return appExtData{Category: "windows.startupTask", StartupTask: &d}
}

// AppUriHandler is the uap3:AppUriHandler application extension.
type AppUriHandler interface{ ApplicationExtension }

// AppUriHandlerBuilder builds an AppUriHandler extension.
type AppUriHandlerBuilder interface {
	AddHost(name string) AppUriHandlerBuilder
	Build() AppUriHandler
}

// NewAppUriHandler returns a new AppUriHandlerBuilder.
func NewAppUriHandler() AppUriHandlerBuilder { return &appUriHandlerExt{} }

type appUriHandlerExt struct{ hosts []string }

func (a *appUriHandlerExt) AddHost(name string) AppUriHandlerBuilder {
	a.hosts = append(a.hosts, name)
	return a
}
func (a *appUriHandlerExt) Build() AppUriHandler { return a }
func (a *appUriHandlerExt) toAppExtData() appExtData {
	d := appUriHandlerData{}
	for _, h := range a.hosts {
		d.Hosts = append(d.Hosts, appUriHandlerHostData{Name: h})
	}
	return appExtData{Category: "windows.appUriHandler", AppUriHandler: &d}
}

// AppExtensionHost is the uap3:AppExtensionHost application extension.
type AppExtensionHost interface{ ApplicationExtension }

// AppExtensionHostBuilder builds an AppExtensionHost extension.
type AppExtensionHostBuilder interface {
	AddName(name string) AppExtensionHostBuilder
	Build() AppExtensionHost
}

// NewAppExtensionHost returns a new AppExtensionHostBuilder.
func NewAppExtensionHost() AppExtensionHostBuilder { return &appExtensionHostExt{} }

type appExtensionHostExt struct{ names []string }

func (a *appExtensionHostExt) AddName(name string) AppExtensionHostBuilder {
	a.names = append(a.names, name)
	return a
}
func (a *appExtensionHostExt) Build() AppExtensionHost { return a }
func (a *appExtensionHostExt) toAppExtData() appExtData {
	d := appExtensionHostData{}
	for _, n := range a.names {
		d.Names = append(d.Names, appExtensionNameData{Name: n})
	}
	return appExtData{Category: "windows.appExtensionHost", AppExtensionHost: &d}
}

// AppExtension is the uap3:AppExtension application extension.
type AppExtension interface{ ApplicationExtension }

// AppExtensionBuilder builds an AppExtension extension.
type AppExtensionBuilder interface {
	WithName(string) AppExtensionBuilder
	WithID(string) AppExtensionBuilder
	WithDisplayName(string) AppExtensionBuilder
	WithDescription(string) AppExtensionBuilder
	WithPublicFolder(string) AppExtensionBuilder
	Build() AppExtension
}

// NewAppExtension returns a new AppExtensionBuilder.
func NewAppExtension() AppExtensionBuilder { return &appExtensionExt{} }

type appExtensionExt struct{ d appExtensionData }

func (a *appExtensionExt) WithName(s string) AppExtensionBuilder { a.d.Name = s; return a }
func (a *appExtensionExt) WithID(s string) AppExtensionBuilder   { a.d.ID = s; return a }
func (a *appExtensionExt) WithDisplayName(s string) AppExtensionBuilder {
	a.d.DisplayName = s
	return a
}
func (a *appExtensionExt) WithDescription(s string) AppExtensionBuilder {
	a.d.Description = s
	return a
}
func (a *appExtensionExt) WithPublicFolder(s string) AppExtensionBuilder {
	a.d.PublicFolder = s
	return a
}
func (a *appExtensionExt) Build() AppExtension { return a }
func (a *appExtensionExt) toAppExtData() appExtData {
	d := a.d
	return appExtData{Category: "windows.appExtension", AppExtension: &d}
}

// FullTrustProcess is the desktop:FullTrustProcess application extension.
type FullTrustProcess interface{ ApplicationExtension }

// FullTrustProcessBuilder builds a FullTrustProcess extension.
type FullTrustProcessBuilder interface {
	WithGroupID(string) FullTrustProcessBuilder
	WithParameterGroup(groupID, parameters string) FullTrustProcessBuilder
	Build() FullTrustProcess
}

// NewFullTrustProcess returns a new FullTrustProcessBuilder.
func NewFullTrustProcess() FullTrustProcessBuilder { return &fullTrustProcessExt{} }

type fullTrustProcessExt struct {
	groupID string
	pg      *parameterGroupData
}

func (f *fullTrustProcessExt) WithGroupID(s string) FullTrustProcessBuilder { f.groupID = s; return f }
func (f *fullTrustProcessExt) WithParameterGroup(groupID, parameters string) FullTrustProcessBuilder {
	f.pg = &parameterGroupData{GroupID: groupID, Parameters: parameters}
	return f
}
func (f *fullTrustProcessExt) Build() FullTrustProcess { return f }
func (f *fullTrustProcessExt) toAppExtData() appExtData {
	d := fullTrustProcessData{GroupID: f.groupID, ParameterGroup: f.pg}
	return appExtData{Category: "windows.fullTrustProcess", FullTrustProcess: &d}
}

// ToastNotificationActivation is the desktop:ToastNotificationActivation extension.
type ToastNotificationActivation interface{ ApplicationExtension }

// ToastNotificationActivationBuilder builds a ToastNotificationActivation extension.
type ToastNotificationActivationBuilder interface {
	WithToastActivatorCLSID(string) ToastNotificationActivationBuilder
	Build() ToastNotificationActivation
}

// NewToastNotificationActivation returns a new ToastNotificationActivationBuilder.
func NewToastNotificationActivation() ToastNotificationActivationBuilder {
	return &toastNotificationActivationExt{}
}

type toastNotificationActivationExt struct{ clsid string }

func (t *toastNotificationActivationExt) WithToastActivatorCLSID(s string) ToastNotificationActivationBuilder {
	t.clsid = s
	return t
}
func (t *toastNotificationActivationExt) Build() ToastNotificationActivation { return t }
func (t *toastNotificationActivationExt) toAppExtData() appExtData {
	d := toastNotificationActivationData{ToastActivatorCLSID: t.clsid}
	return appExtData{Category: "windows.toastNotificationActivation", ToastNotificationActivation: &d}
}

// ComServer is the com:ComServer application extension.
type ComServer interface{ ApplicationExtension }

// ComServerBuilder builds a ComServer extension.
type ComServerBuilder interface {
	WithExeServer(ExeServer) ComServerBuilder
	WithSurrogateServer(SurrogateServer) ComServerBuilder
	WithInProcessServer(InProcessServer) ComServerBuilder
	Build() ComServer
}

// NewComServer returns a new ComServerBuilder.
func NewComServer() ComServerBuilder { return &comServerExt{} }

type comServerExt struct{ comServerCommon }

func (c *comServerExt) WithExeServer(s ExeServer) ComServerBuilder { c.exe = s; return c }
func (c *comServerExt) WithSurrogateServer(s SurrogateServer) ComServerBuilder {
	c.surrogate = s
	return c
}
func (c *comServerExt) WithInProcessServer(s InProcessServer) ComServerBuilder {
	c.inproc = s
	return c
}
func (c *comServerExt) Build() ComServer { return c }
func (c *comServerExt) toAppExtData() appExtData {
	d := c.data()
	return appExtData{Category: "windows.comServer", ComServer: &d}
}

// ComInterface is the com:ComInterface application extension.
type ComInterface interface{ ApplicationExtension }

// ComInterfaceBuilder builds a ComInterface extension.
type ComInterfaceBuilder interface {
	AddInterface(InterfaceEntry) ComInterfaceBuilder
	AddProxyStub(ProxyStub) ComInterfaceBuilder
	Build() ComInterface
}

// NewComInterface returns a new ComInterfaceBuilder.
func NewComInterface() ComInterfaceBuilder { return &comInterfaceExt{} }

type comInterfaceExt struct {
	interfaces []InterfaceEntry
	proxyStubs []ProxyStub
}

func (c *comInterfaceExt) AddInterface(e InterfaceEntry) ComInterfaceBuilder {
	c.interfaces = append(c.interfaces, e)
	return c
}
func (c *comInterfaceExt) AddProxyStub(p ProxyStub) ComInterfaceBuilder {
	c.proxyStubs = append(c.proxyStubs, p)
	return c
}
func (c *comInterfaceExt) Build() ComInterface { return c }
func (c *comInterfaceExt) toAppExtData() appExtData {
	d := comInterfaceData{}
	for _, e := range c.interfaces {
		d.Interfaces = append(d.Interfaces, e.(*interfaceEntry).data())
	}
	for _, p := range c.proxyStubs {
		d.ProxyStubs = append(d.ProxyStubs, p.(*proxyStub).data())
	}
	return appExtData{Category: "windows.comInterface", ComInterface: &d}
}

// Service is the desktop6:Service application extension.
type Service interface{ ApplicationExtension }

// ServiceBuilder builds a Service extension.
type ServiceBuilder interface {
	WithName(string) ServiceBuilder
	WithStartupType(string) ServiceBuilder
	WithStartAccount(string) ServiceBuilder
	Build() Service
}

// NewService returns a new ServiceBuilder.
func NewService() ServiceBuilder { return &serviceExt{} }

type serviceExt struct{ d desktopServiceData }

func (s *serviceExt) WithName(v string) ServiceBuilder         { s.d.Name = v; return s }
func (s *serviceExt) WithStartupType(v string) ServiceBuilder  { s.d.StartupType = v; return s }
func (s *serviceExt) WithStartAccount(v string) ServiceBuilder { s.d.StartAccount = v; return s }
func (s *serviceExt) Build() Service                           { return s }
func (s *serviceExt) toAppExtData() appExtData {
	d := s.d
	return appExtData{Category: "windows.service", Service: &d}
}

// FileExplorerContextMenus is the desktop4:FileExplorerContextMenus extension.
type FileExplorerContextMenus interface{ ApplicationExtension }

// FileExplorerContextMenusBuilder builds a FileExplorerContextMenus extension.
type FileExplorerContextMenusBuilder interface {
	AddItemType(FileExplorerItemType) FileExplorerContextMenusBuilder
	Build() FileExplorerContextMenus
}

// NewFileExplorerContextMenus returns a new FileExplorerContextMenusBuilder.
func NewFileExplorerContextMenus() FileExplorerContextMenusBuilder {
	return &fileExplorerContextMenusExt{}
}

type fileExplorerContextMenusExt struct{ items []FileExplorerItemType }

func (f *fileExplorerContextMenusExt) AddItemType(t FileExplorerItemType) FileExplorerContextMenusBuilder {
	f.items = append(f.items, t)
	return f
}
func (f *fileExplorerContextMenusExt) Build() FileExplorerContextMenus { return f }
func (f *fileExplorerContextMenusExt) toAppExtData() appExtData {
	d := fileExplorerContextMenusData{}
	for _, t := range f.items {
		d.ItemTypes = append(d.ItemTypes, t.(*fileExplorerItemType).data())
	}
	return appExtData{Category: "windows.fileExplorerContextMenus", FileExplorerContextMenus: &d}
}

// BackgroundTasks is the windows.backgroundTasks application extension.
type BackgroundTasks interface{ ApplicationExtension }

// BackgroundTasksBuilder builds a BackgroundTasks extension.
type BackgroundTasksBuilder interface {
	WithTaskType(string) BackgroundTasksBuilder
	AddTask(taskType string) BackgroundTasksBuilder
	Build() BackgroundTasks
}

// NewBackgroundTasks returns a new BackgroundTasksBuilder.
func NewBackgroundTasks() BackgroundTasksBuilder { return &backgroundTasksExt{} }

type backgroundTasksExt struct {
	taskType string
	tasks    []string
}

func (b *backgroundTasksExt) WithTaskType(s string) BackgroundTasksBuilder { b.taskType = s; return b }
func (b *backgroundTasksExt) AddTask(t string) BackgroundTasksBuilder {
	b.tasks = append(b.tasks, t)
	return b
}
func (b *backgroundTasksExt) Build() BackgroundTasks { return b }
func (b *backgroundTasksExt) toAppExtData() appExtData {
	d := backgroundTasksData{TaskType: b.taskType}
	for _, t := range b.tasks {
		d.Tasks = append(d.Tasks, taskData{Type: t})
	}
	return appExtData{Category: "windows.backgroundTasks", BackgroundTasks: &d}
}

// HostRuntime is the uap10:HostRuntime application extension.
type HostRuntime interface{ ApplicationExtension }

// HostRuntimeBuilder builds a HostRuntime extension.
type HostRuntimeBuilder interface {
	WithID(string) HostRuntimeBuilder
	WithRuntimeBehavior(string) HostRuntimeBuilder
	Build() HostRuntime
}

// NewHostRuntime returns a new HostRuntimeBuilder.
func NewHostRuntime() HostRuntimeBuilder { return &hostRuntimeExt{} }

type hostRuntimeExt struct{ d hostRuntimeData }

func (h *hostRuntimeExt) WithID(s string) HostRuntimeBuilder { h.d.ID = s; return h }
func (h *hostRuntimeExt) WithRuntimeBehavior(s string) HostRuntimeBuilder {
	h.d.RuntimeBehavior = s
	return h
}
func (h *hostRuntimeExt) Build() HostRuntime { return h }
func (h *hostRuntimeExt) toAppExtData() appExtData {
	d := h.d
	return appExtData{Category: "windows.hostRuntime", HostRuntime: &d}
}

// PackageIntegrity is the uap10:PackageIntegrity application extension.
type PackageIntegrity interface{ ApplicationExtension }

// PackageIntegrityBuilder builds a PackageIntegrity extension.
type PackageIntegrityBuilder interface {
	WithEnforcement(string) PackageIntegrityBuilder
	Build() PackageIntegrity
}

// NewPackageIntegrity returns a new PackageIntegrityBuilder.
func NewPackageIntegrity() PackageIntegrityBuilder { return &packageIntegrityExt{} }

type packageIntegrityExt struct{ enforcement string }

func (p *packageIntegrityExt) WithEnforcement(s string) PackageIntegrityBuilder {
	p.enforcement = s
	return p
}
func (p *packageIntegrityExt) Build() PackageIntegrity { return p }
func (p *packageIntegrityExt) toAppExtData() appExtData {
	d := packageIntegrityData{}
	if p.enforcement != "" {
		d.Content = &packageIntegrityContentData{Enforcement: p.enforcement}
	}
	return appExtData{Category: "windows.packageIntegrity", PackageIntegrity: &d}
}

// Shortcut is the desktop7:Shortcut application extension.
type Shortcut interface{ ApplicationExtension }

// ShortcutBuilder builds a Shortcut extension.
type ShortcutBuilder interface {
	WithFile(string) ShortcutBuilder
	WithIcon(string) ShortcutBuilder
	WithArguments(string) ShortcutBuilder
	WithDisplayName(string) ShortcutBuilder
	WithDescription(string) ShortcutBuilder
	Build() Shortcut
}

// NewShortcut returns a new ShortcutBuilder.
func NewShortcut() ShortcutBuilder { return &shortcutExt{} }

type shortcutExt struct{ d shortcutData }

func (s *shortcutExt) WithFile(v string) ShortcutBuilder        { s.d.File = v; return s }
func (s *shortcutExt) WithIcon(v string) ShortcutBuilder        { s.d.Icon = v; return s }
func (s *shortcutExt) WithArguments(v string) ShortcutBuilder   { s.d.Arguments = v; return s }
func (s *shortcutExt) WithDisplayName(v string) ShortcutBuilder { s.d.DisplayName = v; return s }
func (s *shortcutExt) WithDescription(v string) ShortcutBuilder { s.d.Description = v; return s }
func (s *shortcutExt) Build() Shortcut                          { return s }
func (s *shortcutExt) toAppExtData() appExtData {
	d := s.d
	return appExtData{Category: "windows.shortcut", Shortcut: &d}
}

// --- package extensions (rendered) ---

// Certificates is the windows.certificates package extension.
type Certificates interface{ PackageExtension }

// CertificatesBuilder builds a Certificates package extension.
type CertificatesBuilder interface {
	AddCertificate(storeName, content string) CertificatesBuilder
	Build() Certificates
}

// NewCertificates returns a new CertificatesBuilder.
func NewCertificates() CertificatesBuilder { return &certificatesExt{} }

type certificatesExt struct{ entries []certificateEntryData }

func (c *certificatesExt) AddCertificate(storeName, content string) CertificatesBuilder {
	c.entries = append(c.entries, certificateEntryData{StoreName: storeName, Content: content})
	return c
}
func (c *certificatesExt) Build() Certificates { return c }
func (c *certificatesExt) toPkgExtData() pkgExtData {
	d := &certificatesData{Certificate: c.entries}
	return pkgExtData{Category: "windows.certificates", Certificates: d}
}

// ComServerPkg is the com:ComServer package extension.
type ComServerPkg interface{ PackageExtension }

// ComServerPkgBuilder builds a ComServerPkg package extension.
type ComServerPkgBuilder interface {
	WithExeServer(ExeServer) ComServerPkgBuilder
	WithSurrogateServer(SurrogateServer) ComServerPkgBuilder
	WithInProcessServer(InProcessServer) ComServerPkgBuilder
	Build() ComServerPkg
}

// NewComServerPkg returns a new ComServerPkgBuilder.
func NewComServerPkg() ComServerPkgBuilder { return &comServerPkgExt{} }

type comServerPkgExt struct{ comServerCommon }

func (c *comServerPkgExt) WithExeServer(s ExeServer) ComServerPkgBuilder { c.exe = s; return c }
func (c *comServerPkgExt) WithSurrogateServer(s SurrogateServer) ComServerPkgBuilder {
	c.surrogate = s
	return c
}
func (c *comServerPkgExt) WithInProcessServer(s InProcessServer) ComServerPkgBuilder {
	c.inproc = s
	return c
}
func (c *comServerPkgExt) Build() ComServerPkg { return c }
func (c *comServerPkgExt) toPkgExtData() pkgExtData {
	d := c.data()
	return pkgExtData{Category: "windows.comServer", ComServerPkg: &d}
}
