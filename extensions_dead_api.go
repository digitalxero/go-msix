package msix

// This file completes the public builder API for the application and package
// extensions that previously had data structs but no builder or render block.
//
// VERIFICATION STATUS: the 19 originally-rendered extensions (extensions_api.go)
// were the only ones with any prior coverage. The element/attribute shapes and
// Category strings here are derived from the *Data field names and Microsoft's
// MSIX manifest namespace conventions, but most are NOT covered by the makemsix
// integration test (which uses an extension-free manifest). Lines marked
// TODO(verify-xsd) call out specific choices that should be checked against the
// official Microsoft appx manifest XSDs before relying on them in production.

// --- uap namespace extensions ---

// FileOpenPicker is the uap:FileOpenPicker application extension.
type FileOpenPicker interface{ ApplicationExtension }

// FileOpenPickerBuilder builds a FileOpenPicker extension.
type FileOpenPickerBuilder interface {
	AddSupportedFileType(FileType) FileOpenPickerBuilder
	Build() FileOpenPicker
}

// NewFileOpenPicker returns a new FileOpenPickerBuilder.
func NewFileOpenPicker() FileOpenPickerBuilder { return &fileOpenPickerExt{} }

type fileOpenPickerExt struct{ fileTypes []FileType }

func (f *fileOpenPickerExt) AddSupportedFileType(t FileType) FileOpenPickerBuilder {
	f.fileTypes = append(f.fileTypes, t)
	return f
}
func (f *fileOpenPickerExt) Build() FileOpenPicker { return f }
func (f *fileOpenPickerExt) toAppExtData() appExtData {
	d := fileOpenPickerData{}
	for _, t := range f.fileTypes {
		d.SupportedFileTypes = append(d.SupportedFileTypes, t.(*fileType).data())
	}
	return appExtData{Category: "windows.fileOpenPicker", FileOpenPicker: &d}
}

// FileSavePicker is the uap:FileSavePicker application extension.
type FileSavePicker interface{ ApplicationExtension }

// FileSavePickerBuilder builds a FileSavePicker extension.
type FileSavePickerBuilder interface {
	AddSupportedFileType(FileType) FileSavePickerBuilder
	Build() FileSavePicker
}

// NewFileSavePicker returns a new FileSavePickerBuilder.
func NewFileSavePicker() FileSavePickerBuilder { return &fileSavePickerExt{} }

type fileSavePickerExt struct{ fileTypes []FileType }

func (f *fileSavePickerExt) AddSupportedFileType(t FileType) FileSavePickerBuilder {
	f.fileTypes = append(f.fileTypes, t)
	return f
}
func (f *fileSavePickerExt) Build() FileSavePicker { return f }
func (f *fileSavePickerExt) toAppExtData() appExtData {
	d := fileSavePickerData{}
	for _, t := range f.fileTypes {
		d.SupportedFileTypes = append(d.SupportedFileTypes, t.(*fileType).data())
	}
	return appExtData{Category: "windows.fileSavePicker", FileSavePicker: &d}
}

// AutoPlayContent is the uap:AutoPlayContent application extension.
type AutoPlayContent interface{ ApplicationExtension }

// AutoPlayContentBuilder builds an AutoPlayContent extension.
type AutoPlayContentBuilder interface {
	AddLaunchAction(verb, actionDisplayName, contentEvent string) AutoPlayContentBuilder
	Build() AutoPlayContent
}

// NewAutoPlayContent returns a new AutoPlayContentBuilder.
func NewAutoPlayContent() AutoPlayContentBuilder { return &autoPlayContentExt{} }

type autoPlayContentExt struct{ actions []autoPlayLaunchActionData }

func (a *autoPlayContentExt) AddLaunchAction(verb, actionDisplayName, contentEvent string) AutoPlayContentBuilder {
	a.actions = append(a.actions, autoPlayLaunchActionData{Verb: verb, ActionDisplayName: actionDisplayName, ContentEvent: contentEvent})
	return a
}
func (a *autoPlayContentExt) Build() AutoPlayContent { return a }
func (a *autoPlayContentExt) toAppExtData() appExtData {
	d := autoPlayContentData{LaunchActions: a.actions}
	return appExtData{Category: "windows.autoPlayContent", AutoPlayContent: &d}
}

// AutoPlayDevice is the uap:AutoPlayDevice application extension.
type AutoPlayDevice interface{ ApplicationExtension }

// AutoPlayDeviceBuilder builds an AutoPlayDevice extension.
type AutoPlayDeviceBuilder interface {
	AddLaunchAction(verb, actionDisplayName, deviceEvent string) AutoPlayDeviceBuilder
	Build() AutoPlayDevice
}

// NewAutoPlayDevice returns a new AutoPlayDeviceBuilder.
func NewAutoPlayDevice() AutoPlayDeviceBuilder { return &autoPlayDeviceExt{} }

type autoPlayDeviceExt struct {
	actions []autoPlayDeviceLaunchActionData
}

func (a *autoPlayDeviceExt) AddLaunchAction(verb, actionDisplayName, deviceEvent string) AutoPlayDeviceBuilder {
	a.actions = append(a.actions, autoPlayDeviceLaunchActionData{Verb: verb, ActionDisplayName: actionDisplayName, DeviceEvent: deviceEvent})
	return a
}
func (a *autoPlayDeviceExt) Build() AutoPlayDevice { return a }
func (a *autoPlayDeviceExt) toAppExtData() appExtData {
	d := autoPlayDeviceData{LaunchActions: a.actions}
	return appExtData{Category: "windows.autoPlayDevice", AutoPlayDevice: &d}
}

// DialProtocol is the uap:DialProtocol application extension.
type DialProtocol interface{ ApplicationExtension }

// DialProtocolBuilder builds a DialProtocol extension.
type DialProtocolBuilder interface {
	WithName(string) DialProtocolBuilder
	Build() DialProtocol
}

// NewDialProtocol returns a new DialProtocolBuilder.
func NewDialProtocol() DialProtocolBuilder { return &dialProtocolExt{} }

type dialProtocolExt struct{ d dialProtocolData }

func (p *dialProtocolExt) WithName(s string) DialProtocolBuilder { p.d.Name = s; return p }
func (p *dialProtocolExt) Build() DialProtocol                   { return p }
func (p *dialProtocolExt) toAppExtData() appExtData {
	d := p.d
	return appExtData{Category: "windows.dialProtocol", DialProtocol: &d}
}

// VoipCall is the uap:VoipCall application extension.
type VoipCall interface{ ApplicationExtension }

// VoipCallBuilder builds a VoipCall extension.
type VoipCallBuilder interface{ Build() VoipCall }

// NewVoipCall returns a new VoipCallBuilder.
func NewVoipCall() VoipCallBuilder { return &voipCallExt{} }

type voipCallExt struct{}

func (v *voipCallExt) Build() VoipCall { return v }
func (v *voipCallExt) toAppExtData() appExtData {
	return appExtData{Category: "windows.voipCall", VoipCall: &voipCallData{}}
}

// --- uap3 namespace data providers ---
// TODO(verify-xsd): the appointment/email/contact data-provider element + Category
// names are inferred from the *Data field (ServerName) and may need adjustment.

// AppointmentDataProvider is the uap3:AppointmentDataProvider application extension.
type AppointmentDataProvider interface{ ApplicationExtension }

// AppointmentDataProviderBuilder builds an AppointmentDataProvider extension.
type AppointmentDataProviderBuilder interface {
	WithServerName(string) AppointmentDataProviderBuilder
	Build() AppointmentDataProvider
}

// NewAppointmentDataProvider returns a new AppointmentDataProviderBuilder.
func NewAppointmentDataProvider() AppointmentDataProviderBuilder {
	return &appointmentDataProviderExt{}
}

type appointmentDataProviderExt struct{ d appointmentDataProviderData }

func (a *appointmentDataProviderExt) WithServerName(s string) AppointmentDataProviderBuilder {
	a.d.ServerName = s
	return a
}
func (a *appointmentDataProviderExt) Build() AppointmentDataProvider { return a }
func (a *appointmentDataProviderExt) toAppExtData() appExtData {
	d := a.d
	return appExtData{Category: "windows.appointmentsProvider", AppointmentDataProvider: &d}
}

// EmailDataProvider is the uap3:EmailDataProvider application extension.
type EmailDataProvider interface{ ApplicationExtension }

// EmailDataProviderBuilder builds an EmailDataProvider extension.
type EmailDataProviderBuilder interface {
	WithServerName(string) EmailDataProviderBuilder
	Build() EmailDataProvider
}

// NewEmailDataProvider returns a new EmailDataProviderBuilder.
func NewEmailDataProvider() EmailDataProviderBuilder { return &emailDataProviderExt{} }

type emailDataProviderExt struct{ d emailDataProviderData }

func (e *emailDataProviderExt) WithServerName(s string) EmailDataProviderBuilder {
	e.d.ServerName = s
	return e
}
func (e *emailDataProviderExt) Build() EmailDataProvider { return e }
func (e *emailDataProviderExt) toAppExtData() appExtData {
	d := e.d
	return appExtData{Category: "windows.emailDataProvider", EmailDataProvider: &d}
}

// ContactDataProvider is the uap3:ContactDataProvider application extension.
type ContactDataProvider interface{ ApplicationExtension }

// ContactDataProviderBuilder builds a ContactDataProvider extension.
type ContactDataProviderBuilder interface {
	WithServerName(string) ContactDataProviderBuilder
	Build() ContactDataProvider
}

// NewContactDataProvider returns a new ContactDataProviderBuilder.
func NewContactDataProvider() ContactDataProviderBuilder { return &contactDataProviderExt{} }

type contactDataProviderExt struct{ d contactDataProviderData }

func (c *contactDataProviderExt) WithServerName(s string) ContactDataProviderBuilder {
	c.d.ServerName = s
	return c
}
func (c *contactDataProviderExt) Build() ContactDataProvider { return c }
func (c *contactDataProviderExt) toAppExtData() appExtData {
	d := c.d
	return appExtData{Category: "windows.contactDataProvider", ContactDataProvider: &d}
}

// --- uap4 namespace extensions ---

// SharedFonts is the uap4:SharedFonts application extension.
type SharedFonts interface{ ApplicationExtension }

// SharedFontsBuilder builds a SharedFonts extension.
type SharedFontsBuilder interface {
	AddFont(file string) SharedFontsBuilder
	Build() SharedFonts
}

// NewSharedFonts returns a new SharedFontsBuilder.
func NewSharedFonts() SharedFontsBuilder { return &sharedFontsExt{} }

type sharedFontsExt struct{ files []string }

func (s *sharedFontsExt) AddFont(file string) SharedFontsBuilder {
	s.files = append(s.files, file)
	return s
}
func (s *sharedFontsExt) Build() SharedFonts { return s }
func (s *sharedFontsExt) toAppExtData() appExtData {
	d := sharedFontsData{}
	for _, f := range s.files {
		d.Fonts = append(d.Fonts, fontData{File: f})
	}
	return appExtData{Category: "windows.sharedFonts", SharedFonts: &d}
}

// ContactPanel is the uap4:ContactPanel application extension.
// TODO(verify-xsd): Category/element for ContactPanel inferred.
type ContactPanel interface{ ApplicationExtension }

// ContactPanelBuilder builds a ContactPanel extension.
type ContactPanelBuilder interface {
	WithSupportsUnknownContacts(bool) ContactPanelBuilder
	Build() ContactPanel
}

// NewContactPanel returns a new ContactPanelBuilder.
func NewContactPanel() ContactPanelBuilder { return &contactPanelExt{} }

type contactPanelExt struct{ d contactPanelData }

func (c *contactPanelExt) WithSupportsUnknownContacts(v bool) ContactPanelBuilder {
	c.d.SupportsUnknownContacts = v
	return c
}
func (c *contactPanelExt) Build() ContactPanel { return c }
func (c *contactPanelExt) toAppExtData() appExtData {
	d := c.d
	return appExtData{Category: "windows.contactPanel", ContactPanel: &d}
}

// MediaCodec is the uap4:MediaCodec application extension.
// TODO(verify-xsd): MediaCodec element/attribute layout inferred from fields.
type MediaCodec interface{ ApplicationExtension }

// MediaCodecBuilder builds a MediaCodec extension.
type MediaCodecBuilder interface {
	WithDisplayName(string) MediaCodecBuilder
	WithDescription(string) MediaCodecBuilder
	WithCategory(string) MediaCodecBuilder
	AddMediaType(subType string) MediaCodecBuilder
	Build() MediaCodec
}

// NewMediaCodec returns a new MediaCodecBuilder.
func NewMediaCodec() MediaCodecBuilder { return &mediaCodecExt{} }

type mediaCodecExt struct {
	d          mediaCodecData
	mediaTypes []string
}

func (m *mediaCodecExt) WithDisplayName(s string) MediaCodecBuilder { m.d.DisplayName = s; return m }
func (m *mediaCodecExt) WithDescription(s string) MediaCodecBuilder { m.d.Description = s; return m }
func (m *mediaCodecExt) WithCategory(s string) MediaCodecBuilder    { m.d.Category = s; return m }
func (m *mediaCodecExt) AddMediaType(subType string) MediaCodecBuilder {
	m.mediaTypes = append(m.mediaTypes, subType)
	return m
}
func (m *mediaCodecExt) Build() MediaCodec { return m }
func (m *mediaCodecExt) toAppExtData() appExtData {
	d := m.d
	for _, st := range m.mediaTypes {
		d.MediaTypes = append(d.MediaTypes, mediaTypeData{SubType: st})
	}
	return appExtData{Category: "windows.mediaCodec", MediaCodec: &d}
}

// LoopbackAccessRules is the uap4:LoopbackAccessRules application extension.
// TODO(verify-xsd): LoopbackAccessRules element/Category inferred.
type LoopbackAccessRules interface{ ApplicationExtension }

// LoopbackAccessRulesBuilder builds a LoopbackAccessRules extension.
type LoopbackAccessRulesBuilder interface {
	AddRule(direction string) LoopbackAccessRulesBuilder
	Build() LoopbackAccessRules
}

// NewLoopbackAccessRules returns a new LoopbackAccessRulesBuilder.
func NewLoopbackAccessRules() LoopbackAccessRulesBuilder { return &loopbackAccessRulesExt{} }

type loopbackAccessRulesExt struct{ rules []string }

func (l *loopbackAccessRulesExt) AddRule(direction string) LoopbackAccessRulesBuilder {
	l.rules = append(l.rules, direction)
	return l
}
func (l *loopbackAccessRulesExt) Build() LoopbackAccessRules { return l }
func (l *loopbackAccessRulesExt) toAppExtData() appExtData {
	d := loopbackAccessRulesData{}
	for _, r := range l.rules {
		d.Rules = append(d.Rules, loopbackRuleData{Direction: r})
	}
	return appExtData{Category: "windows.loopbackAccessRules", LoopbackAccessRules: &d}
}

// DevicePortalProvider is the uap4:DevicePortalProvider application extension.
type DevicePortalProvider interface{ ApplicationExtension }

// DevicePortalProviderBuilder builds a DevicePortalProvider extension.
type DevicePortalProviderBuilder interface {
	WithDisplayName(string) DevicePortalProviderBuilder
	WithAppServiceName(string) DevicePortalProviderBuilder
	WithContentRoute(string) DevicePortalProviderBuilder
	WithHandlerRoute(string) DevicePortalProviderBuilder
	Build() DevicePortalProvider
}

// NewDevicePortalProvider returns a new DevicePortalProviderBuilder.
func NewDevicePortalProvider() DevicePortalProviderBuilder { return &devicePortalProviderExt{} }

type devicePortalProviderExt struct{ d devicePortalProviderData }

func (d *devicePortalProviderExt) WithDisplayName(s string) DevicePortalProviderBuilder {
	d.d.DisplayName = s
	return d
}
func (d *devicePortalProviderExt) WithAppServiceName(s string) DevicePortalProviderBuilder {
	d.d.AppServiceName = s
	return d
}
func (d *devicePortalProviderExt) WithContentRoute(s string) DevicePortalProviderBuilder {
	d.d.ContentRoute = s
	return d
}
func (d *devicePortalProviderExt) WithHandlerRoute(s string) DevicePortalProviderBuilder {
	d.d.HandlerRoute = s
	return d
}
func (d *devicePortalProviderExt) Build() DevicePortalProvider { return d }
func (d *devicePortalProviderExt) toAppExtData() appExtData {
	dd := d.d
	return appExtData{Category: "windows.devicePortalProvider", DevicePortalProvider: &dd}
}

// UserDataTaskDataProvider is the uap4:UserDataTaskDataProvider application extension.
// TODO(verify-xsd): Category/element inferred.
type UserDataTaskDataProvider interface{ ApplicationExtension }

// UserDataTaskDataProviderBuilder builds a UserDataTaskDataProvider extension.
type UserDataTaskDataProviderBuilder interface {
	WithServerName(string) UserDataTaskDataProviderBuilder
	Build() UserDataTaskDataProvider
}

// NewUserDataTaskDataProvider returns a new UserDataTaskDataProviderBuilder.
func NewUserDataTaskDataProvider() UserDataTaskDataProviderBuilder {
	return &userDataTaskDataProviderExt{}
}

type userDataTaskDataProviderExt struct{ d userDataTaskDataProviderData }

func (u *userDataTaskDataProviderExt) WithServerName(s string) UserDataTaskDataProviderBuilder {
	u.d.ServerName = s
	return u
}
func (u *userDataTaskDataProviderExt) Build() UserDataTaskDataProvider { return u }
func (u *userDataTaskDataProviderExt) toAppExtData() appExtData {
	d := u.d
	return appExtData{Category: "windows.userDataTasks", UserDataTaskDataProvider: &d}
}

// --- uap5 namespace extensions ---

// UserActivity is the uap5:UserActivity application extension.
// TODO(verify-xsd): UserActivity element layout inferred.
type UserActivity interface{ ApplicationExtension }

// UserActivityBuilder builds a UserActivity extension.
type UserActivityBuilder interface {
	WithActivitySourceHost(string) UserActivityBuilder
	Build() UserActivity
}

// NewUserActivity returns a new UserActivityBuilder.
func NewUserActivity() UserActivityBuilder { return &userActivityExt{} }

type userActivityExt struct{ d userActivityData }

func (u *userActivityExt) WithActivitySourceHost(s string) UserActivityBuilder {
	u.d.ActivitySourceHost = s
	return u
}
func (u *userActivityExt) Build() UserActivity { return u }
func (u *userActivityExt) toAppExtData() appExtData {
	d := u.d
	return appExtData{Category: "windows.userActivity", UserActivity: &d}
}

// MediaSource is the uap5:MediaSource application extension.
// TODO(verify-xsd): MediaSource element layout inferred.
type MediaSource interface{ ApplicationExtension }

// MediaSourceBuilder builds a MediaSource extension.
type MediaSourceBuilder interface {
	WithDisplayName(string) MediaSourceBuilder
	AddMediaType(subType string) MediaSourceBuilder
	Build() MediaSource
}

// NewMediaSource returns a new MediaSourceBuilder.
func NewMediaSource() MediaSourceBuilder { return &mediaSourceExt{} }

type mediaSourceExt struct {
	d          mediaSourceData
	mediaTypes []string
}

func (m *mediaSourceExt) WithDisplayName(s string) MediaSourceBuilder { m.d.DisplayName = s; return m }
func (m *mediaSourceExt) AddMediaType(subType string) MediaSourceBuilder {
	m.mediaTypes = append(m.mediaTypes, subType)
	return m
}
func (m *mediaSourceExt) Build() MediaSource { return m }
func (m *mediaSourceExt) toAppExtData() appExtData {
	d := m.d
	for _, st := range m.mediaTypes {
		d.MediaTypes = append(d.MediaTypes, mediaSourceMediaTypeData{SubType: st})
	}
	return appExtData{Category: "windows.mediaSource", MediaSource: &d}
}

// VideoRendererEffect is the uap5:VideoRendererEffect application extension.
// TODO(verify-xsd): VideoRendererEffect element layout inferred.
type VideoRendererEffect interface{ ApplicationExtension }

// VideoRendererEffectBuilder builds a VideoRendererEffect extension.
type VideoRendererEffectBuilder interface {
	WithDisplayName(string) VideoRendererEffectBuilder
	WithActivatableClassID(string) VideoRendererEffectBuilder
	Build() VideoRendererEffect
}

// NewVideoRendererEffect returns a new VideoRendererEffectBuilder.
func NewVideoRendererEffect() VideoRendererEffectBuilder { return &videoRendererEffectExt{} }

type videoRendererEffectExt struct{ d videoRendererEffectData }

func (v *videoRendererEffectExt) WithDisplayName(s string) VideoRendererEffectBuilder {
	v.d.DisplayName = s
	return v
}
func (v *videoRendererEffectExt) WithActivatableClassID(s string) VideoRendererEffectBuilder {
	v.d.ActivatableClassID = s
	return v
}
func (v *videoRendererEffectExt) Build() VideoRendererEffect { return v }
func (v *videoRendererEffectExt) toAppExtData() appExtData {
	d := v.d
	return appExtData{Category: "windows.videoRendererEffect", VideoRendererEffect: &d}
}

// --- uap6 namespace extensions ---

// BarcodeScannerProvider is the uap6:BarcodeScannerProvider application extension.
// TODO(verify-xsd): Category/element for BarcodeScannerProvider inferred.
type BarcodeScannerProvider interface{ ApplicationExtension }

// BarcodeScannerProviderBuilder builds a BarcodeScannerProvider extension.
type BarcodeScannerProviderBuilder interface{ Build() BarcodeScannerProvider }

// NewBarcodeScannerProvider returns a new BarcodeScannerProviderBuilder.
func NewBarcodeScannerProvider() BarcodeScannerProviderBuilder {
	return &barcodeScannerProviderExt{}
}

type barcodeScannerProviderExt struct{}

func (b *barcodeScannerProviderExt) Build() BarcodeScannerProvider { return b }
func (b *barcodeScannerProviderExt) toAppExtData() appExtData {
	return appExtData{Category: "windows.barcodeScanner", BarcodeScannerProvider: &barcodeScannerProviderData{}}
}

// --- uap7 namespace extensions ---

// SharedFontsUap7 is the uap7:SharedFonts application extension.
type SharedFontsUap7 interface{ ApplicationExtension }

// SharedFontsUap7Builder builds a uap7 SharedFonts extension.
type SharedFontsUap7Builder interface {
	AddFont(file string) SharedFontsUap7Builder
	Build() SharedFontsUap7
}

// NewSharedFontsUap7 returns a new SharedFontsUap7Builder.
func NewSharedFontsUap7() SharedFontsUap7Builder { return &sharedFontsUap7Ext{} }

type sharedFontsUap7Ext struct{ files []string }

func (s *sharedFontsUap7Ext) AddFont(file string) SharedFontsUap7Builder {
	s.files = append(s.files, file)
	return s
}
func (s *sharedFontsUap7Ext) Build() SharedFontsUap7 { return s }
func (s *sharedFontsUap7Ext) toAppExtData() appExtData {
	d := sharedFontsUap7Data{}
	for _, f := range s.files {
		d.Fonts = append(d.Fonts, fontData{File: f})
	}
	return appExtData{Category: "windows.sharedFonts", SharedFontsUap7: &d}
}

// EnterpriseDataProtection is the uap7:EnterpriseDataProtection application extension.
// TODO(verify-xsd): element layout inferred.
type EnterpriseDataProtection interface{ ApplicationExtension }

// EnterpriseDataProtectionBuilder builds an EnterpriseDataProtection extension.
type EnterpriseDataProtectionBuilder interface {
	AddProtectionDomain(name string) EnterpriseDataProtectionBuilder
	Build() EnterpriseDataProtection
}

// NewEnterpriseDataProtection returns a new EnterpriseDataProtectionBuilder.
func NewEnterpriseDataProtection() EnterpriseDataProtectionBuilder {
	return &enterpriseDataProtectionExt{}
}

type enterpriseDataProtectionExt struct{ domains []string }

func (e *enterpriseDataProtectionExt) AddProtectionDomain(name string) EnterpriseDataProtectionBuilder {
	e.domains = append(e.domains, name)
	return e
}
func (e *enterpriseDataProtectionExt) Build() EnterpriseDataProtection { return e }
func (e *enterpriseDataProtectionExt) toAppExtData() appExtData {
	d := enterpriseDataProtectionData{}
	for _, n := range e.domains {
		d.ProtectionDomains = append(d.ProtectionDomains, protectionDomainData{Name: n})
	}
	return appExtData{Category: "windows.enterpriseDataProtection", EnterpriseDataProtection: &d}
}

// --- uap10 namespace extensions ---

// ProtocolUap10 is the uap10:Protocol application extension (adds Parameters).
type ProtocolUap10 interface{ ApplicationExtension }

// ProtocolUap10Builder builds a uap10 Protocol extension.
type ProtocolUap10Builder interface {
	WithName(string) ProtocolUap10Builder
	WithParameters(string) ProtocolUap10Builder
	Build() ProtocolUap10
}

// NewProtocolUap10 returns a new ProtocolUap10Builder.
func NewProtocolUap10() ProtocolUap10Builder { return &protocolUap10Ext{} }

type protocolUap10Ext struct{ d protocolUap10Data }

func (p *protocolUap10Ext) WithName(s string) ProtocolUap10Builder { p.d.Name = s; return p }
func (p *protocolUap10Ext) WithParameters(s string) ProtocolUap10Builder {
	p.d.Parameters = s
	return p
}
func (p *protocolUap10Ext) Build() ProtocolUap10 { return p }
func (p *protocolUap10Ext) toAppExtData() appExtData {
	d := p.d
	return appExtData{Category: "windows.protocol", ProtocolUap10: &d}
}

// --- desktop namespace extensions ---

// DesktopStartupTask is the desktop:StartupTask application extension.
type DesktopStartupTask interface{ ApplicationExtension }

// DesktopStartupTaskBuilder builds a desktop StartupTask extension.
type DesktopStartupTaskBuilder interface {
	WithTaskID(string) DesktopStartupTaskBuilder
	WithEnabled(bool) DesktopStartupTaskBuilder
	Build() DesktopStartupTask
}

// NewDesktopStartupTask returns a new DesktopStartupTaskBuilder.
func NewDesktopStartupTask() DesktopStartupTaskBuilder { return &desktopStartupTaskExt{} }

type desktopStartupTaskExt struct{ d desktopStartupTaskData }

func (s *desktopStartupTaskExt) WithTaskID(v string) DesktopStartupTaskBuilder {
	s.d.TaskID = v
	return s
}
func (s *desktopStartupTaskExt) WithEnabled(v bool) DesktopStartupTaskBuilder {
	s.d.Enabled = v
	return s
}
func (s *desktopStartupTaskExt) Build() DesktopStartupTask { return s }
func (s *desktopStartupTaskExt) toAppExtData() appExtData {
	d := s.d
	return appExtData{Category: "windows.startupTask", DesktopStartupTask: &d}
}

// SearchProtocolHandler is the desktop:SearchProtocolHandler application extension.
// TODO(verify-xsd): Category/element inferred.
type SearchProtocolHandler interface{ ApplicationExtension }

// SearchProtocolHandlerBuilder builds a SearchProtocolHandler extension.
type SearchProtocolHandlerBuilder interface {
	WithDisplayName(string) SearchProtocolHandlerBuilder
	Build() SearchProtocolHandler
}

// NewSearchProtocolHandler returns a new SearchProtocolHandlerBuilder.
func NewSearchProtocolHandler() SearchProtocolHandlerBuilder { return &searchProtocolHandlerExt{} }

type searchProtocolHandlerExt struct{ d searchProtocolHandlerData }

func (s *searchProtocolHandlerExt) WithDisplayName(v string) SearchProtocolHandlerBuilder {
	s.d.DisplayName = v
	return s
}
func (s *searchProtocolHandlerExt) Build() SearchProtocolHandler { return s }
func (s *searchProtocolHandlerExt) toAppExtData() appExtData {
	d := s.d
	return appExtData{Category: "windows.searchProtocolHandler", SearchProtocolHandler: &d}
}

// --- desktop2 namespace extensions ---

// AppPrinter is the desktop2:AppPrinter application extension.
type AppPrinter interface{ ApplicationExtension }

// AppPrinterBuilder builds an AppPrinter extension.
type AppPrinterBuilder interface {
	WithDisplayName(string) AppPrinterBuilder
	WithParameters(string) AppPrinterBuilder
	Build() AppPrinter
}

// NewAppPrinter returns a new AppPrinterBuilder.
func NewAppPrinter() AppPrinterBuilder { return &appPrinterExt{} }

type appPrinterExt struct{ d appPrinterData }

func (a *appPrinterExt) WithDisplayName(s string) AppPrinterBuilder { a.d.DisplayName = s; return a }
func (a *appPrinterExt) WithParameters(s string) AppPrinterBuilder  { a.d.Parameters = s; return a }
func (a *appPrinterExt) Build() AppPrinter                          { return a }
func (a *appPrinterExt) toAppExtData() appExtData {
	d := a.d
	return appExtData{Category: "windows.appPrinter", AppPrinter: &d}
}

// SearchFilterHandler is the desktop2:SearchFilterHandler application extension.
// TODO(verify-xsd): Category/element inferred.
type SearchFilterHandler interface{ ApplicationExtension }

// SearchFilterHandlerBuilder builds a SearchFilterHandler extension.
type SearchFilterHandlerBuilder interface {
	WithCLSID(string) SearchFilterHandlerBuilder
	WithDisplayName(string) SearchFilterHandlerBuilder
	Build() SearchFilterHandler
}

// NewSearchFilterHandler returns a new SearchFilterHandlerBuilder.
func NewSearchFilterHandler() SearchFilterHandlerBuilder { return &searchFilterHandlerExt{} }

type searchFilterHandlerExt struct{ d searchFilterHandlerData }

func (s *searchFilterHandlerExt) WithCLSID(v string) SearchFilterHandlerBuilder {
	s.d.CLSID = v
	return s
}
func (s *searchFilterHandlerExt) WithDisplayName(v string) SearchFilterHandlerBuilder {
	s.d.DisplayName = v
	return s
}
func (s *searchFilterHandlerExt) Build() SearchFilterHandler { return s }
func (s *searchFilterHandlerExt) toAppExtData() appExtData {
	d := s.d
	return appExtData{Category: "windows.searchFilterHandler", SearchFilterHandler: &d}
}

// SearchPropertyHandler is the desktop2:SearchPropertyHandler application extension.
// TODO(verify-xsd): Category/element inferred.
type SearchPropertyHandler interface{ ApplicationExtension }

// SearchPropertyHandlerBuilder builds a SearchPropertyHandler extension.
type SearchPropertyHandlerBuilder interface {
	WithCLSID(string) SearchPropertyHandlerBuilder
	WithDisplayName(string) SearchPropertyHandlerBuilder
	Build() SearchPropertyHandler
}

// NewSearchPropertyHandler returns a new SearchPropertyHandlerBuilder.
func NewSearchPropertyHandler() SearchPropertyHandlerBuilder { return &searchPropertyHandlerExt{} }

type searchPropertyHandlerExt struct{ d searchPropertyHandlerData }

func (s *searchPropertyHandlerExt) WithCLSID(v string) SearchPropertyHandlerBuilder {
	s.d.CLSID = v
	return s
}
func (s *searchPropertyHandlerExt) WithDisplayName(v string) SearchPropertyHandlerBuilder {
	s.d.DisplayName = v
	return s
}
func (s *searchPropertyHandlerExt) Build() SearchPropertyHandler { return s }
func (s *searchPropertyHandlerExt) toAppExtData() appExtData {
	d := s.d
	return appExtData{Category: "windows.searchPropertyHandler", SearchPropertyHandler: &d}
}

// FirewallRule builds a single desktop2 firewall rule.
type FirewallRule interface{ isFirewallRule() }

// FirewallRuleBuilder builds a FirewallRule.
type FirewallRuleBuilder interface {
	WithDirection(string) FirewallRuleBuilder
	WithProtocol(string) FirewallRuleBuilder
	WithProfile(string) FirewallRuleBuilder
	WithLocalPortMin(string) FirewallRuleBuilder
	WithLocalPortMax(string) FirewallRuleBuilder
	WithRemotePortMin(string) FirewallRuleBuilder
	WithRemotePortMax(string) FirewallRuleBuilder
	Build() FirewallRule
}

// NewFirewallRule returns a new FirewallRuleBuilder.
func NewFirewallRule() FirewallRuleBuilder { return &firewallRule{} }

type firewallRule struct{ d firewallRuleData }

func (f *firewallRule) WithDirection(s string) FirewallRuleBuilder    { f.d.Direction = s; return f }
func (f *firewallRule) WithProtocol(s string) FirewallRuleBuilder     { f.d.Protocol = s; return f }
func (f *firewallRule) WithProfile(s string) FirewallRuleBuilder      { f.d.Profile = s; return f }
func (f *firewallRule) WithLocalPortMin(s string) FirewallRuleBuilder { f.d.LocalPortMin = s; return f }
func (f *firewallRule) WithLocalPortMax(s string) FirewallRuleBuilder { f.d.LocalPortMax = s; return f }
func (f *firewallRule) WithRemotePortMin(s string) FirewallRuleBuilder {
	f.d.RemotePortMin = s
	return f
}
func (f *firewallRule) WithRemotePortMax(s string) FirewallRuleBuilder {
	f.d.RemotePortMax = s
	return f
}
func (f *firewallRule) Build() FirewallRule    { return f }
func (f *firewallRule) isFirewallRule()        {}
func (f *firewallRule) data() firewallRuleData { return f.d }

// FirewallRules is the desktop2:FirewallRules application extension.
// TODO(verify-xsd): Rule attribute names (Protocol vs IPProtocol) inferred.
type FirewallRules interface{ ApplicationExtension }

// FirewallRulesBuilder builds a FirewallRules extension.
type FirewallRulesBuilder interface {
	AddRule(FirewallRule) FirewallRulesBuilder
	Build() FirewallRules
}

// NewFirewallRules returns a new FirewallRulesBuilder.
func NewFirewallRules() FirewallRulesBuilder { return &firewallRulesExt{} }

type firewallRulesExt struct{ rules []FirewallRule }

func (f *firewallRulesExt) AddRule(r FirewallRule) FirewallRulesBuilder {
	f.rules = append(f.rules, r)
	return f
}
func (f *firewallRulesExt) Build() FirewallRules { return f }
func (f *firewallRulesExt) toAppExtData() appExtData {
	d := firewallRulesData{}
	for _, r := range f.rules {
		d.Rules = append(d.Rules, r.(*firewallRule).data())
	}
	return appExtData{Category: "windows.firewallRules", FirewallRules: &d}
}

// DesktopEventLogging is the desktop2:DesktopEventLogging application extension.
// TODO(verify-xsd): element/attribute layout inferred.
type DesktopEventLogging interface{ ApplicationExtension }

// DesktopEventLoggingBuilder builds a DesktopEventLogging extension.
type DesktopEventLoggingBuilder interface {
	WithProviderGUID(string) DesktopEventLoggingBuilder
	AddChannel(name string) DesktopEventLoggingBuilder
	Build() DesktopEventLogging
}

// NewDesktopEventLogging returns a new DesktopEventLoggingBuilder.
func NewDesktopEventLogging() DesktopEventLoggingBuilder { return &desktopEventLoggingExt{} }

type desktopEventLoggingExt struct {
	d        desktopEventLoggingData
	channels []string
}

func (e *desktopEventLoggingExt) WithProviderGUID(s string) DesktopEventLoggingBuilder {
	e.d.ProviderGUID = s
	return e
}
func (e *desktopEventLoggingExt) AddChannel(name string) DesktopEventLoggingBuilder {
	e.channels = append(e.channels, name)
	return e
}
func (e *desktopEventLoggingExt) Build() DesktopEventLogging { return e }
func (e *desktopEventLoggingExt) toAppExtData() appExtData {
	d := e.d
	for _, c := range e.channels {
		d.Channels = append(d.Channels, eventLogChannelData{Name: c})
	}
	return appExtData{Category: "windows.desktopEventLogging", DesktopEventLogging: &d}
}

// --- desktop3 namespace extensions ---

// InvokeAction builds a desktop3 AutoPlayHandler invoke action.
type InvokeAction interface{ isInvokeAction() }

// InvokeActionBuilder builds an InvokeAction.
type InvokeActionBuilder interface {
	WithActionDisplayName(string) InvokeActionBuilder
	WithProviderCLSID(string) InvokeActionBuilder
	WithContentEvent(string) InvokeActionBuilder
	WithDeviceEvent(string) InvokeActionBuilder
	Build() InvokeAction
}

// NewInvokeAction returns a new InvokeActionBuilder.
func NewInvokeAction() InvokeActionBuilder { return &invokeAction{} }

type invokeAction struct{ d invokeActionData }

func (a *invokeAction) WithActionDisplayName(s string) InvokeActionBuilder {
	a.d.ActionDisplayName = s
	return a
}
func (a *invokeAction) WithProviderCLSID(s string) InvokeActionBuilder {
	a.d.ProviderCLSID = s
	return a
}
func (a *invokeAction) WithContentEvent(s string) InvokeActionBuilder { a.d.ContentEvent = s; return a }
func (a *invokeAction) WithDeviceEvent(s string) InvokeActionBuilder  { a.d.DeviceEvent = s; return a }
func (a *invokeAction) Build() InvokeAction                           { return a }
func (a *invokeAction) isInvokeAction()                               {}
func (a *invokeAction) data() invokeActionData                        { return a.d }

// AutoPlayHandler is the desktop3:AutoPlayHandler application extension.
// TODO(verify-xsd): element/attribute layout inferred.
type AutoPlayHandler interface{ ApplicationExtension }

// AutoPlayHandlerBuilder builds an AutoPlayHandler extension.
type AutoPlayHandlerBuilder interface {
	AddInvokeAction(InvokeAction) AutoPlayHandlerBuilder
	Build() AutoPlayHandler
}

// NewAutoPlayHandler returns a new AutoPlayHandlerBuilder.
func NewAutoPlayHandler() AutoPlayHandlerBuilder { return &autoPlayHandlerExt{} }

type autoPlayHandlerExt struct{ actions []InvokeAction }

func (a *autoPlayHandlerExt) AddInvokeAction(ia InvokeAction) AutoPlayHandlerBuilder {
	a.actions = append(a.actions, ia)
	return a
}
func (a *autoPlayHandlerExt) Build() AutoPlayHandler { return a }
func (a *autoPlayHandlerExt) toAppExtData() appExtData {
	d := autoPlayHandlerData{}
	for _, ia := range a.actions {
		d.InvokeActions = append(d.InvokeActions, ia.(*invokeAction).data())
	}
	return appExtData{Category: "windows.autoPlayHandler", AutoPlayHandler: &d}
}

// CloudFiles is the desktop3:CloudFiles application extension.
// TODO(verify-xsd): child handler element names inferred.
type CloudFiles interface{ ApplicationExtension }

// CloudFilesBuilder builds a CloudFiles extension.
type CloudFilesBuilder interface {
	WithIconResource(string) CloudFilesBuilder
	WithCustomStateHandler(clsid string) CloudFilesBuilder
	WithThumbnailProviderHandler(clsid string) CloudFilesBuilder
	WithExtendedPropertyHandler(clsid string) CloudFilesBuilder
	WithBannersHandler(clsid string) CloudFilesBuilder
	WithContentUriSource(clsid string) CloudFilesBuilder
	Build() CloudFiles
}

// NewCloudFiles returns a new CloudFilesBuilder.
func NewCloudFiles() CloudFilesBuilder { return &cloudFilesExt{} }

type cloudFilesExt struct{ d cloudFilesData }

func (c *cloudFilesExt) WithIconResource(s string) CloudFilesBuilder { c.d.IconResource = s; return c }
func (c *cloudFilesExt) WithCustomStateHandler(clsid string) CloudFilesBuilder {
	c.d.CustomStateHandler = &customStateHandlerData{CLSID: clsid}
	return c
}
func (c *cloudFilesExt) WithThumbnailProviderHandler(clsid string) CloudFilesBuilder {
	c.d.ThumbnailProviderHandler = &thumbnailProviderHandlerData{CLSID: clsid}
	return c
}
func (c *cloudFilesExt) WithExtendedPropertyHandler(clsid string) CloudFilesBuilder {
	c.d.ExtendedPropertyHandler = &extendedPropertyHandlerData{CLSID: clsid}
	return c
}
func (c *cloudFilesExt) WithBannersHandler(clsid string) CloudFilesBuilder {
	c.d.BannersHandler = &bannersHandlerData{CLSID: clsid}
	return c
}
func (c *cloudFilesExt) WithContentUriSource(clsid string) CloudFilesBuilder {
	c.d.ContentUriSource = &contentUriSourceData{CLSID: clsid}
	return c
}
func (c *cloudFilesExt) Build() CloudFiles { return c }
func (c *cloudFilesExt) toAppExtData() appExtData {
	d := c.d
	return appExtData{Category: "windows.cloudFiles", CloudFiles: &d}
}

// --- desktop7 namespace extensions ---

// ApprovedShellExtension is the desktop7:ApprovedShellExtension application extension.
// TODO(verify-xsd): Category/element inferred.
type ApprovedShellExtension interface{ ApplicationExtension }

// ApprovedShellExtensionBuilder builds an ApprovedShellExtension.
type ApprovedShellExtensionBuilder interface {
	WithCLSID(string) ApprovedShellExtensionBuilder
	Build() ApprovedShellExtension
}

// NewApprovedShellExtension returns a new ApprovedShellExtensionBuilder.
func NewApprovedShellExtension() ApprovedShellExtensionBuilder { return &approvedShellExtensionExt{} }

type approvedShellExtensionExt struct{ d approvedShellExtensionData }

func (a *approvedShellExtensionExt) WithCLSID(s string) ApprovedShellExtensionBuilder {
	a.d.CLSID = s
	return a
}
func (a *approvedShellExtensionExt) Build() ApprovedShellExtension { return a }
func (a *approvedShellExtensionExt) toAppExtData() appExtData {
	d := a.d
	return appExtData{Category: "windows.approvedShellExtension", ApprovedShellExtension: &d}
}

// ControlPanelItem is the desktop7:ControlPanelItem application extension.
// TODO(verify-xsd): Category/element inferred.
type ControlPanelItem interface{ ApplicationExtension }

// ControlPanelItemBuilder builds a ControlPanelItem extension.
type ControlPanelItemBuilder interface {
	WithSystemApplicationName(string) ControlPanelItemBuilder
	Build() ControlPanelItem
}

// NewControlPanelItem returns a new ControlPanelItemBuilder.
func NewControlPanelItem() ControlPanelItemBuilder { return &controlPanelItemExt{} }

type controlPanelItemExt struct{ d controlPanelItemData }

func (c *controlPanelItemExt) WithSystemApplicationName(s string) ControlPanelItemBuilder {
	c.d.SystemApplicationName = s
	return c
}
func (c *controlPanelItemExt) Build() ControlPanelItem { return c }
func (c *controlPanelItemExt) toAppExtData() appExtData {
	d := c.d
	return appExtData{Category: "windows.controlPanelItem", ControlPanelItem: &d}
}

// ServiceDesktop7 is the desktop7:Service application extension (adds Arguments).
type ServiceDesktop7 interface{ ApplicationExtension }

// ServiceDesktop7Builder builds a desktop7 Service extension.
type ServiceDesktop7Builder interface {
	WithName(string) ServiceDesktop7Builder
	WithStartupType(string) ServiceDesktop7Builder
	WithStartAccount(string) ServiceDesktop7Builder
	WithArguments(string) ServiceDesktop7Builder
	Build() ServiceDesktop7
}

// NewServiceDesktop7 returns a new ServiceDesktop7Builder.
func NewServiceDesktop7() ServiceDesktop7Builder { return &serviceDesktop7Ext{} }

type serviceDesktop7Ext struct{ d serviceDesktop7Data }

func (s *serviceDesktop7Ext) WithName(v string) ServiceDesktop7Builder { s.d.Name = v; return s }
func (s *serviceDesktop7Ext) WithStartupType(v string) ServiceDesktop7Builder {
	s.d.StartupType = v
	return s
}
func (s *serviceDesktop7Ext) WithStartAccount(v string) ServiceDesktop7Builder {
	s.d.StartAccount = v
	return s
}
func (s *serviceDesktop7Ext) WithArguments(v string) ServiceDesktop7Builder {
	s.d.Arguments = v
	return s
}
func (s *serviceDesktop7Ext) Build() ServiceDesktop7 { return s }
func (s *serviceDesktop7Ext) toAppExtData() appExtData {
	d := s.d
	return appExtData{Category: "windows.service", ServiceDesktop7: &d}
}

// ApplicationRegistration is the desktop7:ApplicationRegistration application extension.
// TODO(verify-xsd): Category/element inferred.
type ApplicationRegistration interface{ ApplicationExtension }

// ApplicationRegistrationBuilder builds an ApplicationRegistration extension.
type ApplicationRegistrationBuilder interface {
	Build() ApplicationRegistration
}

// NewApplicationRegistration returns a new ApplicationRegistrationBuilder.
func NewApplicationRegistration() ApplicationRegistrationBuilder {
	return &applicationRegistrationExt{}
}

type applicationRegistrationExt struct{}

func (a *applicationRegistrationExt) Build() ApplicationRegistration { return a }
func (a *applicationRegistrationExt) toAppExtData() appExtData {
	return appExtData{Category: "windows.desktopAppMigration", ApplicationRegistration: &applicationRegistrationData{}}
}

// DesktopAppMigration is the desktop7:DesktopAppMigration application extension.
// TODO(verify-xsd): Category/element inferred (normally package-level).
type DesktopAppMigration interface{ ApplicationExtension }

// DesktopAppMigrationBuilder builds a DesktopAppMigration extension.
type DesktopAppMigrationBuilder interface {
	AddDesktopApp(aumID, shortcutPath string) DesktopAppMigrationBuilder
	Build() DesktopAppMigration
}

// NewDesktopAppMigration returns a new DesktopAppMigrationBuilder.
func NewDesktopAppMigration() DesktopAppMigrationBuilder { return &desktopAppMigrationExt{} }

type desktopAppMigrationExt struct{ apps []desktopAppData }

func (m *desktopAppMigrationExt) AddDesktopApp(aumID, shortcutPath string) DesktopAppMigrationBuilder {
	m.apps = append(m.apps, desktopAppData{AumID: aumID, ShortcutPath: shortcutPath})
	return m
}
func (m *desktopAppMigrationExt) Build() DesktopAppMigration { return m }
func (m *desktopAppMigrationExt) toAppExtData() appExtData {
	d := desktopAppMigrationData{DesktopApps: m.apps}
	return appExtData{Category: "windows.desktopAppMigration", DesktopAppMigration: &d}
}

// SystemFileAssociation is the desktop7:SystemFileAssociation application extension.
// TODO(verify-xsd): element/attribute layout inferred.
type SystemFileAssociation interface{ ApplicationExtension }

// SystemFileAssociationBuilder builds a SystemFileAssociation extension.
type SystemFileAssociationBuilder interface {
	WithExtension(string) SystemFileAssociationBuilder
	WithFullDetails(string) SystemFileAssociationBuilder
	WithPreviewDetails(string) SystemFileAssociationBuilder
	WithPreviewTitle(string) SystemFileAssociationBuilder
	WithTileInfo(string) SystemFileAssociationBuilder
	Build() SystemFileAssociation
}

// NewSystemFileAssociation returns a new SystemFileAssociationBuilder.
func NewSystemFileAssociation() SystemFileAssociationBuilder { return &systemFileAssociationExt{} }

type systemFileAssociationExt struct{ d systemFileAssociationData }

func (s *systemFileAssociationExt) WithExtension(v string) SystemFileAssociationBuilder {
	s.d.Extension = v
	return s
}
func (s *systemFileAssociationExt) WithFullDetails(v string) SystemFileAssociationBuilder {
	s.d.FullDetails = v
	return s
}
func (s *systemFileAssociationExt) WithPreviewDetails(v string) SystemFileAssociationBuilder {
	s.d.PreviewDetails = v
	return s
}
func (s *systemFileAssociationExt) WithPreviewTitle(v string) SystemFileAssociationBuilder {
	s.d.PreviewTitle = v
	return s
}
func (s *systemFileAssociationExt) WithTileInfo(v string) SystemFileAssociationBuilder {
	s.d.TileInfo = v
	return s
}
func (s *systemFileAssociationExt) Build() SystemFileAssociation { return s }
func (s *systemFileAssociationExt) toAppExtData() appExtData {
	d := s.d
	return appExtData{Category: "windows.systemFileAssociation", SystemFileAssociation: &d}
}

// --- desktop9 namespace extensions ---

// FileExplorerClassicContextMenuHandler is the desktop9 extension of the same name.
// TODO(verify-xsd): Category/element inferred.
type FileExplorerClassicContextMenuHandler interface{ ApplicationExtension }

// FileExplorerClassicContextMenuHandlerBuilder builds the extension.
type FileExplorerClassicContextMenuHandlerBuilder interface {
	WithCLSID(string) FileExplorerClassicContextMenuHandlerBuilder
	Build() FileExplorerClassicContextMenuHandler
}

// NewFileExplorerClassicContextMenuHandler returns a new builder.
func NewFileExplorerClassicContextMenuHandler() FileExplorerClassicContextMenuHandlerBuilder {
	return &fileExplorerClassicContextMenuHandlerExt{}
}

type fileExplorerClassicContextMenuHandlerExt struct {
	d fileExplorerClassicContextMenuHandlerData
}

func (f *fileExplorerClassicContextMenuHandlerExt) WithCLSID(s string) FileExplorerClassicContextMenuHandlerBuilder {
	f.d.CLSID = s
	return f
}
func (f *fileExplorerClassicContextMenuHandlerExt) Build() FileExplorerClassicContextMenuHandler {
	return f
}
func (f *fileExplorerClassicContextMenuHandlerExt) toAppExtData() appExtData {
	d := f.d
	return appExtData{Category: "windows.fileExplorerContextMenus", FileExplorerClassicContextMenuHandler: &d}
}

// FileExplorerClassicDragDropContextMenuHandler is the desktop9 extension of the same name.
// TODO(verify-xsd): Category/element inferred.
type FileExplorerClassicDragDropContextMenuHandler interface{ ApplicationExtension }

// FileExplorerClassicDragDropContextMenuHandlerBuilder builds the extension.
type FileExplorerClassicDragDropContextMenuHandlerBuilder interface {
	WithCLSID(string) FileExplorerClassicDragDropContextMenuHandlerBuilder
	Build() FileExplorerClassicDragDropContextMenuHandler
}

// NewFileExplorerClassicDragDropContextMenuHandler returns a new builder.
func NewFileExplorerClassicDragDropContextMenuHandler() FileExplorerClassicDragDropContextMenuHandlerBuilder {
	return &fileExplorerClassicDragDropContextMenuHandlerExt{}
}

type fileExplorerClassicDragDropContextMenuHandlerExt struct {
	d fileExplorerClassicDragDropContextMenuHandlerData
}

func (f *fileExplorerClassicDragDropContextMenuHandlerExt) WithCLSID(s string) FileExplorerClassicDragDropContextMenuHandlerBuilder {
	f.d.CLSID = s
	return f
}
func (f *fileExplorerClassicDragDropContextMenuHandlerExt) Build() FileExplorerClassicDragDropContextMenuHandler {
	return f
}
func (f *fileExplorerClassicDragDropContextMenuHandlerExt) toAppExtData() appExtData {
	d := f.d
	return appExtData{Category: "windows.fileExplorerContextMenus", FileExplorerClassicDragDropContextMenuHandler: &d}
}

// --- rescap3 namespace (application-level DesktopAppMigration) ---

// DesktopAppMigrationRescap is the rescap3:DesktopAppMigration application extension.
// TODO(verify-xsd): this is normally a package-level extension; placement as an
// application extension is preserved from the original data model.
type DesktopAppMigrationRescap interface{ ApplicationExtension }

// DesktopAppMigrationRescapBuilder builds the extension.
type DesktopAppMigrationRescapBuilder interface {
	AddDesktopApp(aumID, shortcutPath string) DesktopAppMigrationRescapBuilder
	Build() DesktopAppMigrationRescap
}

// NewDesktopAppMigrationRescap returns a new builder.
func NewDesktopAppMigrationRescap() DesktopAppMigrationRescapBuilder {
	return &desktopAppMigrationRescapExt{}
}

type desktopAppMigrationRescapExt struct{ apps []desktopAppRescapData }

func (m *desktopAppMigrationRescapExt) AddDesktopApp(aumID, shortcutPath string) DesktopAppMigrationRescapBuilder {
	m.apps = append(m.apps, desktopAppRescapData{AumID: aumID, ShortcutPath: shortcutPath})
	return m
}
func (m *desktopAppMigrationRescapExt) Build() DesktopAppMigrationRescap { return m }
func (m *desktopAppMigrationRescapExt) toAppExtData() appExtData {
	d := desktopAppMigrationRescapData{DesktopApps: m.apps}
	return appExtData{Category: "windows.desktopAppMigration", DesktopAppMigrationRescap: &d}
}

// --- mobile namespace extensions ---

// MobileMultiScreenProperties is the mobile:MultiScreenProperties application extension.
// TODO(verify-xsd): Category/element inferred.
type MobileMultiScreenProperties interface{ ApplicationExtension }

// MobileMultiScreenPropertiesBuilder builds the extension.
type MobileMultiScreenPropertiesBuilder interface {
	WithRestoreFromOtherDisplayOnReactivation(bool) MobileMultiScreenPropertiesBuilder
	Build() MobileMultiScreenProperties
}

// NewMobileMultiScreenProperties returns a new builder.
func NewMobileMultiScreenProperties() MobileMultiScreenPropertiesBuilder {
	return &mobileMultiScreenPropertiesExt{}
}

type mobileMultiScreenPropertiesExt struct {
	d mobileMultiScreenPropertiesData
}

func (m *mobileMultiScreenPropertiesExt) WithRestoreFromOtherDisplayOnReactivation(v bool) MobileMultiScreenPropertiesBuilder {
	m.d.RestoreFromOtherDisplayOnReactivation = v
	return m
}
func (m *mobileMultiScreenPropertiesExt) Build() MobileMultiScreenProperties { return m }
func (m *mobileMultiScreenPropertiesExt) toAppExtData() appExtData {
	d := m.d
	return appExtData{Category: "windows.mobile.multiScreen", MobileMultiScreenProperties: &d}
}

// CommunicationBlockingProvider is the mobile:CommunicationBlockingProvider extension.
// TODO(verify-xsd): Category/element inferred.
type CommunicationBlockingProvider interface{ ApplicationExtension }

// CommunicationBlockingProviderBuilder builds the extension.
type CommunicationBlockingProviderBuilder interface {
	Build() CommunicationBlockingProvider
}

// NewCommunicationBlockingProvider returns a new builder.
func NewCommunicationBlockingProvider() CommunicationBlockingProviderBuilder {
	return &communicationBlockingProviderExt{}
}

type communicationBlockingProviderExt struct{}

func (c *communicationBlockingProviderExt) Build() CommunicationBlockingProvider { return c }
func (c *communicationBlockingProviderExt) toAppExtData() appExtData {
	return appExtData{Category: "windows.communicationBlocking", CommunicationBlockingProvider: &communicationBlockingProviderData{}}
}

// PhoneCallOriginProvider is the mobile:PhoneCallOriginProvider extension.
// TODO(verify-xsd): Category/element inferred.
type PhoneCallOriginProvider interface{ ApplicationExtension }

// PhoneCallOriginProviderBuilder builds the extension.
type PhoneCallOriginProviderBuilder interface {
	Build() PhoneCallOriginProvider
}

// NewPhoneCallOriginProvider returns a new builder.
func NewPhoneCallOriginProvider() PhoneCallOriginProviderBuilder {
	return &phoneCallOriginProviderExt{}
}

type phoneCallOriginProviderExt struct{}

func (p *phoneCallOriginProviderExt) Build() PhoneCallOriginProvider { return p }
func (p *phoneCallOriginProviderExt) toAppExtData() appExtData {
	return appExtData{Category: "windows.phoneCallOrigin", PhoneCallOriginProvider: &phoneCallOriginProviderData{}}
}

// --- printSupport namespace extensions ---
// TODO(verify-xsd): the printSupport namespace prefix, element names and Category
// strings are all inferred; verify against the Microsoft printSupport manifest XSD.

// PrintSupportSettingsUI is the printSupport:PrintSupportSettingsUI extension.
type PrintSupportSettingsUI interface{ ApplicationExtension }

// PrintSupportSettingsUIBuilder builds the extension.
type PrintSupportSettingsUIBuilder interface{ Build() PrintSupportSettingsUI }

// NewPrintSupportSettingsUI returns a new builder.
func NewPrintSupportSettingsUI() PrintSupportSettingsUIBuilder {
	return &printSupportSettingsUIExt{}
}

type printSupportSettingsUIExt struct{}

func (p *printSupportSettingsUIExt) Build() PrintSupportSettingsUI { return p }
func (p *printSupportSettingsUIExt) toAppExtData() appExtData {
	return appExtData{Category: "windows.printSupportSettingsUI", PrintSupportSettingsUI: &printSupportSettingsUIData{}}
}

// PrintSupportExtension is the printSupport:PrintSupportExtension extension.
type PrintSupportExtension interface{ ApplicationExtension }

// PrintSupportExtensionBuilder builds the extension.
type PrintSupportExtensionBuilder interface{ Build() PrintSupportExtension }

// NewPrintSupportExtension returns a new builder.
func NewPrintSupportExtension() PrintSupportExtensionBuilder {
	return &printSupportExtensionExt{}
}

type printSupportExtensionExt struct{}

func (p *printSupportExtensionExt) Build() PrintSupportExtension { return p }
func (p *printSupportExtensionExt) toAppExtData() appExtData {
	return appExtData{Category: "windows.printSupportExtension", PrintSupportExtension: &printSupportExtensionData{}}
}

// PrintSupportJobUI is the printSupport:PrintSupportJobUI extension.
type PrintSupportJobUI interface{ ApplicationExtension }

// PrintSupportJobUIBuilder builds the extension.
type PrintSupportJobUIBuilder interface{ Build() PrintSupportJobUI }

// NewPrintSupportJobUI returns a new builder.
func NewPrintSupportJobUI() PrintSupportJobUIBuilder { return &printSupportJobUIExt{} }

type printSupportJobUIExt struct{}

func (p *printSupportJobUIExt) Build() PrintSupportJobUI { return p }
func (p *printSupportJobUIExt) toAppExtData() appExtData {
	return appExtData{Category: "windows.printSupportJobUI", PrintSupportJobUI: &printSupportJobUIData{}}
}

// --- package extensions ---

// PkgInProcessServer is the package-level activatable in-process server extension.
// TODO(verify-xsd): element/Category inferred.
type PkgInProcessServer interface{ PackageExtension }

// PkgInProcessServerBuilder builds the extension.
type PkgInProcessServerBuilder interface {
	WithPath(string) PkgInProcessServerBuilder
	AddActivatableClass(id, threadingModel string) PkgInProcessServerBuilder
	Build() PkgInProcessServer
}

// NewPkgInProcessServer returns a new builder.
func NewPkgInProcessServer() PkgInProcessServerBuilder { return &pkgInProcessServerExt{} }

type pkgInProcessServerExt struct {
	d       pkgInProcessServerData
	classes []activatableClassData
}

func (p *pkgInProcessServerExt) WithPath(s string) PkgInProcessServerBuilder { p.d.Path = s; return p }
func (p *pkgInProcessServerExt) AddActivatableClass(id, threadingModel string) PkgInProcessServerBuilder {
	p.classes = append(p.classes, activatableClassData{ActivatableClassID: id, ThreadingModel: threadingModel})
	return p
}
func (p *pkgInProcessServerExt) Build() PkgInProcessServer { return p }
func (p *pkgInProcessServerExt) toPkgExtData() pkgExtData {
	d := p.d
	d.ActivatableClasses = p.classes
	return pkgExtData{Category: "windows.activatableClass.inProcessServer", InProcessServer: &d}
}

// PkgOutOfProcessServer is the package-level activatable out-of-process server extension.
// TODO(verify-xsd): element/Category inferred.
type PkgOutOfProcessServer interface{ PackageExtension }

// PkgOutOfProcessServerBuilder builds the extension.
type PkgOutOfProcessServerBuilder interface {
	WithServerName(string) PkgOutOfProcessServerBuilder
	WithExecutable(string) PkgOutOfProcessServerBuilder
	WithArguments(string) PkgOutOfProcessServerBuilder
	WithInstancing(string) PkgOutOfProcessServerBuilder
	AddActivatableClass(id, threadingModel string) PkgOutOfProcessServerBuilder
	Build() PkgOutOfProcessServer
}

// NewPkgOutOfProcessServer returns a new builder.
func NewPkgOutOfProcessServer() PkgOutOfProcessServerBuilder { return &pkgOutOfProcessServerExt{} }

type pkgOutOfProcessServerExt struct {
	d       pkgOutOfProcessServerData
	classes []activatableClassData
}

func (p *pkgOutOfProcessServerExt) WithServerName(s string) PkgOutOfProcessServerBuilder {
	p.d.ServerName = s
	return p
}
func (p *pkgOutOfProcessServerExt) WithExecutable(s string) PkgOutOfProcessServerBuilder {
	p.d.Executable = s
	return p
}
func (p *pkgOutOfProcessServerExt) WithArguments(s string) PkgOutOfProcessServerBuilder {
	p.d.Arguments = s
	return p
}
func (p *pkgOutOfProcessServerExt) WithInstancing(s string) PkgOutOfProcessServerBuilder {
	p.d.Instancing = s
	return p
}
func (p *pkgOutOfProcessServerExt) AddActivatableClass(id, threadingModel string) PkgOutOfProcessServerBuilder {
	p.classes = append(p.classes, activatableClassData{ActivatableClassID: id, ThreadingModel: threadingModel})
	return p
}
func (p *pkgOutOfProcessServerExt) Build() PkgOutOfProcessServer { return p }
func (p *pkgOutOfProcessServerExt) toPkgExtData() pkgExtData {
	d := p.d
	d.ActivatableClasses = p.classes
	return pkgExtData{Category: "windows.activatableClass.outOfProcessServer", OutOfProcessServer: &d}
}

// ProxyStubPkg is the package-level activatable proxy-stub extension.
// TODO(verify-xsd): element/Category inferred.
type ProxyStubPkg interface{ PackageExtension }

// ProxyStubPkgBuilder builds the extension.
type ProxyStubPkgBuilder interface {
	WithPath(string) ProxyStubPkgBuilder
	WithCLSID(string) ProxyStubPkgBuilder
	Build() ProxyStubPkg
}

// NewProxyStubPkg returns a new builder.
func NewProxyStubPkg() ProxyStubPkgBuilder { return &proxyStubPkgExt{} }

type proxyStubPkgExt struct{ d proxyStubPkgData }

func (p *proxyStubPkgExt) WithPath(s string) ProxyStubPkgBuilder  { p.d.Path = s; return p }
func (p *proxyStubPkgExt) WithCLSID(s string) ProxyStubPkgBuilder { p.d.CLSID = s; return p }
func (p *proxyStubPkgExt) Build() ProxyStubPkg                    { return p }
func (p *proxyStubPkgExt) toPkgExtData() pkgExtData {
	d := p.d
	return pkgExtData{Category: "windows.activatableClass.proxyStub", ProxyStubPkg: &d}
}

// PublisherCacheFolders is the package-level PublisherCacheFolders extension.
// TODO(verify-xsd): element/Category inferred.
type PublisherCacheFolders interface{ PackageExtension }

// PublisherCacheFoldersBuilder builds the extension.
type PublisherCacheFoldersBuilder interface {
	AddFolder(name string) PublisherCacheFoldersBuilder
	Build() PublisherCacheFolders
}

// NewPublisherCacheFolders returns a new builder.
func NewPublisherCacheFolders() PublisherCacheFoldersBuilder { return &publisherCacheFoldersExt{} }

type publisherCacheFoldersExt struct{ folders []string }

func (p *publisherCacheFoldersExt) AddFolder(name string) PublisherCacheFoldersBuilder {
	p.folders = append(p.folders, name)
	return p
}
func (p *publisherCacheFoldersExt) Build() PublisherCacheFolders { return p }
func (p *publisherCacheFoldersExt) toPkgExtData() pkgExtData {
	d := publisherCacheFoldersData{}
	for _, f := range p.folders {
		d.Folders = append(d.Folders, publisherCacheFolderData{Name: f})
	}
	return pkgExtData{Category: "windows.publisherCacheFolders", PublisherCacheFolders: &d}
}

// LoaderSearchPathOverride is the uap6:LoaderSearchPathOverride package extension.
// TODO(verify-xsd): element/Category inferred.
type LoaderSearchPathOverride interface{ PackageExtension }

// LoaderSearchPathOverrideBuilder builds the extension.
type LoaderSearchPathOverrideBuilder interface {
	AddEntry(folderPath string) LoaderSearchPathOverrideBuilder
	Build() LoaderSearchPathOverride
}

// NewLoaderSearchPathOverride returns a new builder.
func NewLoaderSearchPathOverride() LoaderSearchPathOverrideBuilder {
	return &loaderSearchPathOverrideExt{}
}

type loaderSearchPathOverrideExt struct{ entries []string }

func (l *loaderSearchPathOverrideExt) AddEntry(folderPath string) LoaderSearchPathOverrideBuilder {
	l.entries = append(l.entries, folderPath)
	return l
}
func (l *loaderSearchPathOverrideExt) Build() LoaderSearchPathOverride { return l }
func (l *loaderSearchPathOverrideExt) toPkgExtData() pkgExtData {
	d := loaderSearchPathOverrideData{}
	for _, e := range l.entries {
		d.Entries = append(d.Entries, loaderSearchPathEntryData{FolderPath: e})
	}
	return pkgExtData{Category: "windows.loaderSearchPathOverride", LoaderSearchPathOverride: &d}
}

// ComInterfacePkg is the com:ComInterface package extension.
type ComInterfacePkg interface{ PackageExtension }

// ComInterfacePkgBuilder builds the extension.
type ComInterfacePkgBuilder interface {
	AddInterface(InterfaceEntry) ComInterfacePkgBuilder
	AddProxyStub(ProxyStub) ComInterfacePkgBuilder
	Build() ComInterfacePkg
}

// NewComInterfacePkg returns a new builder.
func NewComInterfacePkg() ComInterfacePkgBuilder { return &comInterfacePkgExt{} }

type comInterfacePkgExt struct {
	interfaces []InterfaceEntry
	proxyStubs []ProxyStub
}

func (c *comInterfacePkgExt) AddInterface(e InterfaceEntry) ComInterfacePkgBuilder {
	c.interfaces = append(c.interfaces, e)
	return c
}
func (c *comInterfacePkgExt) AddProxyStub(p ProxyStub) ComInterfacePkgBuilder {
	c.proxyStubs = append(c.proxyStubs, p)
	return c
}
func (c *comInterfacePkgExt) Build() ComInterfacePkg { return c }
func (c *comInterfacePkgExt) toPkgExtData() pkgExtData {
	d := comInterfaceData{}
	for _, e := range c.interfaces {
		d.Interfaces = append(d.Interfaces, e.(*interfaceEntry).data())
	}
	for _, p := range c.proxyStubs {
		d.ProxyStubs = append(d.ProxyStubs, p.(*proxyStub).data())
	}
	return pkgExtData{Category: "windows.comInterface", ComInterfacePkg: &d}
}

// DesktopAppMigrationPkg is the rescap3:DesktopAppMigration package extension.
// TODO(verify-xsd): element/Category inferred.
type DesktopAppMigrationPkg interface{ PackageExtension }

// DesktopAppMigrationPkgBuilder builds the extension.
type DesktopAppMigrationPkgBuilder interface {
	AddDesktopApp(aumID, shortcutPath string) DesktopAppMigrationPkgBuilder
	Build() DesktopAppMigrationPkg
}

// NewDesktopAppMigrationPkg returns a new builder.
func NewDesktopAppMigrationPkg() DesktopAppMigrationPkgBuilder { return &desktopAppMigrationPkgExt{} }

type desktopAppMigrationPkgExt struct{ apps []desktopAppRescapData }

func (m *desktopAppMigrationPkgExt) AddDesktopApp(aumID, shortcutPath string) DesktopAppMigrationPkgBuilder {
	m.apps = append(m.apps, desktopAppRescapData{AumID: aumID, ShortcutPath: shortcutPath})
	return m
}
func (m *desktopAppMigrationPkgExt) Build() DesktopAppMigrationPkg { return m }
func (m *desktopAppMigrationPkgExt) toPkgExtData() pkgExtData {
	d := desktopAppMigrationRescapData{DesktopApps: m.apps}
	return pkgExtData{Category: "windows.desktopAppMigration", DesktopAppMigrationPkg: &d}
}
