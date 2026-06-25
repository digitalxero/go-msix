package msix

// --- uap namespace extensions ---

// protocolData represents uap:Protocol for protocol activation.
type protocolData struct {
	Name        string
	DisplayName string
	Logo        string
	// uap3 parameters support
	Parameters string
}

// fileTypeAssociationData represents uap:FileTypeAssociation.
type fileTypeAssociationData struct {
	Name               string
	DisplayName        string
	Logo               string
	InfoTip            string
	SupportedFileTypes []fileTypeData
	// uap4 additions
	DesiredView string
}

// fileTypeData represents a supported file type within a FileTypeAssociation.
type fileTypeData struct {
	Extension   string // e.g., ".myf"
	ContentType string // MIME type, optional
}

// shareTargetData represents uap:ShareTarget.
type shareTargetData struct {
	SupportedFileTypes []fileTypeData
	DataFormats        []dataFormatData
}

// dataFormatData represents a data format within ShareTarget.
type dataFormatData struct {
	Format string // e.g., "Text", "URI", "Bitmap", "HTML", "StorageItems"
}

// fileOpenPickerData represents uap:FileOpenPicker.
type fileOpenPickerData struct {
	SupportedFileTypes []fileTypeData
}

// fileSavePickerData represents uap:FileSavePicker.
type fileSavePickerData struct {
	SupportedFileTypes []fileTypeData
}

// autoPlayContentData represents uap:AutoPlayContent.
type autoPlayContentData struct {
	LaunchActions []autoPlayLaunchActionData
}

// autoPlayDeviceData represents uap:AutoPlayDevice.
type autoPlayDeviceData struct {
	LaunchActions []autoPlayDeviceLaunchActionData
}

// autoPlayLaunchActionData represents an action within AutoPlayContent.
type autoPlayLaunchActionData struct {
	Verb              string
	ActionDisplayName string
	ContentEvent      string
}

// autoPlayDeviceLaunchActionData represents an action within AutoPlayDevice.
type autoPlayDeviceLaunchActionData struct {
	Verb              string
	ActionDisplayName string
	DeviceEvent       string
}

// appServiceData represents uap:AppService / uap3:AppService.
type appServiceData struct {
	Name                      string
	ServerName                string
	SupportsRemoteSystemsEnum bool // uap4
}

// dialProtocolData represents uap:DialProtocol.
type dialProtocolData struct {
	Name string
}

// voipCallData represents uap:VoipCall.
type voipCallData struct{}

// --- uap3 namespace extensions ---

// appUriHandlerData represents uap3:AppUriHandler.
type appUriHandlerData struct {
	Hosts []appUriHandlerHostData
}

// appUriHandlerHostData represents a host within AppUriHandler.
type appUriHandlerHostData struct {
	Name string
}

// appExtensionHostData represents uap3:AppExtensionHost.
type appExtensionHostData struct {
	Names []appExtensionNameData
}

// appExtensionNameData is a name entry in AppExtensionHost.
type appExtensionNameData struct {
	Name string
}

// appExtensionData represents uap3:AppExtension.
type appExtensionData struct {
	Name         string
	ID           string
	DisplayName  string
	Description  string
	PublicFolder string
}

// appointmentDataProviderData represents uap3:AppointmentDataProvider.
type appointmentDataProviderData struct {
	ServerName string
}

// emailDataProviderData represents uap3:EmailDataProvider.
type emailDataProviderData struct {
	ServerName string
}

// contactDataProviderData represents uap3:ContactDataProvider.
type contactDataProviderData struct {
	ServerName string
}

// --- uap4 namespace extensions ---

// sharedFontsData represents uap4:SharedFonts.
type sharedFontsData struct {
	Fonts []fontData
}

// fontData represents a uap4:Font entry.
type fontData struct {
	File string
}

// contactPanelData represents uap4:ContactPanel.
type contactPanelData struct {
	SupportsUnknownContacts bool
}

// mediaCodecData represents uap4:MediaCodec.
type mediaCodecData struct {
	DisplayName string
	Description string
	Category    string // "audioDecoder", "audioEncoder", "videoDecoder", "videoEncoder"
	MediaTypes  []mediaTypeData
}

// mediaTypeData within MediaCodec.
type mediaTypeData struct {
	SubType string
}

// loopbackAccessRulesData represents uap4:LoopbackAccessRules.
type loopbackAccessRulesData struct {
	Rules []loopbackRuleData
}

// loopbackRuleData represents a single rule.
type loopbackRuleData struct {
	Direction string // "out"
}

// devicePortalProviderData represents uap4:DevicePortalProvider.
type devicePortalProviderData struct {
	DisplayName    string
	AppServiceName string
	ContentRoute   string
	HandlerRoute   string
}

// userDataTaskDataProviderData represents uap4:UserDataTaskDataProvider.
type userDataTaskDataProviderData struct {
	ServerName string
}

// --- uap5 namespace extensions ---

// userActivityData represents uap5:UserActivity.
type userActivityData struct {
	ActivitySourceHost string
}

// mediaSourceData represents uap5:MediaSource.
type mediaSourceData struct {
	DisplayName string
	MediaTypes  []mediaSourceMediaTypeData
}

// mediaSourceMediaTypeData is a media type for MediaSource.
type mediaSourceMediaTypeData struct {
	SubType string
}

// videoRendererEffectData represents uap5:VideoRendererEffect.
type videoRendererEffectData struct {
	DisplayName        string
	ActivatableClassID string
}

// startupTaskData represents uap5:StartupTask / desktop:StartupTask.
type startupTaskData struct {
	TaskID      string
	Enabled     bool
	DisplayName string
}

// appExecutionAliasData represents uap5:AppExecutionAlias.
type appExecutionAliasData struct {
	ExecutionAliases []executionAliasData
}

// executionAliasData represents a single execution alias entry.
type executionAliasData struct {
	Alias string
}

// --- uap6 namespace extensions ---

// barcodeScannerProviderData represents uap6:BarcodeScannerProvider.
type barcodeScannerProviderData struct{}

// --- uap7 namespace extensions ---

// sharedFontsUap7Data represents uap7:SharedFonts.
type sharedFontsUap7Data struct {
	Fonts []fontData
}

// enterpriseDataProtectionData represents uap7:EnterpriseDataProtection.
type enterpriseDataProtectionData struct {
	ProtectionDomains []protectionDomainData
}

// protectionDomainData within EnterpriseDataProtection.
type protectionDomainData struct {
	Name string
}

// --- uap10 namespace extensions ---

// protocolUap10Data represents uap10:Protocol.
type protocolUap10Data struct {
	Name       string
	Parameters string
}

// hostRuntimeData represents uap10:HostRuntime.
type hostRuntimeData struct {
	ID              string
	RuntimeBehavior string // "packagedClassicApp", "windowsApp"
}

// packageIntegrityData represents uap10:PackageIntegrity.
type packageIntegrityData struct {
	Content *packageIntegrityContentData
}

// packageIntegrityContentData contains content integrity info.
type packageIntegrityContentData struct {
	Enforcement string // "on", "default"
}
