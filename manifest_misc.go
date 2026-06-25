package msix

// --- Background tasks ---

// backgroundTasksData represents background task registration.
type backgroundTasksData struct {
	TaskType string // "timer", "systemEvent", "pushNotification", etc.
	Tasks    []taskData
}

// taskData represents a single background task.
type taskData struct {
	Type string
}

// --- mobile namespace extensions ---

// mobileMultiScreenPropertiesData represents mobile:MobileMultiScreenProperties.
type mobileMultiScreenPropertiesData struct {
	RestoreFromOtherDisplayOnReactivation bool
}

// communicationBlockingProviderData represents mobile:CommunicationBlockingProvider.
type communicationBlockingProviderData struct{}

// phoneCallOriginProviderData represents mobile:PhoneCallOriginProvider.
type phoneCallOriginProviderData struct{}

// --- printSupport namespace extensions ---

// printSupportSettingsUIData represents printSupport:PrintSupportSettingsUI.
type printSupportSettingsUIData struct{}

// printSupportExtensionData represents printSupport:PrintSupportExtension.
type printSupportExtensionData struct{}

// printSupportJobUIData represents printSupport:PrintSupportJobUI.
type printSupportJobUIData struct{}
