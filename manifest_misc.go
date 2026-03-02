package msix

// --- Background tasks ---

// BackgroundTasks represents background task registration.
type BackgroundTasks struct {
	TaskType   string // "timer", "systemEvent", "pushNotification", etc.
	Tasks      []Task
}

// Task represents a single background task.
type Task struct {
	Type string
}

// --- mobile namespace extensions ---

// MobileMultiScreenProperties represents mobile:MobileMultiScreenProperties.
type MobileMultiScreenProperties struct {
	RestoreFromOtherDisplayOnReactivation bool
}

// CommunicationBlockingProvider represents mobile:CommunicationBlockingProvider.
type CommunicationBlockingProvider struct{}

// PhoneCallOriginProvider represents mobile:PhoneCallOriginProvider.
type PhoneCallOriginProvider struct{}

// --- printSupport namespace extensions ---

// PrintSupportSettingsUI represents printSupport:PrintSupportSettingsUI.
type PrintSupportSettingsUI struct{}

// PrintSupportExtension represents printSupport:PrintSupportExtension.
type PrintSupportExtension struct{}

// PrintSupportJobUI represents printSupport:PrintSupportJobUI.
type PrintSupportJobUI struct{}
