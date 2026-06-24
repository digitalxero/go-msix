package msix

// capabilitiesData contains all capability declarations for the package.
type capabilitiesData struct {
	Capabilities       []capabilityData
	DeviceCapabilities []deviceCapabilityData
	Restricted         []restrictedCapabilityData
	UAP                []uapCapabilityData
	Custom             []customCapabilityData
}

// capabilityData represents a standard capability (e.g., "internetClient").
type capabilityData struct {
	Name string
}

// deviceCapabilityData represents a DeviceCapability with optional child devices.
type deviceCapabilityData struct {
	Name    string
	Devices []deviceData
}

// deviceData represents a device within a DeviceCapability.
type deviceData struct {
	ID        string
	Functions []deviceFunctionData
}

// deviceFunctionData represents a function within a device.
type deviceFunctionData struct {
	Type string
}

// restrictedCapabilityData represents a rescap:Capability.
type restrictedCapabilityData struct {
	Name string
}

// uapCapabilityData represents a uap:Capability.
type uapCapabilityData struct {
	Name string
}

// customCapabilityData represents a uap4:CustomCapability.
type customCapabilityData struct {
	Name string
}
