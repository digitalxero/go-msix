package msix

// Capabilities contains all capability declarations for the package.
type Capabilities struct {
	Capabilities       []Capability
	DeviceCapabilities []DeviceCapability
	Restricted         []RestrictedCapability
	UAP                []UAPCapability
	Custom             []CustomCapability
}

// Capability represents a standard capability (e.g., "internetClient").
type Capability struct {
	Name string
}

// DeviceCapability represents a DeviceCapability with optional child devices.
type DeviceCapability struct {
	Name    string
	Devices []Device
}

// Device represents a device within a DeviceCapability.
type Device struct {
	ID       string
	Functions []DeviceFunction
}

// DeviceFunction represents a function within a device.
type DeviceFunction struct {
	Type string
}

// RestrictedCapability represents a rescap:Capability.
type RestrictedCapability struct {
	Name string
}

// UAPCapability represents a uap:Capability.
type UAPCapability struct {
	Name string
}

// CustomCapability represents a uap4:CustomCapability.
type CustomCapability struct {
	Name string
}
