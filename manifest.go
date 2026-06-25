package msix

// manifestData represents the full AppxManifest.xml structure (internal template data).
type manifestData struct {
	Identity     identityData
	Properties   propertiesData
	Dependencies dependenciesData
	Resources    []resourceData
	Capabilities capabilitiesData
	Applications []applicationData
	Extensions   []pkgExtData
}

// identityData represents the Package/Identity element.
type identityData struct {
	Name                  string
	Version               string
	Publisher             string
	ProcessorArchitecture string // x86, x64, arm, arm64, neutral
	ResourceID            string // Optional
}

// propertiesData represents Package/Properties.
type propertiesData struct {
	DisplayName          string
	PublisherDisplayName string
	Logo                 string
	Description          string
	Framework            bool
	ResourcePackage      bool
	AllowExecution       bool
	ModificationPackage  bool // rescap6:ModificationPackage
}

// dependenciesData represents Package/Dependencies.
type dependenciesData struct {
	TargetDeviceFamilies []targetDeviceFamilyData
	PackageDependencies  []packageDependencyData
}

// targetDeviceFamilyData represents a Dependencies/TargetDeviceFamily element.
type targetDeviceFamilyData struct {
	Name             string
	MinVersion       string
	MaxVersionTested string
}

// packageDependencyData represents a Dependencies/PackageDependency element.
type packageDependencyData struct {
	Name       string
	Publisher  string
	MinVersion string
}

// resourceData represents a Resources/Resource element.
type resourceData struct {
	Language       string
	Scale          string // e.g., "100", "200"
	DXFeatureLevel string // e.g., "dx9"
}
