package msix

// Manifest represents the full AppxManifest.xml structure.
type Manifest struct {
	Identity     Identity
	Properties   Properties
	Dependencies Dependencies
	Resources    []Resource
	Capabilities Capabilities
	Applications []Application
	Extensions   []PackageExtension
}

// Identity represents the Package/Identity element.
type Identity struct {
	Name                  string
	Version               string
	Publisher             string
	ProcessorArchitecture string // x86, x64, arm, arm64, neutral
	ResourceID            string // Optional
}

// Properties represents Package/Properties.
type Properties struct {
	DisplayName          string
	PublisherDisplayName  string
	Logo                 string
	Description          string
	Framework            bool
	ResourcePackage      bool
	AllowExecution       bool
	ModificationPackage  bool // rescap6:ModificationPackage
}

// Dependencies represents Package/Dependencies.
type Dependencies struct {
	TargetDeviceFamilies []TargetDeviceFamily
	PackageDependencies  []PackageDependency
}

// TargetDeviceFamily represents a Dependencies/TargetDeviceFamily element.
type TargetDeviceFamily struct {
	Name             string
	MinVersion       string
	MaxVersionTested string
}

// PackageDependency represents a Dependencies/PackageDependency element.
type PackageDependency struct {
	Name         string
	Publisher    string
	MinVersion   string
}

// Resource represents a Resources/Resource element.
type Resource struct {
	Language string
	Scale    string // e.g., "100", "200"
	DXFeatureLevel string // e.g., "dx9"
}
