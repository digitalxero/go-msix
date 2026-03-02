package msix

// PackageExtension represents a package-level extension.
// Only one of the typed fields should be non-nil, corresponding to the Category.
type PackageExtension struct {
	Category string

	// Standard activatable classes
	InProcessServer  *PkgInProcessServer
	OutOfProcessServer *PkgOutOfProcessServer
	ProxyStubPkg     *ProxyStubPkg

	// Certificates
	Certificates *Certificates

	// PublisherCacheFolders
	PublisherCacheFolders *PublisherCacheFolders

	// LoaderSearchPathOverride (uap6)
	LoaderSearchPathOverride *LoaderSearchPathOverride

	// Package-level COM
	ComServerPkg    *ComServer
	ComInterfacePkg *ComInterface

	// rescap3 package extensions
	DesktopAppMigrationPkg *DesktopAppMigrationRescap
}

// PkgInProcessServer represents a package-level InProcessServer for activatable classes.
type PkgInProcessServer struct {
	Path               string
	ActivatableClasses []ActivatableClass
}

// PkgOutOfProcessServer represents a package-level OutOfProcessServer.
type PkgOutOfProcessServer struct {
	ServerName         string
	Executable         string
	Arguments          string
	Instancing         string // "singleInstance", "multipleInstances"
	ActivatableClasses []ActivatableClass
}

// ActivatableClass represents an activatable class in a server.
type ActivatableClass struct {
	ActivatableClassID string
	ThreadingModel     string // "both", "STA", "MTA"
}

// ProxyStubPkg represents a package-level ProxyStub.
type ProxyStubPkg struct {
	Path string
	CLSID string
}

// Certificates represents package-level certificate declarations.
type Certificates struct {
	Certificate []CertificateEntry
}

// CertificateEntry is a single certificate.
type CertificateEntry struct {
	StoreName string
	Content   string // path to .cer file in package
}

// PublisherCacheFolders represents package-level PublisherCacheFolders.
type PublisherCacheFolders struct {
	Folders []PublisherCacheFolder
}

// PublisherCacheFolder is a single folder entry.
type PublisherCacheFolder struct {
	Name string
}

// LoaderSearchPathOverride represents uap6:LoaderSearchPathOverride.
type LoaderSearchPathOverride struct {
	Entries []LoaderSearchPathEntry
}

// LoaderSearchPathEntry represents a path entry.
type LoaderSearchPathEntry struct {
	FolderPath string
}
