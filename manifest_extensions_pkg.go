package msix

// pkgExtData represents a package-level extension.
// Only one of the typed fields should be non-nil, corresponding to the Category.
type pkgExtData struct {
	Category string

	// Standard activatable classes
	InProcessServer    *pkgInProcessServerData
	OutOfProcessServer *pkgOutOfProcessServerData
	ProxyStubPkg       *proxyStubPkgData

	// Certificates
	Certificates *certificatesData

	// PublisherCacheFolders
	PublisherCacheFolders *publisherCacheFoldersData

	// LoaderSearchPathOverride (uap6)
	LoaderSearchPathOverride *loaderSearchPathOverrideData

	// Package-level COM
	ComServerPkg    *comServerData
	ComInterfacePkg *comInterfaceData

	// rescap3 package extensions
	DesktopAppMigrationPkg *desktopAppMigrationRescapData
}

// pkgInProcessServerData represents a package-level InProcessServer for activatable classes.
type pkgInProcessServerData struct {
	Path               string
	ActivatableClasses []activatableClassData
}

// pkgOutOfProcessServerData represents a package-level OutOfProcessServer.
type pkgOutOfProcessServerData struct {
	ServerName         string
	Executable         string
	Arguments          string
	Instancing         string // "singleInstance", "multipleInstances"
	ActivatableClasses []activatableClassData
}

// activatableClassData represents an activatable class in a server.
type activatableClassData struct {
	ActivatableClassID string
	ThreadingModel     string // "both", "STA", "MTA"
}

// proxyStubPkgData represents a package-level ProxyStub.
type proxyStubPkgData struct {
	Path  string
	CLSID string
}

// certificatesData represents package-level certificate declarations.
type certificatesData struct {
	Certificate []certificateEntryData
}

// certificateEntryData is a single certificate.
type certificateEntryData struct {
	StoreName string
	Content   string // path to .cer file in package
}

// publisherCacheFoldersData represents package-level PublisherCacheFolders.
type publisherCacheFoldersData struct {
	Folders []publisherCacheFolderData
}

// publisherCacheFolderData is a single folder entry.
type publisherCacheFolderData struct {
	Name string
}

// loaderSearchPathOverrideData represents uap6:LoaderSearchPathOverride.
type loaderSearchPathOverrideData struct {
	Entries []loaderSearchPathEntryData
}

// loaderSearchPathEntryData represents a path entry.
type loaderSearchPathEntryData struct {
	FolderPath string
}
