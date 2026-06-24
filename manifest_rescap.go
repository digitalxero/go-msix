package msix

// --- rescap/rescap3 namespace extensions ---

// desktopAppMigrationRescapData represents rescap3:DesktopAppMigration (package-level).
type desktopAppMigrationRescapData struct {
	DesktopApps []desktopAppRescapData
}

// desktopAppRescapData within DesktopAppMigrationRescap.
type desktopAppRescapData struct {
	AumID        string
	ShortcutPath string
}

// lockScreenComponentData represents rescap3:LockScreenComponent.
type lockScreenComponentData struct {
	Category string
}

// --- rescap4 namespace extensions ---

// classicAppCompatKeysData represents rescap4:ClassicAppCompatKeys.
type classicAppCompatKeysData struct {
	Keys []classicAppCompatKeyData
}

// classicAppCompatKeyData is a single compat key.
type classicAppCompatKeyData struct {
	Name      string
	ValueName string
	Value     string
	ValueType string
}

// primaryInteropAssembliesData represents rescap4:PrimaryInteropAssemblies.
type primaryInteropAssembliesData struct{}

// --- rescap6 namespace extensions ---

// modificationPackageData represents rescap6:ModificationPackage.
// (Used as a property, declared in Properties.)
type modificationPackageData struct{}
