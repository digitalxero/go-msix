package msix

// --- rescap/rescap3 namespace extensions ---

// DesktopAppMigrationRescap represents rescap3:DesktopAppMigration (package-level).
type DesktopAppMigrationRescap struct {
	DesktopApps []DesktopAppRescap
}

// DesktopAppRescap within DesktopAppMigrationRescap.
type DesktopAppRescap struct {
	AumID        string
	ShortcutPath string
}

// LockScreenComponent represents rescap3:LockScreenComponent.
type LockScreenComponent struct {
	Category string
}

// --- rescap4 namespace extensions ---

// ClassicAppCompatKeys represents rescap4:ClassicAppCompatKeys.
type ClassicAppCompatKeys struct {
	Keys []ClassicAppCompatKey
}

// ClassicAppCompatKey is a single compat key.
type ClassicAppCompatKey struct {
	Name      string
	ValueName string
	Value     string
	ValueType string
}

// PrimaryInteropAssemblies represents rescap4:PrimaryInteropAssemblies.
type PrimaryInteropAssemblies struct{}

// --- rescap6 namespace extensions ---

// ModificationPackage represents rescap6:ModificationPackage.
// (Used as a property, declared in Properties.)
type ModificationPackage struct{}
