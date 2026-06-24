package msix

// --- com namespace extensions ---

// comServerData represents com:ComServer for COM server registration.
type comServerData struct {
	ExeServer       *exeServerData
	SurrogateServer *surrogateServerData
	InProcessServer *inProcessServerData
}

// exeServerData represents com:ExeServer.
type exeServerData struct {
	Executable                    string
	DisplayName                   string
	LaunchAndActivationPermission string
	Classes                       []comClassData
}

// surrogateServerData represents com:SurrogateServer.
type surrogateServerData struct {
	DisplayName string
	AppID       string
	Classes     []comClassData
}

// inProcessServerData represents com:InProcessServer within ComServer.
type inProcessServerData struct {
	Path    string
	Classes []comClassData
}

// comClassData represents a COM class registration.
type comClassData struct {
	ID                       string // CLSID
	DisplayName              string
	ProgID                   string
	ThreadingModel           string // "Both", "STA", "MTA", "Free"
	VersionIndependentProgID string
	Verbs                    []comVerbData
}

// comVerbData represents a verb for a COM class.
type comVerbData struct {
	ID          int
	DisplayName string
}

// comInterfaceData represents com:ComInterface for interface/ProxyStub registration.
type comInterfaceData struct {
	Interfaces     []interfaceEntryData
	ProxyStubs     []proxyStubData
	TreatAsClasses []treatAsClassData
}

// interfaceEntryData represents a COM interface.
type interfaceEntryData struct {
	ID               string // IID
	ProxyStubCLSID   string
	ProxyStubCLSID32 string
	TypeLibID        string
	TypeLibVersion   string
}

// proxyStubData represents a COM proxy/stub.
type proxyStubData struct {
	ID          string // CLSID
	DisplayName string
	Path        string
	Path32      string
}

// treatAsClassData maps one CLSID to another.
type treatAsClassData struct {
	ID      string // source CLSID
	TreatAs string // target CLSID
}
