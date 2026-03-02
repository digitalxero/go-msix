package msix

// --- com namespace extensions ---

// ComServer represents com:ComServer for COM server registration.
type ComServer struct {
	ExeServer       *ExeServer
	SurrogateServer *SurrogateServer
	InProcessServer *InProcessServer
}

// ExeServer represents com:ExeServer.
type ExeServer struct {
	Executable  string
	DisplayName string
	LaunchAndActivationPermission string
	Classes     []ComClass
}

// SurrogateServer represents com:SurrogateServer.
type SurrogateServer struct {
	DisplayName string
	AppID       string
	Classes     []ComClass
}

// InProcessServer represents com:InProcessServer within ComServer.
type InProcessServer struct {
	Path    string
	Classes []ComClass
}

// ComClass represents a COM class registration.
type ComClass struct {
	ID          string // CLSID
	DisplayName string
	ProgID      string
	ThreadingModel string // "Both", "STA", "MTA", "Free"
	VersionIndependentProgID string
	Verbs       []ComVerb
}

// ComVerb represents a verb for a COM class.
type ComVerb struct {
	ID          int
	DisplayName string
}

// ComInterface represents com:ComInterface for interface/ProxyStub registration.
type ComInterface struct {
	Interfaces     []InterfaceEntry
	ProxyStubs     []ProxyStub
	TreatAsClasses []TreatAsClass
}

// InterfaceEntry represents a COM interface.
type InterfaceEntry struct {
	ID              string // IID
	ProxyStubCLSID  string
	ProxyStubCLSID32 string
	TypeLibID       string
	TypeLibVersion  string
}

// ProxyStub represents a COM proxy/stub.
type ProxyStub struct {
	ID          string // CLSID
	DisplayName string
	Path        string
	Path32      string
}

// TreatAsClass maps one CLSID to another.
type TreatAsClass struct {
	ID        string // source CLSID
	TreatAs   string // target CLSID
}
