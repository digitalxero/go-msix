package msix

// This file defines the public builder-is-implementation API for the core
// (non-extension) manifest types. Each type exposes a runtime interface (a sealed
// marker) and a builder interface; the unexported impl wraps the internal *Data
// struct consumed by the template and exposes an unexported data() accessor used by
// the translation in Builder.Build.

// --- Identity ---

// Identity is the runtime view of the package identity.
type Identity interface{ isIdentity() }

// IdentityBuilder builds an Identity.
type IdentityBuilder interface {
	WithName(string) IdentityBuilder
	WithVersion(string) IdentityBuilder
	WithPublisher(string) IdentityBuilder
	WithProcessorArchitecture(string) IdentityBuilder
	WithResourceID(string) IdentityBuilder
	Build() Identity
}

// NewIdentity returns a new IdentityBuilder.
func NewIdentity() IdentityBuilder { return &identity{} }

type identity struct{ d identityData }

func (i *identity) WithName(s string) IdentityBuilder      { i.d.Name = s; return i }
func (i *identity) WithVersion(s string) IdentityBuilder   { i.d.Version = s; return i }
func (i *identity) WithPublisher(s string) IdentityBuilder { i.d.Publisher = s; return i }
func (i *identity) WithProcessorArchitecture(s string) IdentityBuilder {
	i.d.ProcessorArchitecture = s
	return i
}
func (i *identity) WithResourceID(s string) IdentityBuilder { i.d.ResourceID = s; return i }
func (i *identity) Build() Identity                         { return i }
func (i *identity) isIdentity()                             {}
func (i *identity) data() identityData                      { return i.d }

// --- Properties ---

// Properties is the runtime view of package properties.
type Properties interface{ isProperties() }

// PropertiesBuilder builds Properties.
type PropertiesBuilder interface {
	WithDisplayName(string) PropertiesBuilder
	WithPublisherDisplayName(string) PropertiesBuilder
	WithLogo(string) PropertiesBuilder
	WithDescription(string) PropertiesBuilder
	WithFramework(bool) PropertiesBuilder
	WithResourcePackage(bool) PropertiesBuilder
	WithAllowExecution(bool) PropertiesBuilder
	WithModificationPackage(bool) PropertiesBuilder
	Build() Properties
}

// NewProperties returns a new PropertiesBuilder.
func NewProperties() PropertiesBuilder { return &properties{} }

type properties struct{ d propertiesData }

func (p *properties) WithDisplayName(s string) PropertiesBuilder { p.d.DisplayName = s; return p }
func (p *properties) WithPublisherDisplayName(s string) PropertiesBuilder {
	p.d.PublisherDisplayName = s
	return p
}
func (p *properties) WithLogo(s string) PropertiesBuilder        { p.d.Logo = s; return p }
func (p *properties) WithDescription(s string) PropertiesBuilder { p.d.Description = s; return p }
func (p *properties) WithFramework(v bool) PropertiesBuilder     { p.d.Framework = v; return p }
func (p *properties) WithResourcePackage(v bool) PropertiesBuilder {
	p.d.ResourcePackage = v
	return p
}
func (p *properties) WithAllowExecution(v bool) PropertiesBuilder { p.d.AllowExecution = v; return p }
func (p *properties) WithModificationPackage(v bool) PropertiesBuilder {
	p.d.ModificationPackage = v
	return p
}
func (p *properties) Build() Properties    { return p }
func (p *properties) isProperties()        {}
func (p *properties) data() propertiesData { return p.d }

// --- Dependencies ---

// Dependencies is the runtime view of package dependencies.
type Dependencies interface{ isDependencies() }

// DependenciesBuilder builds Dependencies.
type DependenciesBuilder interface {
	AddTargetDeviceFamily(name, minVersion, maxVersionTested string) DependenciesBuilder
	AddPackageDependency(name, publisher, minVersion string) DependenciesBuilder
	Build() Dependencies
}

// NewDependencies returns a new DependenciesBuilder.
func NewDependencies() DependenciesBuilder { return &dependencies{} }

type dependencies struct{ d dependenciesData }

func (d *dependencies) AddTargetDeviceFamily(name, minVersion, maxVersionTested string) DependenciesBuilder {
	d.d.TargetDeviceFamilies = append(d.d.TargetDeviceFamilies, targetDeviceFamilyData{
		Name: name, MinVersion: minVersion, MaxVersionTested: maxVersionTested,
	})
	return d
}
func (d *dependencies) AddPackageDependency(name, publisher, minVersion string) DependenciesBuilder {
	d.d.PackageDependencies = append(d.d.PackageDependencies, packageDependencyData{
		Name: name, Publisher: publisher, MinVersion: minVersion,
	})
	return d
}
func (d *dependencies) Build() Dependencies    { return d }
func (d *dependencies) isDependencies()        {}
func (d *dependencies) data() dependenciesData { return d.d }

// --- Resource ---

// Resource is the runtime view of a Resources/Resource element.
type Resource interface{ isResource() }

// ResourceBuilder builds a Resource.
type ResourceBuilder interface {
	WithLanguage(string) ResourceBuilder
	WithScale(string) ResourceBuilder
	WithDXFeatureLevel(string) ResourceBuilder
	Build() Resource
}

// NewResource returns a new ResourceBuilder.
func NewResource() ResourceBuilder { return &resource{} }

type resource struct{ d resourceData }

func (r *resource) WithLanguage(s string) ResourceBuilder       { r.d.Language = s; return r }
func (r *resource) WithScale(s string) ResourceBuilder          { r.d.Scale = s; return r }
func (r *resource) WithDXFeatureLevel(s string) ResourceBuilder { r.d.DXFeatureLevel = s; return r }
func (r *resource) Build() Resource                             { return r }
func (r *resource) isResource()                                 {}
func (r *resource) data() resourceData                          { return r.d }

// --- DeviceFunction / Device / DeviceCapability ---

// DeviceFunction is the runtime view of a device function.
type DeviceFunction interface{ isDeviceFunction() }

// DeviceFunctionBuilder builds a DeviceFunction.
type DeviceFunctionBuilder interface {
	WithType(string) DeviceFunctionBuilder
	Build() DeviceFunction
}

// NewDeviceFunction returns a new DeviceFunctionBuilder.
func NewDeviceFunction() DeviceFunctionBuilder { return &deviceFunction{} }

type deviceFunction struct{ d deviceFunctionData }

func (f *deviceFunction) WithType(s string) DeviceFunctionBuilder { f.d.Type = s; return f }
func (f *deviceFunction) Build() DeviceFunction                   { return f }
func (f *deviceFunction) isDeviceFunction()                       {}
func (f *deviceFunction) data() deviceFunctionData                { return f.d }

// Device is the runtime view of a device within a DeviceCapability.
type Device interface{ isDevice() }

// DeviceBuilder builds a Device.
type DeviceBuilder interface {
	WithID(string) DeviceBuilder
	AddFunction(DeviceFunction) DeviceBuilder
	Build() Device
}

// NewDevice returns a new DeviceBuilder.
func NewDevice() DeviceBuilder { return &device{} }

type device struct {
	id    string
	funcs []DeviceFunction
}

func (d *device) WithID(s string) DeviceBuilder { d.id = s; return d }
func (d *device) AddFunction(f DeviceFunction) DeviceBuilder {
	d.funcs = append(d.funcs, f)
	return d
}
func (d *device) Build() Device { return d }
func (d *device) isDevice()     {}
func (d *device) data() deviceData {
	out := deviceData{ID: d.id}
	for _, f := range d.funcs {
		out.Functions = append(out.Functions, f.(*deviceFunction).data())
	}
	return out
}

// DeviceCapability is the runtime view of a device capability.
type DeviceCapability interface{ isDeviceCapability() }

// DeviceCapabilityBuilder builds a DeviceCapability.
type DeviceCapabilityBuilder interface {
	WithName(string) DeviceCapabilityBuilder
	AddDevice(Device) DeviceCapabilityBuilder
	Build() DeviceCapability
}

// NewDeviceCapability returns a new DeviceCapabilityBuilder.
func NewDeviceCapability() DeviceCapabilityBuilder { return &deviceCapability{} }

type deviceCapability struct {
	name    string
	devices []Device
}

func (c *deviceCapability) WithName(s string) DeviceCapabilityBuilder { c.name = s; return c }
func (c *deviceCapability) AddDevice(d Device) DeviceCapabilityBuilder {
	c.devices = append(c.devices, d)
	return c
}
func (c *deviceCapability) Build() DeviceCapability { return c }
func (c *deviceCapability) isDeviceCapability()     {}
func (c *deviceCapability) data() deviceCapabilityData {
	out := deviceCapabilityData{Name: c.name}
	for _, d := range c.devices {
		out.Devices = append(out.Devices, d.(*device).data())
	}
	return out
}

// --- Capabilities ---

// Capabilities is the runtime view of package capabilities.
type Capabilities interface{ isCapabilities() }

// CapabilitiesBuilder builds Capabilities.
type CapabilitiesBuilder interface {
	AddCapability(name string) CapabilitiesBuilder
	AddUAP(name string) CapabilitiesBuilder
	AddRestricted(name string) CapabilitiesBuilder
	AddCustom(name string) CapabilitiesBuilder
	AddDeviceCapability(DeviceCapability) CapabilitiesBuilder
	Build() Capabilities
}

// NewCapabilities returns a new CapabilitiesBuilder.
func NewCapabilities() CapabilitiesBuilder { return &capabilities{} }

type capabilities struct {
	d       capabilitiesData
	devices []DeviceCapability
}

func (c *capabilities) AddCapability(name string) CapabilitiesBuilder {
	c.d.Capabilities = append(c.d.Capabilities, capabilityData{Name: name})
	return c
}
func (c *capabilities) AddUAP(name string) CapabilitiesBuilder {
	c.d.UAP = append(c.d.UAP, uapCapabilityData{Name: name})
	return c
}
func (c *capabilities) AddRestricted(name string) CapabilitiesBuilder {
	c.d.Restricted = append(c.d.Restricted, restrictedCapabilityData{Name: name})
	return c
}
func (c *capabilities) AddCustom(name string) CapabilitiesBuilder {
	c.d.Custom = append(c.d.Custom, customCapabilityData{Name: name})
	return c
}
func (c *capabilities) AddDeviceCapability(dc DeviceCapability) CapabilitiesBuilder {
	c.devices = append(c.devices, dc)
	return c
}
func (c *capabilities) Build() Capabilities { return c }
func (c *capabilities) isCapabilities()     {}
func (c *capabilities) data() capabilitiesData {
	out := c.d
	for _, dc := range c.devices {
		out.DeviceCapabilities = append(out.DeviceCapabilities, dc.(*deviceCapability).data())
	}
	return out
}

// --- DefaultTile ---

// DefaultTile is the runtime view of uap:DefaultTile.
type DefaultTile interface{ isDefaultTile() }

// DefaultTileBuilder builds a DefaultTile.
type DefaultTileBuilder interface {
	WithWide310x150Logo(string) DefaultTileBuilder
	WithSquare71x71Logo(string) DefaultTileBuilder
	WithSquare310x310Logo(string) DefaultTileBuilder
	WithShortName(string) DefaultTileBuilder
	WithShowNameOnTiles(string) DefaultTileBuilder
	Build() DefaultTile
}

// NewDefaultTile returns a new DefaultTileBuilder.
func NewDefaultTile() DefaultTileBuilder { return &defaultTile{} }

type defaultTile struct{ d defaultTileData }

func (t *defaultTile) WithWide310x150Logo(s string) DefaultTileBuilder {
	t.d.Wide310x150Logo = s
	return t
}
func (t *defaultTile) WithSquare71x71Logo(s string) DefaultTileBuilder {
	t.d.Square71x71Logo = s
	return t
}
func (t *defaultTile) WithSquare310x310Logo(s string) DefaultTileBuilder {
	t.d.Square310x310Logo = s
	return t
}
func (t *defaultTile) WithShortName(s string) DefaultTileBuilder { t.d.ShortName = s; return t }
func (t *defaultTile) WithShowNameOnTiles(s string) DefaultTileBuilder {
	t.d.ShowNameOnTiles = s
	return t
}
func (t *defaultTile) Build() DefaultTile    { return t }
func (t *defaultTile) isDefaultTile()        {}
func (t *defaultTile) data() defaultTileData { return t.d }

// --- SplashScreen ---

// SplashScreen is the runtime view of uap:SplashScreen.
type SplashScreen interface{ isSplashScreen() }

// SplashScreenBuilder builds a SplashScreen.
type SplashScreenBuilder interface {
	WithImage(string) SplashScreenBuilder
	WithBackgroundColor(string) SplashScreenBuilder
	Build() SplashScreen
}

// NewSplashScreen returns a new SplashScreenBuilder.
func NewSplashScreen() SplashScreenBuilder { return &splashScreen{} }

type splashScreen struct{ d splashScreenData }

func (s *splashScreen) WithImage(v string) SplashScreenBuilder { s.d.Image = v; return s }
func (s *splashScreen) WithBackgroundColor(v string) SplashScreenBuilder {
	s.d.BackgroundColor = v
	return s
}
func (s *splashScreen) Build() SplashScreen    { return s }
func (s *splashScreen) isSplashScreen()        {}
func (s *splashScreen) data() splashScreenData { return s.d }

// --- VisualElements ---

// VisualElements is the runtime view of uap:VisualElements.
type VisualElements interface{ isVisualElements() }

// VisualElementsBuilder builds VisualElements.
type VisualElementsBuilder interface {
	WithDisplayName(string) VisualElementsBuilder
	WithDescription(string) VisualElementsBuilder
	WithBackgroundColor(string) VisualElementsBuilder
	WithSquare150x150Logo(string) VisualElementsBuilder
	WithSquare44x44Logo(string) VisualElementsBuilder
	WithAppListEntry(string) VisualElementsBuilder
	WithDefaultTile(DefaultTile) VisualElementsBuilder
	WithSplashScreen(SplashScreen) VisualElementsBuilder
	Build() VisualElements
}

// NewVisualElements returns a new VisualElementsBuilder.
func NewVisualElements() VisualElementsBuilder { return &visualElements{} }

type visualElements struct {
	d      visualElementsData
	tile   DefaultTile
	splash SplashScreen
}

func (v *visualElements) WithDisplayName(s string) VisualElementsBuilder {
	v.d.DisplayName = s
	return v
}
func (v *visualElements) WithDescription(s string) VisualElementsBuilder {
	v.d.Description = s
	return v
}
func (v *visualElements) WithBackgroundColor(s string) VisualElementsBuilder {
	v.d.BackgroundColor = s
	return v
}
func (v *visualElements) WithSquare150x150Logo(s string) VisualElementsBuilder {
	v.d.Square150x150Logo = s
	return v
}
func (v *visualElements) WithSquare44x44Logo(s string) VisualElementsBuilder {
	v.d.Square44x44Logo = s
	return v
}
func (v *visualElements) WithAppListEntry(s string) VisualElementsBuilder {
	v.d.AppListEntry = s
	return v
}
func (v *visualElements) WithDefaultTile(t DefaultTile) VisualElementsBuilder {
	v.tile = t
	return v
}
func (v *visualElements) WithSplashScreen(s SplashScreen) VisualElementsBuilder {
	v.splash = s
	return v
}
func (v *visualElements) Build() VisualElements { return v }
func (v *visualElements) isVisualElements()     {}
func (v *visualElements) data() visualElementsData {
	out := v.d
	if v.tile != nil {
		td := v.tile.(*defaultTile).data()
		out.DefaultTile = &td
	}
	if v.splash != nil {
		sd := v.splash.(*splashScreen).data()
		out.SplashScreen = &sd
	}
	return out
}

// --- Application ---

// Application is the runtime view of an application entry.
type Application interface{ isApplication() }

// ApplicationBuilder builds an Application.
type ApplicationBuilder interface {
	WithID(string) ApplicationBuilder
	WithExecutable(string) ApplicationBuilder
	WithEntryPoint(string) ApplicationBuilder
	WithStartPage(string) ApplicationBuilder
	WithResourceGroup(string) ApplicationBuilder
	WithVisualElements(VisualElements) ApplicationBuilder
	AddExtension(ApplicationExtension) ApplicationBuilder
	Build() Application
}

// NewApplication returns a new ApplicationBuilder.
func NewApplication() ApplicationBuilder { return &application{} }

type application struct {
	d    applicationData
	ve   VisualElements
	exts []ApplicationExtension
}

func (a *application) WithID(s string) ApplicationBuilder            { a.d.ID = s; return a }
func (a *application) WithExecutable(s string) ApplicationBuilder    { a.d.Executable = s; return a }
func (a *application) WithEntryPoint(s string) ApplicationBuilder    { a.d.EntryPoint = s; return a }
func (a *application) WithStartPage(s string) ApplicationBuilder     { a.d.StartPage = s; return a }
func (a *application) WithResourceGroup(s string) ApplicationBuilder { a.d.ResourceGroup = s; return a }
func (a *application) WithVisualElements(ve VisualElements) ApplicationBuilder {
	a.ve = ve
	return a
}
func (a *application) AddExtension(e ApplicationExtension) ApplicationBuilder {
	a.exts = append(a.exts, e)
	return a
}
func (a *application) Build() Application { return a }
func (a *application) isApplication()     {}
func (a *application) data() applicationData {
	out := a.d
	if a.ve != nil {
		out.VisualElements = a.ve.(*visualElements).data()
	}
	for _, e := range a.exts {
		out.Extensions = append(out.Extensions, e.toAppExtData())
	}
	return out
}
