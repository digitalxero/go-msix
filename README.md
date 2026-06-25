# go-msix

A pure Go library for creating MSIX packages programmatically, with optional code signing support.

## Features

- Build MSIX packages entirely in Go — no external tools or Windows SDK required
- **Streaming**: payload files are never fully loaded into memory. Building a multi-GB
  package uses only a few MB of heap (signed or unsigned).
- Fluent, type-safe builder API — every component is an interface with a builder
- Code sign packages using PFX/P12 certificates or an explicit certificate + key
- AppxManifest.xml support for UAP, desktop, COM, restricted-capability and
  package-level extensions
- Correct 64KB block compression and AppxBlockMap generation per Microsoft spec
- Deterministic, reproducible output

## Install

```
go get go.digitalxero.dev/go-msix
```

## Usage

### Build an unsigned package

```go
package main

import (
	"context"
	"os"

	"go.digitalxero.dev/go-msix"
)

func main() {
	f, err := os.Create("MyApp.msix")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	err = msix.NewBuilder().
		WithIdentity(msix.NewIdentity().
			WithName("MyCompany.MyApp").
			WithVersion("1.0.0.0").
			WithPublisher("CN=MyCompany").
			WithProcessorArchitecture("x64").
			Build()).
		WithProperties(msix.NewProperties().
			WithDisplayName("My App").
			WithPublisherDisplayName("My Company").
			WithLogo(`Assets\StoreLogo.png`).
			Build()).
		WithDependencies(msix.NewDependencies().
			AddTargetDeviceFamily("Windows.Desktop", "10.0.17763.0", "10.0.22621.0").
			Build()).
		WithCapabilities(msix.NewCapabilities().
			AddRestricted("runFullTrust").
			Build()).
		AddResource(msix.NewResource().WithLanguage("en-us").Build()).
		AddApplication(msix.NewApplication().
			WithID("App").
			WithExecutable("MyApp.exe").
			WithEntryPoint("Windows.FullTrustApplication").
			WithVisualElements(msix.NewVisualElements().
				WithDisplayName("My App").
				WithBackgroundColor("#464646").
				WithSquare150x150Logo(`Assets\Square150x150Logo.png`).
				WithSquare44x44Logo(`Assets\Square44x44Logo.png`).
				Build()).
			Build()).
		AddFile(`Assets\StoreLogo.png`, "/path/to/StoreLogo.png").
		AddFile(`Assets\Square150x150Logo.png`, "/path/to/Square150x150Logo.png").
		AddFile(`Assets\Square44x44Logo.png`, "/path/to/Square44x44Logo.png").
		AddFile("MyApp.exe", "/path/to/MyApp.exe").
		Build(context.Background(), f)
	if err != nil {
		panic(err)
	}
}
```

Configuration and payload-source errors are deferred and returned from `Build`.

### Build a signed package

```go
err := msix.NewBuilder().
	// ... identity, properties, dependencies, application as above ...
	WithSigning(msix.NewSigning().WithPFX("certificate.pfx", "password").Build()).
	Build(context.Background(), f)
```

Or supply the certificate and key directly:

```go
cert, key, chain, err := msix.LoadPFX("certificate.pfx", "password")
if err != nil {
	panic(err)
}

signing := msix.NewSigning().
	WithCertificate(cert).
	WithPrivateKey(key).
	WithCertChain(chain...).
	Build()

err = msix.NewBuilder().
	// ... manifest configuration ...
	WithSigning(signing).
	Build(context.Background(), f)
```

### Adding files (streaming)

All payloads are streamed; their contents are never fully held in memory.

```go
// From disk — opened lazily and streamed during Build
b.AddFile(`Assets\logo.png`, "/path/to/logo.png")

// From bytes (kept in memory — for small, already-loaded data)
b.AddFileFromBytes("config.json", jsonData)

// From a one-shot reader — streamed to a temp file so it can be re-read during Build
b.AddFileFromReader("data.bin", reader)

// From a custom re-openable source — streamed, never buffered
b.AddFileSource("big.dat", func() (io.ReadCloser, error) {
	return os.Open("/path/to/big.dat")
})
```

### Application extensions

Extensions are added with their own builders:

```go
app := msix.NewApplication().
	WithID("App").
	WithExecutable("MyApp.exe").
	AddExtension(msix.NewProtocol().WithName("myapp-scheme").Build()).
	AddExtension(msix.NewFileTypeAssociation().
		WithName("myfiles").
		AddSupportedFileType(msix.NewFileType().WithExtension(".myf").Build()).
		Build()).
	Build()
```

## Requirements

- Go 1.23 or later

## License

See [LICENSE](LICENSE) for details.
