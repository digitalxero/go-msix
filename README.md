# go-msix

A pure Go library for creating MSIX packages programmatically, with optional code signing support.

## Features

- Build MSIX packages entirely in Go — no external tools or Windows SDK required
- Code sign packages using PFX/P12 certificates
- Full AppxManifest.xml support including UAP, desktop, COM, and restricted capability extensions
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
	"os"

	"go.digitalxero.dev/go-msix"
)

func main() {
	b := msix.NewBuilder()

	b.Manifest = msix.Manifest{
		Identity: msix.Identity{
			Name:                  "MyCompany.MyApp",
			Version:               "1.0.0.0",
			Publisher:             "CN=MyCompany",
			ProcessorArchitecture: "x64",
		},
		Properties: msix.Properties{
			DisplayName:         "My App",
			PublisherDisplayName: "My Company",
			Logo:                "Assets\\StoreLogo.png",
		},
		Dependencies: msix.Dependencies{
			TargetDeviceFamilies: []msix.TargetDeviceFamily{
				{
					Name:             "Windows.Desktop",
					MinVersion:       "10.0.17763.0",
					MaxVersionTested: "10.0.22621.0",
				},
			},
		},
		Resources: []msix.Resource{
			{Language: "en-us"},
		},
		Applications: []msix.Application{
			{
				ID:         "App",
				Executable: "MyApp.exe",
				EntryPoint: "Windows.FullTrustApplication",
			},
		},
	}

	b.AddFileFromBytes("Assets\\StoreLogo.png", logoBytes)

	f, _ := os.Create("MyApp.msix")
	defer f.Close()

	if err := b.Build(f); err != nil {
		panic(err)
	}
}
```

### Build a signed package

```go
cert, key, chain, err := msix.LoadPFX("certificate.pfx", "password")
if err != nil {
	panic(err)
}

b := msix.NewBuilder()
b.SignOptions = &msix.SignOptions{
	Certificate: cert,
	PrivateKey:  key,
	CertChain:   chain,
}

// ... configure manifest and add files as above ...

f, _ := os.Create("MyApp.msix")
defer f.Close()

if err := b.Build(f); err != nil {
	panic(err)
}
```

### Adding files

```go
// From disk
b.AddFile("Assets\\logo.png", "/path/to/logo.png")

// From bytes
b.AddFileFromBytes("config.json", jsonData)

// From a reader
b.AddFileFromReader("data.bin", reader)
```

## Requirements

- Go 1.23 or later

## License

See [LICENSE](LICENSE) for details.
