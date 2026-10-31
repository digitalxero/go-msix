package msix

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var asciiIdentifier = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
var applicationIdentifier = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(\.[A-Za-z][A-Za-z0-9]*)*$`)
var protocolScheme = regexp.MustCompile(`^[a-z][a-z0-9+.-]+$`)

const dnKeyPattern = `(CN|L|O|OU|E|C|S|STREET|T|G|I|SN|DC|SERIALNUMBER|Description|PostalCode|POBox|Phone|X21Address|dnQualifier|OID\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))+)`
const dnValuePattern = `([^,+=\x00-\x1f"<>#;]+|"([^"\x00-\x1f]|"")*")`

var publisherPattern = regexp.MustCompile(`^` + dnKeyPattern + `=` + dnValuePattern + `(, ` + dnKeyPattern + `=` + dnValuePattern + `)*$`)

func validVersion(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
		if _, err := strconv.ParseUint(p, 10, 16); err != nil {
			return false
		}
	}
	return true
}
func validatePublisher(s string) error {
	if !validXMLText(s) || utf8.RuneCountInString(s) > 8192 || strings.TrimSpace(s) != s || !publisherPattern.MatchString(s) {
		return errors.New("msix: identity publisher must be a Windows distinguished name (comma-space separators, quoted reserved characters, maximum 8192 characters)")
	}
	return nil
}
func validateCoreManifest(m *manifestData) error {
	var errs []error
	check := func(ok bool, field, rule string) {
		if !ok {
			errs = append(errs, fmt.Errorf("msix: %s %s", field, rule))
		}
	}
	id := m.Identity
	check(len(id.Name) >= 3 && len(id.Name) <= 50 && asciiIdentifier.MatchString(id.Name), "identity name", "must contain 3-50 ASCII letters, digits, periods or hyphens")
	check(validVersion(id.Version), "identity version", "must have four decimal components in 0..65535 without leading zeroes")
	if err := validatePublisher(id.Publisher); err != nil {
		errs = append(errs, err)
	}
	check(id.ResourceID == "" || (len(id.ResourceID) <= 30 && asciiIdentifier.MatchString(id.ResourceID)), "identity resource ID", "must contain at most 30 ASCII letters, digits, periods or hyphens")
	switch id.ProcessorArchitecture {
	case "", "x86", "x64", "arm", "arm64", "x86a64", "neutral":
	default:
		check(false, "identity processor architecture", "is unsupported")
	}

	if m.Properties.ResourcePackage {
		check(id.ProcessorArchitecture == "", "resource package identity processor architecture", "must be omitted")
		check(id.ResourceID != "", "resource package identity resource ID", "is required")
		check(len(m.Applications) == 0, "resource package applications", "must be omitted")
	}
	for i, r := range m.Resources {
		check(r.Scale == "" || r.DXFeatureLevel == "", fmt.Sprintf("resource[%d]", i), "must not combine Scale and DXFeatureLevel on one element")
	}

	check(len(m.Dependencies.TargetDeviceFamilies) > 0 && len(m.Dependencies.TargetDeviceFamilies) <= 128, "dependencies target device families", "must contain 1-128 entries")
	for i, d := range m.Dependencies.TargetDeviceFamilies {
		field := fmt.Sprintf("dependencies target device family[%d]", i)
		check(asciiIdentifier.MatchString(d.Name), field+" name", "must be an ASCII identifier")
		check(validVersion(d.MinVersion), field+" minimum version", "must be a four-component version")
		check(validVersion(d.MaxVersionTested), field+" maximum version tested", "must be a four-component version")
	}
	for i, d := range m.Dependencies.PackageDependencies {
		field := fmt.Sprintf("package dependency[%d]", i)
		check(len(d.Name) >= 3 && len(d.Name) <= 50 && asciiIdentifier.MatchString(d.Name), field+" name", "must be a package name")
		check(validVersion(d.MinVersion), field+" minimum version", "must be a four-component version")
		if err := validatePublisher(d.Publisher); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", field, err))
		}
	}

	text := func(s, field string, max int, required bool) {
		if !required && s == "" {
			return
		}
		check(s != "" && strings.TrimSpace(s) == s && (utf8.RuneCountInString(s) <= max || (strings.HasPrefix(s, "ms-resource:") && len(strings.TrimPrefix(s, "ms-resource:")) > 0 && utf8.RuneCountInString(strings.TrimPrefix(s, "ms-resource:")) <= 256)), field, fmt.Sprintf("must contain 1-%d characters with no leading or trailing whitespace", max))
	}
	imagePath := func(value, field string) {
		p, err := manifestPath(value)
		ext := path.Ext(p)
		check(err == nil && utf8.RuneCountInString(value) <= 256 && (ext == ".png" || ext == ".jpg" || ext == ".jpeg"), field, "must be a package-relative .png, .jpg or .jpeg path of at most 256 characters")
	}
	imagePath(m.Properties.Logo, "properties logo")
	text(m.Properties.DisplayName, "properties display name", 256, true)
	text(m.Properties.PublisherDisplayName, "properties publisher display name", 256, true)
	text(m.Properties.Description, "properties description", 2048, false)
	check(!strings.ContainsFunc(m.Properties.Description, func(r rune) bool { return r < 0x20 }), "properties description", "must not contain control characters")
	text(m.Properties.Logo, "properties logo", 256, true)
	for i, a := range m.Applications {
		field := fmt.Sprintf("application[%d]", i)
		check(len(a.ID) <= 64 && applicationIdentifier.MatchString(a.ID), field+" id", "must be an ASCII alphanumeric dotted identifier starting each segment with a letter")
		text(a.EntryPoint, field+" entry point", 256, false)
		check(a.ResourceGroup == "" || (len(a.ResourceGroup) <= 255 && applicationIdentifier.MatchString(a.ResourceGroup)), field+" resource group", "must be an ASCII Windows identifier")
		if a.Executable != "" {
			p, err := manifestPath(a.Executable)
			check(err == nil && len(a.Executable) <= 256 && strings.EqualFold(path.Ext(p), ".exe"), field+" executable", "must be a package-relative .exe path of at most 256 characters")
		}
		v := a.VisualElements
		text(v.DisplayName, field+" display name", 256, true)
		text(v.Description, field+" description", 2048, true)
		check(!strings.ContainsFunc(v.Description, func(r rune) bool { return r < 0x20 }), field+" description", "must not contain control characters")
		imagePath(v.Square150x150Logo, field+" square 150x150 logo")
		imagePath(v.Square44x44Logo, field+" square 44x44 logo")
		check(v.AppListEntry == "" || v.AppListEntry == "default" || v.AppListEntry == "none", field+" app list entry", "must be default or none")
	}
	return errors.Join(errs...)
}

func manifestPath(value string) (string, error) {
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, `\`) {
		return "", fmt.Errorf("manifest path %q must be relative", value)
	}
	return payloadPath(value)
}

// Validate references using Windows path identity. MRT may select a qualified
// image in a language/scale subdirectory instead of the unqualified base name.
func (b *builder) validateReferences(m *manifestData) error {
	files := map[string]bool{}
	for _, f := range b.files {
		files[windowsPathKey(f.packagePath)] = true
	}
	var errs []error
	check := func(value, field string, asset bool) {
		if value == "" {
			return
		}
		// Resource references are resolved at activation by MRT, not as literal parts.
		if asset && strings.HasPrefix(value, "ms-resource:") {
			return
		}
		p, err := manifestPath(value)
		if err != nil {
			errs = append(errs, fmt.Errorf("msix: %s: %w", field, err))
			return
		}
		if files[windowsPathKey(p)] {
			return
		}
		if asset {
			for _, f := range b.files {
				if qualifiedAssetMatches(p, f.packagePath) {
					return
				}
			}
		}
		errs = append(errs, fmt.Errorf("msix: %s references missing payload %q", field, value))
	}
	check(m.Properties.Logo, "properties logo", true)
	for i, a := range m.Applications {
		field := fmt.Sprintf("application[%d]", i)
		check(a.Executable, field+" executable", false)
		check(a.VisualElements.Square150x150Logo, field+" square 150x150 logo", true)
		check(a.VisualElements.Square44x44Logo, field+" square 44x44 logo", true)
		if v := a.VisualElements.DefaultTile; v != nil {
			check(v.Wide310x150Logo, field+" wide tile logo", true)
			check(v.Square71x71Logo, field+" square 71x71 logo", true)
			check(v.Square310x310Logo, field+" square 310x310 logo", true)
		}
		if v := a.VisualElements.SplashScreen; v != nil {
			check(v.Image, field+" splash image", true)
		}
	}
	return errors.Join(errs...)
}

// Only documented MRT qualifiers count, so an unrelated same-named file cannot
// hide a missing image. Both dot-qualified files and qualifier directories work.
var assetQualifier = regexp.MustCompile(`(?i)^(scale-[0-9]+|targetsize-[0-9]+|contrast-(standard|high|black|white)|altform-(unplated|lightunplated)|language-[a-z0-9-]+|[a-z]{2,3}(-[a-z0-9]{2,8})*)$`)

func qualifiedAssetMatches(reference, candidate string) bool {
	ref := strings.Split(windowsPathKey(reference), "/")
	got := strings.Split(windowsPathKey(candidate), "/")
	ext := path.Ext(ref[len(ref)-1])
	base := strings.TrimSuffix(ref[len(ref)-1], ext)
	leaf := got[len(got)-1]
	if path.Ext(leaf) != ext {
		return false
	}
	stem := strings.TrimSuffix(leaf, ext)
	if stem != base {
		if !strings.HasPrefix(stem, base+".") {
			return false
		}
		for _, q := range strings.Split(strings.TrimPrefix(stem, base+"."), "_") {
			if !assetQualifier.MatchString(q) {
				return false
			}
		}
	}
	ri := 0
	for _, segment := range got[:len(got)-1] {
		if ri < len(ref)-1 && segment == ref[ri] {
			ri++
			continue
		}
		if !assetQualifier.MatchString(segment) {
			return false
		}
	}
	return ri == len(ref)-1
}

func validateRegistrationIdentities(m *manifestData) error {
	apps, protocols, services, shortcuts := map[string]string{}, map[string]string{}, map[string]string{}, map[string]string{}
	var errs []error
	claim := func(owners map[string]string, key, field string) {
		if key == "" {
			return
		}
		if owner, ok := owners[key]; ok {
			errs = append(errs, fmt.Errorf("msix: %s duplicates registration owned by %s", field, owner))
		} else {
			owners[key] = field
		}
	}
	for i, a := range m.Applications {
		field := fmt.Sprintf("application[%d]", i)
		// Application Id uses the schema's case-sensitive xs:unique identity.
		claim(apps, a.ID, field+" id "+a.ID)
		for j, e := range a.Extensions {
			ext := fmt.Sprintf("%s extension[%d]", field, j)
			if e.Protocol != nil {
				claim(protocols, strings.ToLower(e.Protocol.Name), ext+" protocol "+e.Protocol.Name)
				if len(e.Protocol.Name) > 2048 || !protocolScheme.MatchString(e.Protocol.Name) {
					errs = append(errs, fmt.Errorf("msix: %s protocol name must be a lowercase URI scheme", ext))
				}
			}
			if e.ProtocolUap10 != nil {
				claim(protocols, strings.ToLower(e.ProtocolUap10.Name), ext+" protocol "+e.ProtocolUap10.Name)
			}
			if e.Service != nil {
				claim(services, strings.ToUpper(e.Service.Name), ext+" service "+e.Service.Name)
			}
			if e.ServiceDesktop7 != nil {
				claim(services, strings.ToUpper(e.ServiceDesktop7.Name), ext+" service "+e.ServiceDesktop7.Name)
			}
			if e.Shortcut != nil {
				key, err := shortcutIdentity(e.Shortcut.File)
				if err != nil {
					errs = append(errs, fmt.Errorf("msix: %s shortcut: %w", ext, err))
				} else {
					claim(shortcuts, key, ext+" shortcut "+e.Shortcut.File)
				}
			}
		}
	}
	return errors.Join(errs...)
}

// These constants name different destinations. Case/separator variants of one
// constant are aliases; Programs and Common Programs must remain distinct.
func shortcutIdentity(value string) (string, error) {
	normalized := strings.ReplaceAll(value, `\`, "/")
	root, relative, ok := strings.Cut(normalized, "/")
	switch windowsPathKey(root) {
	case "$(DESKTOP)", "$(PROGRAMS)", "$(COMMON PROGRAMS)":
	default:
		return "", fmt.Errorf("file %q must use a supported shortcut directory constant", value)
	}
	if !ok || strings.HasPrefix(relative, "/") {
		return "", fmt.Errorf("invalid shortcut file %q", value)
	}
	relative, err := manifestPath(relative)
	if err != nil {
		return "", err
	}
	return windowsPathKey(root + "/" + relative), nil
}
