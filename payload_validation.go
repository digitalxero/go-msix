package msix

import (
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// payloadPath retains the supported single root slash but never cleans traversal,
// UNC, empty segments, or unsupported Windows names into a different user path.
func payloadPath(value string) (string, error) {
	p := strings.ReplaceAll(value, `\`, "/")
	if !utf8.ValidString(p) || !validXMLText(p) || strings.HasPrefix(p, "//") {
		return "", fmt.Errorf("msix: payload path %q must be package-relative UTF-8", value)
	}
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return "", fmt.Errorf("msix: payload path %q is empty", value)
	}
	for _, segment := range strings.Split(p, "/") {
		if len(utf16.Encode([]rune(segment))) > 255 || segment == "" || segment == "." || segment == ".." || strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") || strings.ContainsAny(segment, `<>:"|?*`) || strings.ContainsFunc(segment, func(r rune) bool { return r < 0x20 }) {
			return "", fmt.Errorf("msix: payload path %q contains an unsupported Windows filename %q", value, segment)
		}
		device := windowsPathKey(strings.TrimRight(strings.SplitN(segment, ".", 2)[0], " "))
		if device == "CON" || device == "PRN" || device == "AUX" || device == "NUL" || device == "CONIN$" || device == "CONOUT$" || (len([]rune(device)) == 4 && (strings.HasPrefix(device, "COM") || strings.HasPrefix(device, "LPT")) && strings.ContainsRune("123456789¹²³", []rune(device)[3])) {
			return "", fmt.Errorf("msix: payload path %q uses reserved Windows device %q", value, segment)
		}
	}
	return p, nil
}

// Windows filesystem ownership is case insensitive and does not perform Unicode
// normalization. Keep this separate from case-sensitive manifest identities.
func windowsPathKey(p string) string { return strings.ToUpper(strings.ReplaceAll(p, `\`, "/")) }

func (b *builder) addFile(packagePath string, source fileSource) Builder {
	p, err := payloadPath(packagePath)
	if err != nil {
		b.errs = append(b.errs, err)
		return b
	}
	b.files = append(b.files, fileEntry{packagePath: p, source: source})
	return b
}

func (b *builder) validatePayloads() error {
	// CodeIntegrity.cat has a supported authoring path, spelled exactly as the SIP
	// catalog part name. Other AppxMetadata content is reserved for footprint data.
	owners := map[string]string{}
	dirs := map[string]string{}
	for _, name := range []string{"AppxManifest.xml", "AppxBlockMap.xml", "[Content_Types].xml", "AppxSignature.p7x", "AppxStreamMap.xml"} {
		owners[windowsPathKey(name)] = "generated " + name
	}
	for _, f := range b.files {
		key := windowsPathKey(f.packagePath)
		if key == "APPXMETADATA" || strings.HasPrefix(key, "APPXMETADATA/") {
			if f.packagePath != "AppxMetadata/CodeIntegrity.cat" {
				return fmt.Errorf("msix: payload %q conflicts with reserved AppxMetadata footprint", f.packagePath)
			}
		}
		if owner, ok := owners[key]; ok {
			return fmt.Errorf("msix: payload %q conflicts with %q", f.packagePath, owner)
		}
		if owner, ok := dirs[key]; ok {
			return fmt.Errorf("msix: payload %q conflicts with directory required by %q", f.packagePath, owner)
		}
		parts := strings.Split(key, "/")
		for i := 1; i < len(parts); i++ {
			ancestor := strings.Join(parts[:i], "/")
			if owner, ok := owners[ancestor]; ok {
				return fmt.Errorf("msix: payload %q conflicts with ancestor file %q", f.packagePath, owner)
			}
			dirs[ancestor] = f.packagePath
		}
		owners[key] = f.packagePath
	}
	return nil
}
