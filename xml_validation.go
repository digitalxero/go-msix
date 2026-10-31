package msix

import (
	"fmt"
	"reflect"
	"unicode/utf8"
)

func validXMLText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0xfffe || r == 0xffff {
			return false
		}
	}
	return true
}

// Inspect every string, including nested extensions, before template execution.
// Unlike encoding/xml's replacement behavior, this never changes signed identity.
func validateManifestXML(m *manifestData) error {
	return validateXMLValue(reflect.ValueOf(m), "manifest")
}
func validateXMLValue(v reflect.Value, field string) error {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			return validateXMLValue(v.Elem(), field)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if err := validateXMLValue(v.Field(i), field+"."+v.Type().Field(i).Name); err != nil {
				return err
			}
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			if err := validateXMLValue(v.Index(i), fmt.Sprintf("%s[%d]", field, i)); err != nil {
				return err
			}
		}
	case reflect.String:
		if !validXMLText(v.String()) {
			return fmt.Errorf("msix: %s contains invalid UTF-8 or XML 1.0 characters", field)
		}
	}
	return nil
}
