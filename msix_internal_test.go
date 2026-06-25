package msix

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizePackagePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"test.txt", "test.txt"},
		{"/test.txt", "test.txt"},
		{"dir/file.txt", "dir/file.txt"},
		{"dir\\file.txt", "dir/file.txt"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, normalizePackagePath(tt.input), "normalizePackagePath(%q)", tt.input)
	}
}
