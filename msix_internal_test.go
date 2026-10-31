package msix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		got, err := payloadPath(tt.input)
		require.NoError(t, err)
		assert.Equal(t, tt.want, got)
	}
}
