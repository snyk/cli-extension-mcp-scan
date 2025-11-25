//go:build linux
// +build linux

package runner

import _ "embed"

// go:embed mcp-scan-0.3.31-linux-x86_64
var binaryData []byte
