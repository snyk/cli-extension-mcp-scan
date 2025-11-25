//go:build darwin && arm64
// +build darwin,arm64

package runner

import _ "embed"

//go:embed mcp-scan-0.3.31-macos-arm64
var binaryData []byte
