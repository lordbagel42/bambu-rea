//go:build !(cgo && linux)

// bambu-tunnel needs cgo on Linux to load libBambuSource.so.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "bambu-tunnel: built without cgo; rebuild with CGO_ENABLED=1 on Linux")
	os.Exit(2)
}
