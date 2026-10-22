package blob

import "runtime/debug"

const modulePath = "github.com/upstash/blob-go"

// Version is the SDK version sent in telemetry headers: the module version the program was built
// with, read from its build info, or "v0.0.0" when there is none (a local checkout, a replace).
var Version = moduleVersion()

func moduleVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, m := range append([]*debug.Module{&info.Main}, info.Deps...) {
			if m.Path == modulePath && m.Version != "" && m.Version != "(devel)" {
				return m.Version
			}
		}
	}
	return "v0.0.0"
}
