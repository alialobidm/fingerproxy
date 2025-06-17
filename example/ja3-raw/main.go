package main

import (
	"fmt"

	"github.com/dreadl0ck/tlsx"
	"github.com/subscan-explorer/fingerproxy"
	"github.com/subscan-explorer/fingerproxy/pkg/fingerprint"
	"github.com/subscan-explorer/fingerproxy/pkg/ja3"
	"github.com/subscan-explorer/fingerproxy/pkg/metadata"
	"github.com/subscan-explorer/fingerproxy/pkg/reverseproxy"
)

func main() {
	fingerproxy.GetHeaderInjectors = func() []reverseproxy.HeaderInjector {
		i := fingerproxy.DefaultHeaderInjectors()
		i = append(i, fingerprint.NewFingerprintHeaderInjector(
			"X-JA3-Raw-Fingerprint",
			fpJA3Raw,
		))
		return i
	}
	fingerproxy.Run()
}

func fpJA3Raw(data *metadata.Metadata) (string, error) {
	hellobasic := &tlsx.ClientHelloBasic{}
	if err := hellobasic.Unmarshal(data.ClientHelloRecord); err != nil {
		return "", fmt.Errorf("ja3: %w", err)
	}

	fp := string(ja3.Bare(hellobasic))

	return fp, nil
}
