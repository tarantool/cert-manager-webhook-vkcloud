package main

import (
	"os"
	"testing"

	"github.com/jetstack/cert-manager/test/acme/dns"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.
	//

	// Uncomment the below fixture when implementing your custom DNS provider
	//fixture := dns.NewFixture(&customDNSProviderSolver{},
	//	dns.SetResolvedZone(zone),
	//	dns.SetAllowAmbientCredentials(false),
	//	dns.SetManifestPath("testdata/my-custom-solver"),
	//	dns.SetBinariesPath("_test/kubebuilder/bin"),
	//)

	fixture := dns.NewFixture(&customDNSProviderSolver{},
		dns.SetResolvedZone("example.com."),
		dns.SetManifestPath("testdata/vkcloud-solver"),
		dns.SetBinariesPath("_test/kubebuilder/bin"),
		dns.SetDNSServer("ns2.mcs.mail.ru:53"),
		dns.SetUseAuthoritative(false),
	)

	fixture.RunConformance(t)
}
