package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/gophercloud/gophercloud"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/pkg/errors"
	"github.com/vasiliy-t/cert-manager-webhook-vkcloud/vkcloud"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var GroupName = os.Getenv("GROUP_NAME")

type CreateZoneRequest struct {
	SoaRefresh    int    `json:"soa_refresh"`
	SoaRetry      int    `json:"soa_retry"`
	SoaExpire     int    `json:"soa_expire"`
	SoaPrimaryDNS string `json:"soa_primary_dns"`
	Zone          string `json:"zone"`
	SoaTtl        int    `json:"soa_ttl"`
	SoaSerial     int    `json:"soa_serial"`
	SoaAdminEmail string `json:"soa_admin_email"`
}

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&customDNSProviderSolver{},
	)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type customDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client *kubernetes.Clientset
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type customDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	//Email           string `json:"email"`
	//APIKeySecretRef v1alpha1.SecretKeySelector `json:"apiKeySecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *customDNSProviderSolver) Name() string {
	return "my-custom-solver"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *customDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	fmt.Println("Present")
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}
	fmt.Println("Loaded config")

	authOpts, err := c.AuthOptsFromConfig(cfg, ch.ResourceNamespace)
	if err != nil {
		fmt.Println(err)
		return err
	}

	client, err := vkcloud.NewClient(authOpts)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("Created Openstack Provider")

	zone, err := client.GetZone(ch.ResolvedZone)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("Found zone")

	recordToCreate := &vkcloud.Record{
		Name:    extractRR(ch.ResolvedFQDN, ch.ResolvedZone),
		Content: ch.Key,
		TTL:     3600,
	}
	fmt.Println(recordToCreate)
	if err := client.CreateRecord(zone, recordToCreate); err != nil {
		return err
	}
	fmt.Println("Create record")

	return nil
}

func extractRR(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+domain); idx != -1 {
		return name[:idx]
	}

	return name
}

func (c *customDNSProviderSolver) AuthOptsFromConfig(cfg vkcloud.Config, ns string) (gophercloud.AuthOptions, error) {
	opts := gophercloud.AuthOptions{}
	osAuthUrl, err := c.getSecretData(cfg.OSAuthURLSecretRef, ns)
	if err != nil {
		return gophercloud.AuthOptions{}, err
	}
	opts.IdentityEndpoint = string(osAuthUrl)

	osUsername, err := c.getSecretData(cfg.OSUsernameSecretRef, ns)
	if err != nil {
		return gophercloud.AuthOptions{}, err
	}
	opts.Username = string(osUsername)

	osPassword, err := c.getSecretData(cfg.OSPasswordSecretRef, ns)
	if err != nil {
		return gophercloud.AuthOptions{}, err
	}
	opts.Password = string(osPassword)

	osProjectID, err := c.getSecretData(cfg.OSProjectIDSecretRef, ns)
	if err != nil {
		return gophercloud.AuthOptions{}, err
	}
	opts.TenantID = string(osProjectID)

	osDomainName, err := c.getSecretData(cfg.OSDomainNameSecretRef, ns)
	if err != nil {
		return gophercloud.AuthOptions{}, err
	}
	opts.DomainName = string(osDomainName)

	return opts, nil
}

func (c *customDNSProviderSolver) getSecretData(selector core.SecretKeySelector, ns string) ([]byte, error) {
	secret, err := c.client.CoreV1().Secrets(ns).Get(context.TODO(), selector.Name, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load secret %q", ns+"/"+selector.Name)
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}

	return nil, errors.Errorf("no key %q in secret %q", selector.Key, ns+"/"+selector.Name)
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *customDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	fmt.Println("CleanUp")
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}
	fmt.Print(ch)

	authOpts, err := c.AuthOptsFromConfig(cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	client, err := vkcloud.NewClient(authOpts)
	if err != nil {
		return err
	}

	zone, err := client.GetZone(ch.ResolvedZone)
	if err != nil {
		return err
	}

	record, err := client.FindRecordByContent(zone, ch.Key)
	if err != nil {
		if errors.As(err, &vkcloud.RecrodNotFoundErr{}) {
			fmt.Printf("record not found")
			return nil
		}
		return err
	}

	if err := client.DeleteRecord(zone, record); err != nil {
		return err
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *customDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (vkcloud.Config, error) {
	cfg := vkcloud.Config{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
