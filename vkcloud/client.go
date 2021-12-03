package vkcloud

import (
	"fmt"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

type Client struct {
	providerClient *gophercloud.ProviderClient
	authOpts       gophercloud.AuthOptions
}

func NewClient(authOpts gophercloud.AuthOptions) (*Client, error) {
	c := &Client{}
	provider, err := openstack.AuthenticatedClient(authOpts)
	if err != nil {
		return nil, err
	}
	c.providerClient = provider
	c.authOpts = authOpts

	return c, nil
}

type Zone struct {
	UUID string `json:"uuid"`
	Zone string `json:"zone"`
}

type ZoneCollection []*Zone

type ZoneNotFoundError struct {
	msg string
}

func (e ZoneNotFoundError) Error() string {
	return e.msg
}

func (c *Client) GetZone(resolvedZone string) (*Zone, error) {
	zones := ZoneCollection{}
	_, err := c.providerClient.Request("GET", "https://mcs.mail.ru/public-dns/1.0.0/tenants/"+c.authOpts.TenantID+"/dns/", &gophercloud.RequestOpts{
		JSONResponse: &zones,
	})
	if err != nil {
		return nil, err
	}
	var zoneToControl *Zone
	zoneToFind := util.UnFqdn(resolvedZone)
	for _, z := range zones {
		if z.Zone == zoneToFind {
			zoneToControl = z
			break
		}
	}
	if zoneToControl == nil {
		return nil, ZoneNotFoundError{fmt.Sprintf("Zone %s not found", resolvedZone)}
	}

	return zoneToControl, nil
}

type Record struct {
	UUID    string `json:"uuid"`
	Content string `json:"content"`
	Name    string `json:"name"`
	TTL     int    `json:"ttl"`
}

type RecordCollection []*Record

type RecrodNotFoundErr struct {
	msg string
}

func (e RecrodNotFoundErr) Error() string {
	return e.msg
}

func (c *Client) FindRecordByContent(zone *Zone, content string) (*Record, error) {
	records := RecordCollection{}
	_, err := c.providerClient.Request("GET", "https://mcs.mail.ru/public-dns/1.0.0/tenants/"+string(c.authOpts.TenantID)+"/dns/"+string(zone.UUID)+"/txt/", &gophercloud.RequestOpts{
		JSONResponse: &records,
	})
	if err != nil {
		return nil, err
	}

	var needle *Record
	for _, r := range records {
		if r.Content == content {
			needle = r
			break
		}
	}
	if needle == nil {
		return nil, RecrodNotFoundErr{fmt.Sprintf("Record not found for zone %s", zone.Zone)}
	}

	return needle, nil
}

type CreateDNSRecordRequest struct {
	Content string `json:"content"`
	Name    string `json:"name"`
	TTL     int    `json:"ttl"`
}

func (c *Client) CreateRecord(zone *Zone, record *Record) error {
	_, err := c.providerClient.Request("POST", "https://mcs.mail.ru/public-dns/1.0.0/tenants/"+string(c.authOpts.TenantID)+"/dns/"+zone.UUID+"/txt/", &gophercloud.RequestOpts{
		JSONBody: &CreateDNSRecordRequest{
			Content: record.Content,
			Name:    record.Name,
			TTL:     record.TTL,
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) DeleteRecord(zone *Zone, record *Record) error {
	_, err := c.providerClient.Request("DELETE", "https://mcs.mail.ru/public-dns/1.0.0/tenants/"+string(c.authOpts.TenantID)+"/dns/"+string(zone.UUID)+"/txt/"+record.UUID, &gophercloud.RequestOpts{})
	if err != nil {
		return err
	}

	return nil
}
