package vpcmodel

import (
	"fmt"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

const (
	DetailsAttributeKind = "kind"
	DetailsAttributeName = "name"
	DetailsAttributeCIDR = "cidr"

	publicInternetNodeName = "PublicInternet"
)

// All public IP addresses belong to one of the following public IP address ranges:
func getPublicInternetAdressList() []string {
	return []string{
		"1.0.0.0-9.255.255.255",
		"11.0.0.0-100.63.255.255",
		"100.128.0.0-126.255.255.255",
		"128.0.0.0-169.253.255.255",
		"169.255.0.0-172.15.255.255",
		"172.32.0.0-191.255.255.255",
		"192.0.1.0/24",
		"192.0.3.0-192.88.98.255",
		"192.88.100.0-192.167.255.255",
		"192.169.0.0-198.17.255.255",
		"198.20.0.0-198.51.99.255",
		"198.51.101.0-203.0.112.255",
		"203.0.114.0-223.255.255.255",
	}
}

// ExternalNetwork implements Node interface
type ExternalNetwork struct {
	NamedResource
	CidrStr          string
	isPublicInternet bool
}

func (exn *ExternalNetwork) Cidr() string {
	return exn.CidrStr
}

func (exn *ExternalNetwork) Name() string {
	return exn.CidrStr
}

func (exn *ExternalNetwork) IsInternal() bool {
	return false
}

func (exn *ExternalNetwork) IsPublicInternet() bool {
	return exn.isPublicInternet
}

func (exn *ExternalNetwork) Details() string {
	return "ExternalNetwork " + exn.Cidr()
}

func (exn *ExternalNetwork) Kind() string {
	return "ExternalNetwork"
}

func (exn *ExternalNetwork) DetailsMap() map[string]string {
	res := map[string]string{}
	res[DetailsAttributeKind] = exn.Kind()
	res[DetailsAttributeName] = exn.ResourceName
	res[DetailsAttributeCIDR] = exn.CidrStr
	return res
}

func getPublicInternetIPblocksList() (internetIPblocksList []*common.IPBlock, allInternetRagnes *common.IPBlock, err error) {
	res := []*common.IPBlock{}
	allInternetRagnes = &common.IPBlock{}
	publicInternetAdrressList := getPublicInternetAdressList()
	for _, ipAddressRange := range publicInternetAdrressList {
		var ipb *common.IPBlock
		var err error
		if ipb, err = common.IPBlockFromIPRangeStr(ipAddressRange); err != nil {
			ipb, err = common.NewIPBlock(ipAddressRange, []string{})
		}
		if err != nil {
			return nil, nil, err
		}
		res = append(res, ipb)
		allInternetRagnes = allInternetRagnes.Union(ipb)
	}
	return res, allInternetRagnes, nil
}

func newExternalNode(isPublicInternet bool, ipb *common.IPBlock, index int) Node {
	cidr := ipb.ToCidrList()[0]
	if isPublicInternet {
		return &ExternalNetwork{
			NamedResource: NamedResource{ResourceName: publicInternetNodeName},
			CidrStr:       cidr, isPublicInternet: true,
		}
	}
	nodeName := fmt.Sprintf("ref-address-%d", index)
	return &ExternalNetwork{NamedResource: NamedResource{ResourceName: nodeName}, CidrStr: cidr}
}

func GetExternalNetworkNodes(disjointRefExternalIPBlocks []*common.IPBlock) ([]Node, error) {
	res := []Node{}
	internetIPblocks, allInternetRagnes, err := getPublicInternetIPblocksList()
	if err != nil {
		return nil, err
	}
	disjointRefExternalIPBlocksAll := common.DisjointIPBlocks(internetIPblocks, disjointRefExternalIPBlocks)

	for index, ipb := range disjointRefExternalIPBlocksAll {
		var isPublicInternet bool
		if ipb.ContainedIn(allInternetRagnes) {
			isPublicInternet = true
		}
		res = append(res, newExternalNode(isPublicInternet, ipb, index))
	}
	return res, nil
}
