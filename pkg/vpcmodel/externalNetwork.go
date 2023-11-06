package vpcmodel

import (
	"errors"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

const (
	DetailsAttributeKind = "kind"
	DetailsAttributeName = "name"
	DetailsAttributeCIDR = "cidr"

	publicInternetNodeName  = "Public Internet"
	externalNetworkNodeKind = "ExternalNetwork"
)

// All public IP addresses belong to one of the following public IP address ranges:
func getPublicInternetAddressList() []string {
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
	ResourceType     string
	CidrStr          string
	isPublicInternet bool
}

func (exn *ExternalNetwork) UID() string      { return "" }
func (exn *ExternalNetwork) ZoneName() string { return "" }
func (exn *ExternalNetwork) IsExternal() bool { return true }

func (exn *ExternalNetwork) Cidr() string {
	return exn.CidrStr
}

func (exn *ExternalNetwork) Name() string {
	return exn.ResourceType + " [" + exn.CidrStr + "]"
}

func (exn *ExternalNetwork) IsInternal() bool {
	return false
}

func (exn *ExternalNetwork) IsPublicInternet() bool {
	return exn.isPublicInternet
}

func (exn *ExternalNetwork) Kind() string {
	return externalNetworkNodeKind
}

func ipStringsToIPblocks(ipList []string) (ipbList []*common.IPBlock, unionIPblock *common.IPBlock, err error) {
	ipbList = []*common.IPBlock{}
	unionIPblock = &common.IPBlock{}
	for _, ipAddressRange := range ipList {
		var ipb *common.IPBlock
		if ipb, err = common.IPBlockFromIPRangeStr(ipAddressRange); err != nil {
			ipb, err = common.NewIPBlock(ipAddressRange, []string{})
		}
		if err != nil {
			return nil, nil, err
		}
		ipbList = append(ipbList, ipb)
		unionIPblock = unionIPblock.Union(ipb)
	}
	return ipbList, unionIPblock, nil
}

func getPublicInternetIPblocksList() (internetIPblocksList []*common.IPBlock, allInternetRagnes *common.IPBlock, err error) {
	publicInternetAddressList := getPublicInternetAddressList()
	return ipStringsToIPblocks(publicInternetAddressList)
}

func newExternalNode(isPublicInternet bool, ipb *common.IPBlock) (Node, error) {
	cidrsList := ipb.ToCidrList()
	if len(cidrsList) > 1 {
		return nil, errors.New("newExternalNode: input ip-block should be of a single cidr")
	}
	cidr := ipb.ToCidrList()[0]
	return &ExternalNetwork{
		ResourceType:     publicInternetNodeName,
		CidrStr:          cidr,
		isPublicInternet: isPublicInternet}, nil
}

func newExternalNodeForCidr(cidr string) Node {
	return &ExternalNetwork{
		ResourceType:     publicInternetNodeName,
		CidrStr:          cidr,
		isPublicInternet: true}
}

func GetExternalNetworkNodes(disjointRefExternalIPBlocks []*common.IPBlock) ([]Node, error) {
	res := []Node{}
	internetIPblocks, allInternetRagnes, err := getPublicInternetIPblocksList()
	if err != nil {
		return nil, err
	}
	disjointRefExternalIPBlocksAll := common.DisjointIPBlocks(internetIPblocks, disjointRefExternalIPBlocks)

	for _, ipb := range disjointRefExternalIPBlocksAll {
		var isPublicInternet bool
		if ipb.ContainedIn(allInternetRagnes) {
			isPublicInternet = true
		}
		cidrs := ipb.ToCidrList()
		for _, cidr := range cidrs {
			newNode, err := newExternalNode(isPublicInternet, common.NewIPBlockFromCidr(cidr))
			if err != nil {
				return nil, err
			}
			res = append(res, newNode)
		}
	}
	return res, nil
}

func isEntirePublicInternetRange(nodes []Node) (bool, error) {
	ipList := make([]string, len(nodes))
	for i, n := range nodes {
		ipList[i] = n.Cidr()
	}

	_, nodesRanges, err := ipStringsToIPblocks(ipList)
	if err != nil {
		return false, err
	}
	_, allInternetRagnes, err := getPublicInternetIPblocksList()
	if err != nil {
		return false, err
	}
	return nodesRanges.Equal(allInternetRagnes), nil
}
