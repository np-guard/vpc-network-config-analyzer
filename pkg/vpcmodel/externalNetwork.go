package vpcmodel

import (
	"errors"
	"fmt"
	"strings"

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
	VPCResource
	CidrStr          string
	isPublicInternet bool
}

func (exn *ExternalNetwork) Cidr() string {
	return exn.CidrStr
}

func (exn *ExternalNetwork) Name() string {
	return exn.ResourceName + " [" + exn.CidrStr + "]"
}

func (exn *ExternalNetwork) IsInternal() bool {
	return false
}

func (exn *ExternalNetwork) IsPublicInternet() bool {
	return exn.isPublicInternet
}

func (exn *ExternalNetwork) Details() []string {
	return []string{externalNetworkNodeKind + " " + exn.Cidr()}
}

func (exn *ExternalNetwork) Kind() string {
	return externalNetworkNodeKind
}

func (exn *ExternalNetwork) DetailsMap() []map[string]string {
	res := map[string]string{}
	res[DetailsAttributeKind] = exn.Kind()
	res[DetailsAttributeName] = exn.ResourceName
	res[DetailsAttributeCIDR] = exn.CidrStr
	return []map[string]string{res}
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

func newExternalNode(isPublicInternet bool, ipb *common.IPBlock, index int) (Node, error) {
	cidrsList := ipb.ToCidrList()
	if len(cidrsList) > 1 {
		return nil, errors.New("newExternalNode: input ip-block should be of a single cidr")
	}
	cidr := ipb.ToCidrList()[0]
	if isPublicInternet {
		return &ExternalNetwork{
			VPCResource: VPCResource{ResourceName: publicInternetNodeName},
			CidrStr:     cidr, isPublicInternet: true,
		}, nil
	}
	nodeName := fmt.Sprintf("ref-address-%d", index)
	return &ExternalNetwork{VPCResource: VPCResource{ResourceName: nodeName}, CidrStr: cidr}, nil
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
		cidrs := ipb.ToCidrList()
		for _, cidr := range cidrs {
			newNode, err := newExternalNode(isPublicInternet, common.NewIPBlockFromCidr(cidr), index)
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

func (g *groupedExternalNodes) mergePublicInternetRange() (string, error) {

	// 1. Created a list of IPBlocks
	cidrList := make([]string, len(*g))
	for i, n := range *g {
		cidrList[i] = n.Cidr()
	}
	ipbList, _, err := ipStringsToIPblocks(cidrList)
	if err != nil {
		return "", err
	}
	// 2. Union all IPBlocks in a single one; its intervals will be the cidr blocks or ranges that should be printed, after all possible merges
	unionBlock := &common.IPBlock{}
	for _, ipBlock := range ipbList {
		unionBlock = unionBlock.Union(ipBlock)
	}
	// Prints intervals: if an interval is a single cidr prints it, otherwise prints range
	// gets a list of ip blocks and of cidrs; if single cidr then prints the cidr, otherwise prints the ipBlock range
	ipRangesList := unionBlock.ToIPRangesList()
	cidrListAfterUnion := unionBlock.ToCidrList()
	if len(ipRangesList) != len(cidrListAfterUnion) {
		return "", errors.New("something went very wrong: length of ipRangesList is different than cidrList")
	}
	combinedCidrRangesList := []string{}
	for i, cidrs := range cidrListAfterUnion {
		if len(strings.Split(cidrs, ",")) > 1 {
			combinedCidrRangesList = append(combinedCidrRangesList, ipRangesList[i])
		} else {
			combinedCidrRangesList = append(combinedCidrRangesList, cidrs)
		}
	}
	return strings.Join(combinedCidrRangesList, ","), nil
}
