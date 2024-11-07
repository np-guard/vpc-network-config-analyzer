/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"errors"
	"fmt"
	"sync"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/models/pkg/spec"
)

const (
	DetailsAttributeKind = "kind"
	DetailsAttributeName = "name"
	DetailsAttributeCIDR = "cidr"

	publicInternetNodeName  = "Public Internet"
	serviceNetworkNodeName  = "Service Network"
	externalNetworkNodeKind = "ExternalNetwork"
)

var once sync.Once

// singleton struct
type NetworkAddressLists struct {
	publicInternetAddressList []*netset.IPBlock
	serviceNetworkAddressList []*netset.IPBlock
}

var networkAddressList = &NetworkAddressLists{}

func InitNetworkAddressLists(publicInternetAddressList, serviceNetworkAddressList []string) {
	once.Do(func() {
		ipbListPI, _, _ := ipStringsToIPblocks(publicInternetAddressList)
		ipbListSN, _, _ := ipStringsToIPblocks(serviceNetworkAddressList)
		networkAddressList = &NetworkAddressLists{ipbListPI, ipbListSN}
	})
}

func GetNetworkAddressList() *NetworkAddressLists {
	return networkAddressList
}

// TODO: move getPublicInternetAddressList to pkg IPBlock ?

// Default public IP addresses
// All public IP addresses belong to one of the following public IP address ranges:
func GetDefaultPublicInternetAddressList() []string {
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

func (n *NetworkAddressLists) GetPublicInternetIPblocksList() ([]*netset.IPBlock, *netset.IPBlock, error) {
	if len(n.publicInternetAddressList) == 0 {
		return ipStringsToIPblocks(GetDefaultPublicInternetAddressList())
	}
	allInternetRanges := netset.NewIPBlock()
	for _, ipRange := range n.publicInternetAddressList {
		fmt.Printf("ipRange.String(): %v\n", ipRange.String())
		allInternetRanges = allInternetRanges.Union(ipRange)
	}
	fmt.Printf("allInternetRanges.String(): %v\n", allInternetRanges.String())
	return n.publicInternetAddressList, allInternetRanges, nil
}

func (n *NetworkAddressLists) GetServiceNetworkIPblocksList() ([]*netset.IPBlock, *netset.IPBlock, error) {
	allServiceNetworkRanges := netset.NewIPBlock()
	for _, ipRange := range n.serviceNetworkAddressList {
		allServiceNetworkRanges = allServiceNetworkRanges.Union(ipRange)
	}
	fmt.Printf("allServiceNetworkRanges.String(): %v\n", allServiceNetworkRanges.String())
	return n.serviceNetworkAddressList, allServiceNetworkRanges, nil
}

// ExternalNetwork implements Node interface
type ExternalNetwork struct {
	ResourceType     string
	CidrStr          string
	isPublicInternet bool
	ipblock          *netset.IPBlock
}

func (exn *ExternalNetwork) UID() string        { return exn.Name() }
func (exn *ExternalNetwork) ZoneName() string   { return "" }
func (exn *ExternalNetwork) RegionName() string { return "" }
func (exn *ExternalNetwork) IsExternal() bool   { return true }

func (exn *ExternalNetwork) CidrOrAddress() string {
	return exn.CidrStr
}

func (exn *ExternalNetwork) IPBlock() *netset.IPBlock {
	return exn.ipblock
}

func (exn *ExternalNetwork) Name() string {
	return exn.ResourceType + " [" + exn.CidrStr + "]"
}

func (exn *ExternalNetwork) NameForAnalyzerOut(c *VPCConfig) string {
	return exn.Name()
}

func (exn *ExternalNetwork) SynthesisResourceName() string {
	return exn.Name()
}

func (exn *ExternalNetwork) SynthesisKind() spec.ResourceType {
	return spec.ResourceTypeExternal
}

func (exn *ExternalNetwork) IsInternal() bool {
	return false
}

func (exn *ExternalNetwork) IsPublicInternet() bool {
	return exn.isPublicInternet
}

// only lb are abstracted, so only pip has AbstractedToNodeSet
func (exn *ExternalNetwork) AbstractedToNodeSet() NodeSet {
	return nil
}
func (exn *ExternalNetwork) RepresentedByAddress() bool {
	return true
}

func (exn *ExternalNetwork) Kind() string {
	return externalNetworkNodeKind
}

func (exn *ExternalNetwork) VPC() VPCResourceIntf {
	return nil
}

// input ipList is a list of  cidrs / ip-ranges (see getPublicInternetAddressList() as example)
func ipStringsToIPblocks(ipList []string) (ipbList []*netset.IPBlock, unionIPblock *netset.IPBlock, err error) {
	ipbList = []*netset.IPBlock{}
	unionIPblock = netset.NewIPBlock()
	for _, ipAddressRange := range ipList {
		var ipb *netset.IPBlock
		if ipb, err = netset.IPBlockFromIPRangeStr(ipAddressRange); err != nil {
			ipb, err = netset.IPBlockFromCidr(ipAddressRange)
		}
		if err != nil {
			return nil, nil, err
		}
		ipbList = append(ipbList, ipb)
		unionIPblock = unionIPblock.Union(ipb)
	}
	return ipbList, unionIPblock, nil
}

func newExternalNode(isPublicInternet bool, ipb *netset.IPBlock, resourceType string) (Node, error) {
	cidrsList := ipb.ToCidrList()
	if len(cidrsList) > 1 {
		return nil, errors.New("newExternalNode: input ip-block should be of a single CIDR")
	}
	cidr := ipb.ToCidrList()[0]
	return &ExternalNetwork{
		ResourceType:     resourceType,
		CidrStr:          cidr,
		isPublicInternet: isPublicInternet,
		ipblock:          ipb}, nil
}

func newExternalNodeForCidr(cidr, resourceType string) (Node, error) { //nolint:unparam // resourceType is param
	cidrIPBlodk, err := netset.IPBlockFromCidr(cidr)
	if err != nil {
		return nil, err
	}
	return &ExternalNetwork{
		ResourceType:     resourceType,
		CidrStr:          cidr,
		isPublicInternet: resourceType == publicInternetNodeName,
		ipblock:          cidrIPBlodk,
	}, nil
}

func GetExternalNetworkNodes(disjointRefExternalIPBlocks []*netset.IPBlock) ([]Node, error) {
	res := []Node{}
	internetIPblocks, allInternetRagnes, err := GetNetworkAddressList().GetPublicInternetIPblocksList()
	if err != nil {
		return nil, err
	}
	serviceNetworkIPblocks, serviceNetworkRagnes, err := GetNetworkAddressList().GetServiceNetworkIPblocksList()
	if err != nil {
		return nil, err
	}
	disjointRefExternalIPBlocksPublicInternet := netset.DisjointIPBlocks(internetIPblocks, disjointRefExternalIPBlocks)
	disjointRefExternalIPBlocksServiceNetwork := netset.DisjointIPBlocks(serviceNetworkIPblocks, disjointRefExternalIPBlocks)

	for _, ipb := range disjointRefExternalIPBlocksPublicInternet {
		var isPublicInternet bool
		if ipb.IsSubset(allInternetRagnes) {
			isPublicInternet = true
		} else {
			continue
		}
		cidrs := ipb.ToCidrList()
		for _, cidr := range cidrs {
			nodeIPBlock, err := netset.IPBlockFromCidr(cidr)
			if err != nil {
				return nil, err
			}
			newNode, err := newExternalNode(isPublicInternet, nodeIPBlock, publicInternetNodeName)
			if err != nil {
				return nil, err
			}
			res = append(res, newNode)
		}
	}
	for _, ipb := range disjointRefExternalIPBlocksServiceNetwork {
		var isPublicInternet bool
		if ipb.IsSubset(serviceNetworkRagnes) {
			isPublicInternet = false
		} else {
			continue
		}
		cidrs := ipb.ToCidrList()
		for _, cidr := range cidrs {
			nodeIPBlock, err := netset.IPBlockFromCidr(cidr)
			if err != nil {
				return nil, err
			}
			newNode, err := newExternalNode(isPublicInternet, nodeIPBlock, serviceNetworkNodeName)
			if err != nil {
				return nil, err
			}
			res = append(res, newNode)
		}
	}
	return res, nil
}

func isEntireServiceNetworkRange(nodes []*ExternalNetwork) (bool, error) {
	ipList := make([]string, len(nodes))
	for i, n := range nodes {
		ipList[i] = n.CidrStr
	}

	_, nodesRanges, err := ipStringsToIPblocks(ipList)
	if err != nil {
		return false, err
	}
	_, allServiceNetworkRagnes, err := GetNetworkAddressList().GetServiceNetworkIPblocksList()
	if err != nil {
		return false, err
	}
	return nodesRanges.Equal(allServiceNetworkRagnes), nil
}

func isEntirePublicInternetRange(nodes []*ExternalNetwork) (bool, error) {
	ipList := make([]string, len(nodes))
	for i, n := range nodes {
		ipList[i] = n.CidrStr
	}

	_, nodesRanges, err := ipStringsToIPblocks(ipList)
	if err != nil {
		return false, err
	}
	_, allInternetRagnes, err := GetNetworkAddressList().GetPublicInternetIPblocksList()
	if err != nil {
		return false, err
	}
	return nodesRanges.Equal(allInternetRagnes), nil
}
