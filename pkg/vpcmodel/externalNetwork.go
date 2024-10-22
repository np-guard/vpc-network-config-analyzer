/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"errors"
	"sync"

	"github.com/np-guard/models/pkg/ipblock"
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
	publicInternetAddressList []string
	serviceNetworkAddressList []string
}

var networkAddressList = &NetworkAddressLists{}

func InitNetworkAddressLists(publicInternetAddressList, serviceNetworkAddressList []string) {
	once.Do(func() {
		networkAddressList = &NetworkAddressLists{publicInternetAddressList, serviceNetworkAddressList}
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

func (n *NetworkAddressLists) GetPublicInternetIPblocksList() (internetIPblocksList []*ipblock.IPBlock,
	allInternetRagnes *ipblock.IPBlock, err error) {
	if len(n.publicInternetAddressList) == 0 {
		return ipStringsToIPblocks(GetDefaultPublicInternetAddressList())
	}
	return ipStringsToIPblocks(n.publicInternetAddressList)
}

func (n *NetworkAddressLists) GetServiceNetworkIPblocksList() (serviceNetworkIPblocksList []*ipblock.IPBlock,
	serviceNetworkRagnes *ipblock.IPBlock, err error) {
	return ipStringsToIPblocks(n.serviceNetworkAddressList)
}

// ExternalNetwork implements Node interface
type ExternalNetwork struct {
	ResourceType     string
	CidrStr          string
	isPublicInternet bool
	ipblock          *ipblock.IPBlock
}

func (exn *ExternalNetwork) UID() string        { return exn.Name() }
func (exn *ExternalNetwork) ZoneName() string   { return "" }
func (exn *ExternalNetwork) RegionName() string { return "" }
func (exn *ExternalNetwork) IsExternal() bool   { return true }

func (exn *ExternalNetwork) CidrOrAddress() string {
	return exn.CidrStr
}

func (exn *ExternalNetwork) IPBlock() *ipblock.IPBlock {
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
func ipStringsToIPblocks(ipList []string) (ipbList []*ipblock.IPBlock, unionIPblock *ipblock.IPBlock, err error) {
	ipbList = []*ipblock.IPBlock{}
	unionIPblock = ipblock.New()
	for _, ipAddressRange := range ipList {
		var ipb *ipblock.IPBlock
		if ipb, err = ipblock.FromIPRangeStr(ipAddressRange); err != nil {
			ipb, err = ipblock.FromCidr(ipAddressRange)
		}
		if err != nil {
			return nil, nil, err
		}
		ipbList = append(ipbList, ipb)
		unionIPblock = unionIPblock.Union(ipb)
	}
	return ipbList, unionIPblock, nil
}

func newExternalNode(isPublicInternet bool, ipb *ipblock.IPBlock, resourceType string) (Node, error) {
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
	cidrIPBlodk, err := ipblock.FromCidr(cidr)
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

func GetExternalNetworkNodes(disjointRefExternalIPBlocks []*ipblock.IPBlock) ([]Node, error) {
	res := []Node{}
	internetIPblocks, allInternetRagnes, err := GetNetworkAddressList().GetPublicInternetIPblocksList()
	if err != nil {
		return nil, err
	}
	serviceNetworkIPblocks, serviceNetworkRagnes, err := GetNetworkAddressList().GetServiceNetworkIPblocksList()
	if err != nil {
		return nil, err
	}
	disjointRefExternalIPBlocksPublicInternet := ipblock.DisjointIPBlocks(internetIPblocks, disjointRefExternalIPBlocks)
	disjointRefExternalIPBlocksServiceNetwork := ipblock.DisjointIPBlocks(serviceNetworkIPblocks, disjointRefExternalIPBlocks)

	for _, ipb := range disjointRefExternalIPBlocksPublicInternet {
		var isPublicInternet bool
		if ipb.ContainedIn(allInternetRagnes) {
			isPublicInternet = true
		} else {
			continue
		}
		cidrs := ipb.ToCidrList()
		for _, cidr := range cidrs {
			nodeIPBlock, err := ipblock.FromCidr(cidr)
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
		if ipb.ContainedIn(serviceNetworkRagnes) {
			isPublicInternet = false
		} else {
			continue
		}
		cidrs := ipb.ToCidrList()
		for _, cidr := range cidrs {
			nodeIPBlock, err := ipblock.FromCidr(cidr)
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
