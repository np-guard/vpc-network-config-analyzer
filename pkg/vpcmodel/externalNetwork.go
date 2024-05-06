/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"errors"

	"github.com/np-guard/models/pkg/ipblock"
)

const (
	DetailsAttributeKind = "kind"
	DetailsAttributeName = "name"
	DetailsAttributeCIDR = "cidr"

	publicInternetNodeName  = "Public Internet"
	externalNetworkNodeKind = "ExternalNetwork"
)

// TODO: move getPublicInternetAddressList to pkg IPBlock ?

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

func (exn *ExternalNetwork) ExtendedName(c *VPCConfig) string {
	return exn.Name()
}

func (exn *ExternalNetwork) ExtendedPrefix(c *VPCConfig) string {
	return ""
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

func GetPublicInternetIPblocksList() (internetIPblocksList []*ipblock.IPBlock, allInternetRagnes *ipblock.IPBlock, err error) {
	publicInternetAddressList := getPublicInternetAddressList()
	return ipStringsToIPblocks(publicInternetAddressList)
}

func newExternalNode(isPublicInternet bool, ipb *ipblock.IPBlock) (Node, error) {
	cidrsList := ipb.ToCidrList()
	if len(cidrsList) > 1 {
		return nil, errors.New("newExternalNode: input ip-block should be of a single CIDR")
	}
	cidr := ipb.ToCidrList()[0]
	return &ExternalNetwork{
		ResourceType:     publicInternetNodeName,
		CidrStr:          cidr,
		isPublicInternet: isPublicInternet,
		ipblock:          ipb}, nil
}

func newExternalNodeForCidr(cidr string) (Node, error) {
	cidrIPBlodk, err := ipblock.FromCidr(cidr)
	if err != nil {
		return nil, err
	}
	return &ExternalNetwork{
		ResourceType:     publicInternetNodeName,
		CidrStr:          cidr,
		isPublicInternet: true,
		ipblock:          cidrIPBlodk,
	}, nil
}

func GetExternalNetworkNodes(disjointRefExternalIPBlocks []*ipblock.IPBlock) ([]Node, error) {
	res := []Node{}
	internetIPblocks, allInternetRagnes, err := GetPublicInternetIPblocksList()
	if err != nil {
		return nil, err
	}
	disjointRefExternalIPBlocksAll := ipblock.DisjointIPBlocks(internetIPblocks, disjointRefExternalIPBlocks)

	for _, ipb := range disjointRefExternalIPBlocksAll {
		var isPublicInternet bool
		if ipb.ContainedIn(allInternetRagnes) {
			isPublicInternet = true
		} else {
			// currently skip external nodes which are not in public internet ranges
			continue
		}
		cidrs := ipb.ToCidrList()
		for _, cidr := range cidrs {
			nodeIPBlock, err := ipblock.FromCidr(cidr)
			if err != nil {
				return nil, err
			}
			newNode, err := newExternalNode(isPublicInternet, nodeIPBlock)
			if err != nil {
				return nil, err
			}
			res = append(res, newNode)
		}
	}
	return res, nil
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
	_, allInternetRagnes, err := GetPublicInternetIPblocksList()
	if err != nil {
		return false, err
	}
	return nodesRanges.Equal(allInternetRagnes), nil
}
