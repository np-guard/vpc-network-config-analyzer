/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"errors"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

type InternetGateway struct {
	vpcmodel.VPCResource
	src          []vpcmodel.Node
	destinations []vpcmodel.Node
	srcSubnets   []*commonvpc.Subnet
	vpc          vpcmodel.VPC
}

func (igw *InternetGateway) Sources() []vpcmodel.Node {
	return igw.src
}
func (igw *InternetGateway) Destinations() []vpcmodel.Node {
	return igw.destinations
}
func (igw *InternetGateway) SourcesSubnets() []vpcmodel.Subnet {
	// todo - rewrite with issue #740
	res := make([]vpcmodel.Subnet, len(igw.srcSubnets))
	for i, s := range igw.srcSubnets {
		res[i] = s
	}
	return res
}
func (igw *InternetGateway) VPC() vpcmodel.VPCResourceIntf {
	return igw.vpc
}
func (igw *InternetGateway) SetExternalDestinations(destinations []vpcmodel.Node) {
	igw.destinations = destinations
}

func (igw *InternetGateway) ExternalIP() string {
	return ""
}

func (igw *InternetGateway) AllowedConnectivity(src, dst vpcmodel.VPCResourceIntf) (*connection.Set, error) {
	if areNodes, srcNode, dstNode := isNodesPair(src, dst); areNodes {
		if vpcmodel.HasNode(igw.Sources(), srcNode) && dstNode.IsExternal() {
			return connection.All(), nil
		}
		if vpcmodel.HasNode(igw.Sources(), dstNode) && srcNode.IsExternal() {
			return connection.All(), nil
		}
		return connection.None(), nil
	}
	if src.Kind() == commonvpc.ResourceTypeSubnet {
		srcSubnet := src.(*commonvpc.Subnet)
		if dstNode, ok := dst.(vpcmodel.Node); ok {
			if dstNode.IsExternal() && hasSubnet(igw.srcSubnets, srcSubnet) {
				return connection.All(), nil
			}
		}
		dstSubnet := src.(*commonvpc.Subnet)
		if srcNode, ok := dst.(vpcmodel.Node); ok {
			if srcNode.IsExternal() && hasSubnet(igw.srcSubnets, dstSubnet) {
				return connection.All(), nil
			}
		}
		return connection.None(), nil
	}
	return nil, errors.New("unexpected src/dst input types")
}

func (igw *InternetGateway) RouterDefined(src, dst vpcmodel.Node) bool {
	return vpcmodel.HasNode(igw.Sources(), src) && dst.IsExternal()
}

func (igw *InternetGateway) RulesInConnectivity(src, dst vpcmodel.Node) []vpcmodel.RulesInTable {
	return nil
}

func (igw *InternetGateway) StringOfRouterRules(listRulesInFilter []vpcmodel.RulesInTable,
	verbose bool) (string, error) {
	return "", nil
}

func (igw *InternetGateway) IsMultipleVPCs() bool {
	return false
}

// ////////////////////////////////////
// todo - these two methods are duplicated from ibm/vpc.go needs to be reunion
func isNodesPair(src, dst vpcmodel.VPCResourceIntf) (res bool, srcNode, dstNode vpcmodel.Node) {
	srcNode, isSrcNode := src.(vpcmodel.Node)
	dstNode, isDstNode := dst.(vpcmodel.Node)
	return isSrcNode && isDstNode, srcNode, dstNode
}

func hasSubnet(listSubnets []*commonvpc.Subnet, subnet *commonvpc.Subnet) bool {
	for _, n := range listSubnets {
		if n.UID() == subnet.UID() {
			return true
		}
	}
	return false
}

/////////////////////////////////////////////////////////////
