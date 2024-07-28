/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"errors"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func (rc *AWSresourcesContainer) getIgwConfig(
	res *vpcmodel.MultipleVPCConfigs,
	regionToStructMap map[string]*commonvpc.Region,
	// igwToSubnet map[string][]*commonvpc.Subnet,
	skipByVPC map[string]bool,
) error {
	for _, igw := range rc.InternetGWList {
		igwId := *igw.InternetGatewayId
		subnets := []*commonvpc.Subnet{}
		for _, att := range igw.Attachments {
			vpcUID := *att.VpcId
			if skipByVPC[vpcUID] {
				continue
			}
			vpc := res.GetVPC(vpcUID).(*commonvpc.VPC)
			subnets = append(subnets, vpc.Subnets()...)
		}
		routerIgw := newIGW(igwId, igwId, subnets, defaultRegionName, regionToStructMap)
		// TODO - where to put this resource?
		for _, att := range igw.Attachments {
			vpcUID := *att.VpcId
			if skipByVPC[vpcUID] {
				continue
			}
			res.Config(vpcUID).RoutingResources = append(res.Config(vpcUID).RoutingResources, routerIgw)
			res.Config(vpcUID).UIDToResource[routerIgw.ResourceUID] = routerIgw
		}
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func getSubnetsNodes(subnets []*commonvpc.Subnet) []vpcmodel.Node {
	res := []vpcmodel.Node{}
	for _, s := range subnets {
		res = append(res, s.Nodes()...)
	}
	return res
}

func newIGW(igwName, igwCRN string, subnets []*commonvpc.Subnet, region string, regionToStructMap map[string]*commonvpc.Region) *InternetGateway {
	srcNodes := getSubnetsNodes(subnets)
	return &InternetGateway{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: igwName,
			ResourceUID:  igwCRN,
			ResourceType: commonvpc.ResourceTypePublicGateway,
			Region:       region,
		},
		src:        srcNodes,
		srcSubnets: subnets,
		region:     commonvpc.GetRegionByName(region, regionToStructMap),
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type InternetGateway struct {
	vpcmodel.VPCResource
	src          []vpcmodel.Node
	destinations []vpcmodel.Node
	srcSubnets   []*commonvpc.Subnet
	region       *commonvpc.Region
}

func (igw *InternetGateway) Sources() []vpcmodel.Node {
	return igw.src
}
func (igw *InternetGateway) Destinations() []vpcmodel.Node {
	return igw.destinations
}
func (tgw *InternetGateway) Region() *commonvpc.Region {
	return tgw.region
}
func (igw *InternetGateway) SetExternalDestinations(destinations []vpcmodel.Node) {
	igw.destinations = destinations
}

func (igw *InternetGateway) ExternalIP() string {
	return ""
}

func (igw *InternetGateway) AllowedConnectivity(src, dst vpcmodel.VPCResourceIntf) (*connection.Set, error) {
	if areNodes, src1, dst1 := isNodesPair(src, dst); areNodes {
		if vpcmodel.HasNode(igw.Sources(), src1) && dst1.IsExternal() {
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
			return connection.None(), nil
		}
	}
	return nil, errors.New("unexpected src/dst input types")
}

func (igw *InternetGateway) RouterDefined(src, dst vpcmodel.Node) bool {
	return vpcmodel.HasNode(igw.Sources(), src) && dst.IsExternal()
}

func (igw *InternetGateway) AppliedFiltersKinds() map[string]bool {
	return map[string]bool{vpcmodel.NaclLayer: true, vpcmodel.SecurityGroupLayer: true}
}

func (igw *InternetGateway) RulesInConnectivity(src, dst vpcmodel.Node) []vpcmodel.RulesInTable {
	return nil
}

func (igw *InternetGateway) StringOfRouterRules(listRulesInFilter []vpcmodel.RulesInTable,
	verbose bool) (string, error) {
	return "", nil
}

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

func (igw *InternetGateway) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewTransitGatewayTreeNode(gen.TreeNode(igw.Region()).(*drawio.RegionTreeNode), igw.Name())
}
func (igw *InternetGateway) ShowOnSubnetMode() bool { return true }
