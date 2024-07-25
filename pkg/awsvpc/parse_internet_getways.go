/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"errors"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/logging"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func (rc *AWSresourcesContainer) getIgwConfig(
	res *vpcmodel.MultipleVPCConfigs,
	// pgwToSubnet map[string][]*commonvpc.Subnet,
	skipByVPC map[string]bool,
) error {
	for _, pgw := range rc.InternetGWList {
		pgwName := *pgw.InternetGatewayId
		for _, att := range pgw.Attachments {
			// haim todo - support multi vpc:
			vpcUID := *att.VpcId
			if skipByVPC[vpcUID] {
				continue
			}
			zoneToSubnets := map[*commonvpc.Zone][]*commonvpc.Subnet{}
			vpc := res.GetVPC(vpcUID).(*commonvpc.VPC)
			for _, subnet := range vpc.Subnets() {
				subnetZone, _ := subnet.Zone()
				zoneToSubnets[subnetZone] = append(zoneToSubnets[subnetZone], subnet)
			}
			for zone, subnets := range zoneToSubnets {
				pgwId := pgwName + vpcUID + zone.Name
				vpc, err := commonvpc.GetVPCObjectByUID(res, vpcUID)
				if err != nil {
					return err
				}
				routerPgw := newPGW(pgwName, pgwId, zone.Name, subnets, vpc)
				res.Config(vpcUID).RoutingResources = append(res.Config(vpcUID).RoutingResources, routerPgw)
				res.Config(vpcUID).UIDToResource[routerPgw.ResourceUID] = routerPgw
			}
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

func getSubnetsCidrs(subnets []*commonvpc.Subnet) []string {
	res := []string{}
	for _, s := range subnets {
		res = append(res, s.Cidr)
	}
	return res
}

func newPGW(pgwName, pgwCRN, pgwZone string, subnets []*commonvpc.Subnet, vpc *commonvpc.VPC) *PublicGateway {
	srcNodes := getSubnetsNodes(subnets)
	return &PublicGateway{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: pgwName,
			ResourceUID:  pgwCRN,
			Zone:         pgwZone,
			ResourceType: commonvpc.ResourceTypePublicGateway,
			VPCRef:       vpc,
		},
		cidr:       "",
		src:        srcNodes,
		srcSubnets: subnets,
		subnetCidr: getSubnetsCidrs(subnets),
		vpc:        vpc,
	} // TODO: get cidr from fip of the pgw
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type PublicGateway struct {
	vpcmodel.VPCResource
	cidr         string
	src          []vpcmodel.Node
	destinations []vpcmodel.Node
	srcSubnets   []*commonvpc.Subnet
	subnetCidr   []string
	vpc          *commonvpc.VPC
}

func (pgw *PublicGateway) Zone() (*commonvpc.Zone, error) {
	return pgw.vpc.GetZoneByName(pgw.ZoneName())
}

func (pgw *PublicGateway) Sources() []vpcmodel.Node {
	return pgw.src
}
func (pgw *PublicGateway) Destinations() []vpcmodel.Node {
	return pgw.destinations
}
func (pgw *PublicGateway) ExternalIP() string {
	return ""
}

func (pgw *PublicGateway) AllowedConnectivity(src, dst vpcmodel.VPCResourceIntf) (*connection.Set, error) {
	if areNodes, src1, dst1 := isNodesPair(src, dst); areNodes {
		if vpcmodel.HasNode(pgw.Sources(), src1) && dst1.IsExternal() {
			return connection.All(), nil
		}
		return connection.None(), nil
	}
	if src.Kind() == commonvpc.ResourceTypeSubnet {
		srcSubnet := src.(*commonvpc.Subnet)
		if dstNode, ok := dst.(vpcmodel.Node); ok {
			if dstNode.IsExternal() && hasSubnet(pgw.srcSubnets, srcSubnet) {
				return connection.All(), nil
			}
			return connection.None(), nil
		}
	}
	return nil, errors.New("unexpected src/dst input types")
}

func (pgw *PublicGateway) RouterDefined(src, dst vpcmodel.Node) bool {
	return vpcmodel.HasNode(pgw.Sources(), src) && dst.IsExternal()
}

func (pgw *PublicGateway) AppliedFiltersKinds() map[string]bool {
	return map[string]bool{vpcmodel.NaclLayer: true, vpcmodel.SecurityGroupLayer: true}
}

func (pgw *PublicGateway) RulesInConnectivity(src, dst vpcmodel.Node) []vpcmodel.RulesInTable {
	return nil
}

func (pgw *PublicGateway) StringOfRouterRules(listRulesInFilter []vpcmodel.RulesInTable,
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


func (pgw *PublicGateway) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	// todo - how to handle this error:
	zone, _ := pgw.Zone()
	zoneTn := gen.TreeNode(zone).(*drawio.ZoneTreeNode)
	return drawio.NewGatewayTreeNode(zoneTn, pgw.Name())
}
func (pgw *PublicGateway) ShowOnSubnetMode() bool  { return true }







// filter VPCs with empty address ranges, then add for remaining VPCs the external nodes
func filterVPCSAndAddExternalNodes(vpcInternalAddressRange map[string]*ipblock.IPBlock, res *vpcmodel.MultipleVPCConfigs) error {
	for vpcUID, vpcConfig := range res.Configs() {
		if vpcInternalAddressRange[vpcUID] == nil {
			logging.Warnf("Ignoring VPC %s, no subnets found for this VPC\n", vpcUID)
			res.RemoveConfig(vpcUID)
			continue
		}
		err := handlePublicInternetNodes(vpcConfig, vpcInternalAddressRange[vpcUID])
		if err != nil {
			return err
		}
	}
	return nil
}

func handlePublicInternetNodes(res *vpcmodel.VPCConfig, vpcInternalAddressRange *ipblock.IPBlock) error {
	externalNodes, err := addExternalNodes(res, vpcInternalAddressRange)
	if err != nil {
		return err
	}
	publicInternetNodes := []vpcmodel.Node{}
	for _, node := range externalNodes {
		if node.IsPublicInternet() {
			publicInternetNodes = append(publicInternetNodes, node)
		}
	}
	// update destination of routing resources
	for _, r := range res.RoutingResources {
		if rPgw, ok := r.(*PublicGateway); ok {
			rPgw.destinations = publicInternetNodes
		}
	}
	return nil
}

func addExternalNodes(config *vpcmodel.VPCConfig, vpcInternalAddressRange *ipblock.IPBlock) ([]vpcmodel.Node, error) {
	ipBlocks := []*ipblock.IPBlock{}
	for _, f := range config.FilterResources {
		ipBlocks = append(ipBlocks, f.ReferencedIPblocks()...)
	}

	externalRefIPBlocks := []*ipblock.IPBlock{}
	for _, ipBlock := range ipBlocks {
		if ipBlock.ContainedIn(vpcInternalAddressRange) {
			continue
		}
		externalRefIPBlocks = append(externalRefIPBlocks, ipBlock.Subtract(vpcInternalAddressRange))
	}

	disjointRefExternalIPBlocks := ipblock.DisjointIPBlocks(externalRefIPBlocks, []*ipblock.IPBlock{})

	externalNodes, err := vpcmodel.GetExternalNetworkNodes(disjointRefExternalIPBlocks)
	if err != nil {
		return nil, err
	}
	config.Nodes = append(config.Nodes, externalNodes...)
	for _, n := range externalNodes {
		config.UIDToResource[n.UID()] = n
	}
	return externalNodes, nil
}
