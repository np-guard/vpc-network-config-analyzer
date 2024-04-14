/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/models/pkg/ipblock"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/logging"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// ParseResourcesFromFile returns datamodel.ResourcesContainerModel object, containing the configured resources structs
// from the input JSON file
func ParseResourcesFromFile(fileName string) (*datamodel.ResourcesContainerModel, error) {
	inputConfigContent, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	config := datamodel.ResourcesContainerModel{}
	err = json.Unmarshal(inputConfigContent, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func getRegionByName(regionName string, regionToStructMap map[string]*Region) *Region {
	regionPointer, ok := regionToStructMap[regionName]

	if !ok {
		regionToStructMap[regionName] = &Region{name: regionName}
		return regionToStructMap[regionName]
	}
	return regionPointer
}

func filterByVpcResourceGroupAndRegions(rc *datamodel.ResourcesContainerModel, vpcID, resourceGroup string,
	regions []string) map[string]bool {
	shouldSkipVpcIds := make(map[string]bool)
	for _, vpc := range rc.VpcList {
		if vpcID != "" && *vpc.CRN != vpcID {
			shouldSkipVpcIds[*vpc.CRN] = true
			continue
		}
		if resourceGroup != "" && *vpc.ResourceGroup.ID != resourceGroup && *vpc.ResourceGroup.Name != resourceGroup {
			shouldSkipVpcIds[*vpc.CRN] = true
			continue
		}
		if len(regions) > 0 && !slices.Contains(regions, vpc.Region) {
			shouldSkipVpcIds[*vpc.CRN] = true
		}
	}
	return shouldSkipVpcIds
}

// VPCConfigsFromResources returns a map from VPC UID (string) to its corresponding VPCConfig object,
// containing the parsed resources in the relevant model objects
func VPCConfigsFromResources(rc *datamodel.ResourcesContainerModel, vpcID, resourceGroup string, regions []string, debug bool) (
	vpcmodel.MultipleVPCConfigs, error) {
	res := vpcmodel.MultipleVPCConfigs{}          // map from VPC UID to its config
	filteredOut := map[string]bool{}              // store networkInterface UIDs filtered out by skipByVPC
	regionToStructMap := make(map[string]*Region) // map for caching Region objects
	var err error

	// map to filter resources, if certain VPC, resource-group or region list to analyze is specified,
	// skip resources configured outside that VPC
	shouldSkipVpcIds := filterByVpcResourceGroupAndRegions(rc, vpcID, resourceGroup, regions)

	err = getVPCconfig(rc, res, shouldSkipVpcIds, regionToStructMap)
	if err != nil {
		return nil, err
	}

	var vpcInternalAddressRange map[string]*ipblock.IPBlock // map from vpc name to its internal address range

	subnetNameToNetIntf := map[string][]*NetworkInterface{}
	err = getInstancesConfig(rc.InstanceList, subnetNameToNetIntf, res, filteredOut, shouldSkipVpcIds)
	if err != nil {
		return nil, err
	}
	// pgw can be attached to multiple subnets in the zone
	pgwToSubnet := map[string][]*Subnet{} // map from pgw name to its attached subnet(s)
	vpcInternalAddressRange, err = getSubnetsConfig(res, pgwToSubnet, subnetNameToNetIntf, rc, shouldSkipVpcIds)
	if err != nil {
		return nil, err
	}
	// assign to each vpc object its internal address range, as inferred from its subnets
	err = updateVPCSAddressRanges(vpcInternalAddressRange, res)
	if err != nil {
		return nil, err
	}

	err = getIKSnodesConfig(res, rc, shouldSkipVpcIds)
	if err != nil {
		return nil, err
	}

	err = getPgwConfig(res, rc, pgwToSubnet, shouldSkipVpcIds)
	if err != nil {
		return nil, err
	}

	err = getFipConfig(rc, res, filteredOut, shouldSkipVpcIds)
	if err != nil {
		return nil, err
	}

	err = getVPEconfig(rc, res, shouldSkipVpcIds)
	if err != nil {
		return nil, err
	}
	err = GetLoadBalancersConfig(rc, res, shouldSkipVpcIds)
	if err != nil {
		return nil, err
	}
	err = getSGconfig(rc, res, shouldSkipVpcIds)
	if err != nil {
		return nil, err
	}

	err = getNACLconfig(rc, res, shouldSkipVpcIds)
	if err != nil {
		return nil, err
	}

	err = filterVPCSAndAddExternalNodes(vpcInternalAddressRange, res)
	if err != nil {
		return nil, err
	}

	tgws := getTgwObjects(rc, res, resourceGroup, regions, regionToStructMap)
	err = addTGWbasedConfigs(tgws, res)
	if err != nil {
		return nil, err
	}

	if debug {
		printVPCConfigs(res)
	}

	return res, nil
}

const (
	protocolTCP                  = "tcp"
	protocolUDP                  = "udp"
	inbound                      = "inbound"
	outbound                     = "outbound"
	networkInterfaceResourceType = "network_interface" // used as the type within api objects (e.g. SecurityGroup.Targets.ResourceType)
	vpeResourceType              = "endpoint_gateway"  // used as the type within api objects (e.g. SecurityGroup.Targets.ResourceType)
	loadBalancerResourceType     = "load_balancer"     // used as the type within api objects (e.g. SecurityGroup.Targets.ResourceType)
	// iksNodeResourceType is not actually used from input api objects, but is added by the parser to SGs with targets
	// that should be added with iks nodes
	iksNodeResourceType = "iks_node" // used as the type within api objects (e.g. SecurityGroup.Targets.ResourceType)
	cidrSeparator       = ", "
	linesSeparator      = "---------------------"
)

// Resource types const strings, used in the generated resources of this pkg
const (
	ResourceTypeVSI              = "VSI"
	ResourceTypeNetworkInterface = "NetworkInterface"
	ResourceTypeSubnet           = "Subnet"
	ResourceTypePublicGateway    = "PublicGateway"
	ResourceTypeFloatingIP       = "FloatingIP"
	ResourceTypeVPC              = "VPC"
	ResourceTypeSG               = "SG"
	ResourceTypeNACL             = "NACL"
	ResourceTypeIKSNode          = "IKSNodeNetworkInterface"
	ResourceTypeVPE              = "VPE"
	ResourceTypeTGW              = "TGW"
	ResourceTypeReservedIP       = "ReservedIP"
	ResourceTypeLoadBalancer     = "LoadBalancer"
	ResourceTypePrivateIP        = "PrivateIP"
)

var errIksParsing = errors.New("issue parsing IKS node")

func getCertainNodes(allNodes []vpcmodel.Node, shouldTakeNode func(vpcmodel.Node) bool) (ret []vpcmodel.Node) {
	for _, s := range allNodes {
		if shouldTakeNode(s) {
			ret = append(ret, s)
		}
	}
	return
}

func addZone(zoneName, vpcUID string, res vpcmodel.MultipleVPCConfigs) error {
	vpc, err := getVPCObjectByUID(res, vpcUID)
	if err != nil {
		return err
	}
	if _, ok := vpc.zones[zoneName]; !ok {
		vpc.zones[zoneName] = &Zone{name: zoneName, vpc: vpc}
	}
	return nil
}

func updateFilteredOutNetworkInterfacesUIDs(instance *datamodel.Instance, filterOutUIDs map[string]bool) {
	for j := range instance.NetworkInterfaces {
		networkInterface := instance.NetworkInterfaces[j]
		filterOutUIDs[*networkInterface.ID] = true
	}
}

func newNetworkInterface(name, uid, zone, address, vsi string, vpc vpcmodel.VPCResourceIntf) (*NetworkInterface, error) {
	intfNode := &NetworkInterface{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: name,
			ResourceUID:  uid,
			ResourceType: ResourceTypeNetworkInterface,
			Zone:         zone,
			VPCRef:       vpc,
			Region:       vpc.RegionName(),
		},
		InternalNode: vpcmodel.InternalNode{
			AddressStr: address,
		},
		vsi: vsi,
	}

	if err := intfNode.SetIPBlockFromAddress(); err != nil {
		return nil, err
	}
	return intfNode, nil
}

func getInstancesConfig(
	instanceList []*datamodel.Instance,
	subnetNameToNetIntf map[string][]*NetworkInterface,
	res vpcmodel.MultipleVPCConfigs,
	filteredOutUIDs map[string]bool,
	skipByVPC map[string]bool,
) error {
	for _, instance := range instanceList {
		vpcUID := *instance.VPC.CRN
		if skipByVPC[vpcUID] {
			updateFilteredOutNetworkInterfacesUIDs(instance, filteredOutUIDs)
			continue
		}
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		vsiNode := &Vsi{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: *instance.Name,
				ResourceUID:  *instance.CRN,
				Zone:         *instance.Zone.Name,
				ResourceType: ResourceTypeVSI,
				VPCRef:       vpc,
				Region:       vpc.RegionName(),
			},
			nodes: []vpcmodel.Node{},
		}

		if err := addZone(*instance.Zone.Name, vpcUID, res); err != nil {
			return err
		}
		res[vpcUID].NodeSets = append(res[vpcUID].NodeSets, vsiNode)
		res[vpcUID].UIDToResource[vsiNode.ResourceUID] = vsiNode
		for j := range instance.NetworkInterfaces {
			netintf := instance.NetworkInterfaces[j]
			// netintf has no CRN, thus using its ID for ResourceUID
			intfNode, err := newNetworkInterface(*netintf.Name, *netintf.ID, *instance.Zone.Name, *netintf.PrimaryIP.Address, *instance.Name, vpc)
			if err != nil {
				return err
			}
			res[vpcUID].Nodes = append(res[vpcUID].Nodes, intfNode)
			res[vpcUID].UIDToResource[intfNode.ResourceUID] = intfNode
			vsiNode.nodes = append(vsiNode.nodes, intfNode)
			subnetName := *netintf.Subnet.Name
			if _, ok := subnetNameToNetIntf[subnetName]; !ok {
				subnetNameToNetIntf[subnetName] = []*NetworkInterface{}
			}
			subnetNameToNetIntf[subnetName] = append(subnetNameToNetIntf[subnetName], intfNode)
		}
	}
	return nil
}

func newSubnet(name, uid, zone, cidr string, vpc vpcmodel.VPCResourceIntf) (*Subnet, error) {
	subnetNode := &Subnet{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: name,
			ResourceUID:  uid,
			Zone:         zone,
			ResourceType: ResourceTypeSubnet,
			VPCRef:       vpc,
			Region:       vpc.RegionName(),
		},
		cidr: cidr,
	}

	cidrIPBlock, err := ipblock.FromCidr(subnetNode.cidr)
	if err != nil {
		return nil, err
	}
	subnetNode.ipblock = cidrIPBlock
	return subnetNode, nil
}

func getSubnetsConfig(
	res vpcmodel.MultipleVPCConfigs,
	pgwToSubnet map[string][]*Subnet,
	subnetNameToNetIntf map[string][]*NetworkInterface,
	rc *datamodel.ResourcesContainerModel,
	skipByVPC map[string]bool,
) (vpcInternalAddressRange map[string]*ipblock.IPBlock, err error) {
	vpcInternalAddressRange = map[string]*ipblock.IPBlock{}
	for vpcUID := range res {
		vpcInternalAddressRange[vpcUID] = nil
	}
	for _, subnet := range rc.SubnetList {
		if skipByVPC[*subnet.VPC.CRN] {
			continue
		}
		subnetNodes := []vpcmodel.Node{}
		vpcUID := *subnet.VPC.CRN
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return nil, err
		}

		subnetNode, err := newSubnet(*subnet.Name, *subnet.CRN, *subnet.Zone.Name, *subnet.Ipv4CIDRBlock, vpc)
		if err != nil {
			return nil, err
		}
		if vpcInternalAddressRange[vpcUID] == nil {
			vpcInternalAddressRange[vpcUID] = subnetNode.ipblock
		} else {
			vpcInternalAddressRange[vpcUID] = vpcInternalAddressRange[vpcUID].Union(subnetNode.ipblock)
		}
		res[vpcUID].Subnets = append(res[vpcUID].Subnets, subnetNode)
		if err := addZone(*subnet.Zone.Name, vpcUID, res); err != nil {
			return nil, err
		}
		res[vpcUID].UIDToResource[subnetNode.ResourceUID] = subnetNode
		if subnet.PublicGateway != nil {
			if _, ok := pgwToSubnet[*subnet.PublicGateway.Name]; !ok {
				pgwToSubnet[*subnet.PublicGateway.Name] = []*Subnet{}
			}
			pgwToSubnet[*subnet.PublicGateway.Name] = append(pgwToSubnet[*subnet.PublicGateway.Name], subnetNode)
		}
		// add pointers from networkInterface to its subnet, given the current subnet created
		if subnetInterfaces, ok := subnetNameToNetIntf[*subnet.Name]; ok {
			for _, netIntf := range subnetInterfaces {
				netIntf.SubnetResource = subnetNode
				subnetNodes = append(subnetNodes, netIntf)
			}
			subnetNode.nodes = subnetNodes
		}
		// add subnet to its vpc's list of subnets
		vpc.subnetsList = append(vpc.subnetsList, subnetNode)
	}
	return vpcInternalAddressRange, nil
}

func getSubnetsNodes(subnets []*Subnet) []vpcmodel.Node {
	res := []vpcmodel.Node{}
	for _, s := range subnets {
		res = append(res, s.Nodes()...)
	}
	return res
}

func getSubnetsCidrs(subnets []*Subnet) []string {
	res := []string{}
	for _, s := range subnets {
		res = append(res, s.cidr)
	}
	return res
}

func newPGW(pgwName, pgwCRN, pgwZone string, pgwToSubnet map[string][]*Subnet, vpc *VPC) *PublicGateway {
	srcNodes := getSubnetsNodes(pgwToSubnet[pgwName])
	return &PublicGateway{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: pgwName,
			ResourceUID:  pgwCRN,
			Zone:         pgwZone,
			ResourceType: ResourceTypePublicGateway,
			VPCRef:       vpc,
		},
		cidr:       "",
		src:        srcNodes,
		srcSubnets: pgwToSubnet[pgwName],
		subnetCidr: getSubnetsCidrs(pgwToSubnet[pgwName]),
		vpc:        vpc,
	} // TODO: get cidr from fip of the pgw
}

func getPgwConfig(
	res vpcmodel.MultipleVPCConfigs,
	rc *datamodel.ResourcesContainerModel,
	pgwToSubnet map[string][]*Subnet,
	skipByVPC map[string]bool,
) error {
	for _, pgw := range rc.PublicGWList {
		if skipByVPC[*pgw.VPC.CRN] {
			continue
		}
		pgwName := *pgw.Name
		if _, ok := pgwToSubnet[pgwName]; !ok {
			logging.Warnf("public gateway %s does not have any attached subnet, ignoring this pgw\n", pgwName)
			continue
		}
		vpcUID := *pgw.VPC.CRN
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		routerPgw := newPGW(*pgw.Name, *pgw.CRN, *pgw.Zone.Name, pgwToSubnet, vpc)
		res[vpcUID].RoutingResources = append(res[vpcUID].RoutingResources, routerPgw)
		res[vpcUID].UIDToResource[routerPgw.ResourceUID] = routerPgw
		err = addZone(*pgw.Zone.Name, vpcUID, res)
		if err != nil {
			return err
		}
	}
	return nil
}

func ignoreFIPWarning(fipName, details string) string {
	return fmt.Sprintf("ignoring floatingIP %s: %s", fipName, details)
}

func warnSkippedFip(filteredOutUIDs map[string]bool, targetUID string, fip *datamodel.FloatingIP) {
	if !filteredOutUIDs[targetUID] {
		logging.Warnf("skip fip %s - could not find attached network interface\n", *fip.Name)
	}
}

func newFIP(fipName, fipCRN, fipZone, fipAddress string, vpc *VPC, srcNodes []vpcmodel.Node) *FloatingIP {
	return &FloatingIP{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: fipName,
			ResourceUID:  fipCRN,
			Zone:         fipZone,
			ResourceType: ResourceTypeFloatingIP,
			VPCRef:       vpc,
			Region:       vpc.RegionName(),
		},
		cidr: fipAddress, src: srcNodes,
	}
}

func getFipConfig(
	rc *datamodel.ResourcesContainerModel,
	res vpcmodel.MultipleVPCConfigs,
	filteredOutUIDs map[string]bool,
	skipByVPC map[string]bool,
) error {
	for _, fip := range rc.FloatingIPList {
		targetIntf := fip.Target
		var targetUID string
		switch target := targetIntf.(type) {
		case *vpc1.FloatingIPTargetNetworkInterfaceReference:
			targetUID = *target.ID
		case *vpc1.FloatingIPTarget:
			if *target.ResourceType != networkInterfaceResourceType {
				logging.Warnf(ignoreFIPWarning(*fip.Name,
					fmt.Sprintf("target.ResourceType %s is not supported (only networkInterfaceResourceType supported)",
						*target.ResourceType)))
				continue
			}
			targetUID = *target.ID
		default:
			logging.Warnf(ignoreFIPWarning(*fip.Name, "target (FloatingIPTargetIntf) is not of the expected type"))
			continue
		}

		if targetUID == "" {
			continue
		}

		var srcNodes []vpcmodel.Node
		var vpcUID string
		for uid, vpcConfig := range res {
			srcNodes = getCertainNodes(vpcConfig.Nodes, func(n vpcmodel.Node) bool { return n.UID() == targetUID })
			if len(srcNodes) > 0 {
				vpcUID = uid
				break
			}
		}

		if len(srcNodes) == 0 {
			warnSkippedFip(filteredOutUIDs, targetUID, fip)
			continue // could not find network interface attached to configured fip -- skip that fip
		}

		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		if skipByVPC[vpc.ResourceUID] {
			continue // skip fip because of selected vpc to analyze
		}

		routerFip := newFIP(*fip.Name, *fip.CRN, *fip.Zone.Name, *fip.Address, vpc, srcNodes)
		res[vpcUID].RoutingResources = append(res[vpcUID].RoutingResources, routerFip)
		res[vpcUID].UIDToResource[routerFip.ResourceUID] = routerFip

		// node with fip should not have pgw
		for _, r := range res[vpcUID].RoutingResources {
			if pgw, ok := r.(*PublicGateway); ok {
				// a node captured by a fip should not be captured by a pgw
				for _, nodeWithFip := range srcNodes {
					if vpcmodel.HasNode(pgw.Sources(), nodeWithFip) {
						pgw.src = getCertainNodes(pgw.Sources(), func(n vpcmodel.Node) bool { return n.UID() != nodeWithFip.UID() })
					}
				}
			}
		}
	}
	return nil
}

func getVPCAddressPrefixes(vpc *datamodel.VPC) (res []string) {
	for _, ap := range vpc.AddressPrefixes {
		res = append(res, *ap.CIDR)
	}
	return res
}

func newVPC(name, uid, region string, ap []string, regionToStructMap map[string]*Region) (vpcNodeSet *VPC, err error) {
	vpcNodeSet = &VPC{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: name,
			ResourceUID:  uid,
			ResourceType: ResourceTypeVPC,
			Region:       region,
		},
		nodes:           []vpcmodel.Node{},
		zones:           map[string]*Zone{},
		addressPrefixes: ap,
		region:          getRegionByName(region, regionToStructMap),
	}

	vpcNodeSet.addressPrefixesIPBlock, err = ipblock.FromCidrList(ap)
	if err != nil {
		return nil, err
	}
	vpcNodeSet.VPCRef = vpcNodeSet
	return vpcNodeSet, nil
}

func getVPCconfig(rc *datamodel.ResourcesContainerModel,
	res vpcmodel.MultipleVPCConfigs,
	skipByVPC map[string]bool,
	regionToStructMap map[string]*Region) error {
	for _, vpc := range rc.VpcList {
		if skipByVPC[*vpc.CRN] {
			continue // skip vpc not specified to analyze
		}

		vpcNodeSet, err := newVPC(*vpc.Name, *vpc.CRN, vpc.Region, getVPCAddressPrefixes(vpc), regionToStructMap)
		if err != nil {
			return err
		}
		newVPCConfig := NewEmptyVPCConfig()
		newVPCConfig.UIDToResource[vpcNodeSet.ResourceUID] = vpcNodeSet
		newVPCConfig.VPC = vpcNodeSet
		res[vpcNodeSet.ResourceUID] = newVPCConfig
	}
	if len(res) == 0 {
		return errors.New("could not find any VPC to analyze")
	}
	return nil
}

func parseSGTargets(sgResource *SecurityGroup,
	sg *vpc1.SecurityGroup,
	c *vpcmodel.VPCConfig) {
	targets := sg.Targets // *SecurityGroupTargetReference
	// type SecurityGroupTargetReference struct
	for _, target := range targets {
		if targetIntfRef, ok := target.(*vpc1.SecurityGroupTargetReference); ok {
			// get from target name + resource type -> find the address of the target
			targetType := *targetIntfRef.ResourceType
			switch targetType {
			case networkInterfaceResourceType:
				if intfNode, ok := c.UIDToResource[*targetIntfRef.ID]; ok {
					if intfNodeObj, ok := intfNode.(*NetworkInterface); ok {
						sgResource.members[intfNodeObj.Address()] = intfNodeObj
					}
				}
			case vpeResourceType:
				if vpe, ok := c.UIDToResource[*targetIntfRef.CRN]; ok {
					vpeObj := vpe.(*Vpe)
					for _, n := range vpeObj.nodes {
						nIP := n.(*ReservedIP)
						sgResource.members[nIP.Address()] = n
					}
				}
			case loadBalancerResourceType:
				if lb, ok := c.UIDToResource[*targetIntfRef.CRN]; ok {
					lbObj := lb.(*LoadBalancer)
					for _, n := range lbObj.nodes {
						nIP := n.(*PrivateIP)
						sgResource.members[nIP.Address()] = n
					}
				}
			case iksNodeResourceType:
				if intfNode, ok := c.UIDToResource[*targetIntfRef.ID]; ok {
					if intfNodeObj, ok := intfNode.(*IKSNode); ok {
						sgResource.members[intfNodeObj.Address()] = intfNodeObj
					}
				}
			}
		}
	}
}

func getSGconfig(rc *datamodel.ResourcesContainerModel,
	res vpcmodel.MultipleVPCConfigs,
	skipByVPC map[string]bool,
) error {
	sgMap := map[string]map[string]*SecurityGroup{} // map from vpc uid to map from sg name to its sg object
	sgLists := map[string][]*SecurityGroup{}
	for i := range rc.SecurityGroupList {
		sg := rc.SecurityGroupList[i]
		if skipByVPC[*sg.VPC.CRN] {
			continue
		}
		vpcUID := *sg.VPC.CRN
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}

		sgResource := &SecurityGroup{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: *sg.Name,
				ResourceUID:  *sg.CRN,
				ResourceType: ResourceTypeSG,
				VPCRef:       vpc,
				Region:       vpc.RegionName(),
			},
			analyzer: NewSGAnalyzer(&sg.SecurityGroup), members: map[string]vpcmodel.Node{},
		}
		if _, ok := sgMap[vpcUID]; !ok {
			sgMap[vpcUID] = map[string]*SecurityGroup{}
		}
		sgMap[vpcUID][*sg.Name] = sgResource
		parseSGTargets(sgResource, &sg.SecurityGroup, res[vpcUID])
		sgLists[vpcUID] = append(sgLists[vpcUID], sgResource)
	}
	for vpcUID, sgListInstance := range sgLists {
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		sgLayer := &SecurityGroupLayer{
			VPCResource: vpcmodel.VPCResource{
				ResourceType: vpcmodel.SecurityGroupLayer,
				VPCRef:       vpc,
				Region:       vpc.RegionName(),
			},
			sgList: sgListInstance}
		res[vpcUID].FilterResources = append(res[vpcUID].FilterResources, sgLayer)
	}

	for _, vpcSgMap := range sgMap {
		for _, sg := range vpcSgMap {
			// the name of SG is unique across all SG of the VPC
			err := sg.analyzer.prepareAnalyzer(vpcSgMap, sg)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func getNACLconfig(rc *datamodel.ResourcesContainerModel,
	res vpcmodel.MultipleVPCConfigs,
	skipByVPC map[string]bool,
) error {
	naclLists := map[string][]*NACL{} // map from vpc uid to its nacls
	for i := range rc.NetworkACLList {
		nacl := rc.NetworkACLList[i]
		if skipByVPC[*nacl.VPC.CRN] {
			continue
		}
		naclAnalyzer, err := NewNACLAnalyzer(&nacl.NetworkACL)
		if err != nil {
			return err
		}
		vpcUID := *nacl.VPC.CRN
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}

		naclResource := &NACL{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: *nacl.Name,
				ResourceUID:  *nacl.CRN,
				ResourceType: ResourceTypeNACL,
				VPCRef:       vpc,
				Region:       vpc.RegionName(),
			},
			analyzer: naclAnalyzer, subnets: map[string]*Subnet{}}
		naclLists[vpcUID] = append(naclLists[vpcUID], naclResource)
		for _, subnetRef := range nacl.Subnets {
			subnetCRN := *subnetRef.CRN
			if subnetResource, ok := res[vpcUID].UIDToResource[subnetCRN]; ok {
				if subnet, ok := subnetResource.(*Subnet); ok {
					naclResource.subnets[subnet.cidr] = subnet
				} else {
					return fmt.Errorf("getNACLconfig: could not find subnetRef by CRN")
				}
			}
		}
	}

	for vpcUID := range res {
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		naclLayer := &NaclLayer{
			VPCResource: vpcmodel.VPCResource{
				ResourceType: vpcmodel.NaclLayer,
				VPCRef:       vpc,
				Region:       vpc.RegionName(),
			},
			naclList: naclLists[vpcUID]}
		res[vpcUID].FilterResources = append(res[vpcUID].FilterResources, naclLayer)
	}
	return nil
}

func getTgwMap(c *datamodel.ResourcesContainerModel) map[string]*datamodel.TransitGateway {
	tgwIDToTgw := map[string]*datamodel.TransitGateway{}
	for _, tgw := range c.TransitGatewayList {
		tgwIDToTgw[*tgw.Crn] = tgw
	}
	return tgwIDToTgw
}

func getTgwObjects(c *datamodel.ResourcesContainerModel,
	res vpcmodel.MultipleVPCConfigs,
	resourceGroup string,
	regions []string,
	regionToStructMap map[string]*Region) map[string]*TransitGateway {
	tgwMap := map[string]*TransitGateway{} // collect all tgw resources
	tgwToSkip := map[string]bool{}
	tgwIDToTgw := getTgwMap(c)

	for _, tgwConn := range c.TransitConnectionList {
		tgwUID := *tgwConn.TransitGateway.Crn
		tgwName := *tgwConn.TransitGateway.Name
		vpcUID := *tgwConn.NetworkID

		if _, ok := tgwToSkip[tgwUID]; ok {
			continue
		}
		tgwFromConfig, hasTgwConfig := tgwIDToTgw[tgwUID]

		// filtering by resourceGroup
		if resourceGroup != "" {
			if hasTgwConfig { // if there is a transit gateway in the config file
				if *tgwFromConfig.ResourceGroup.ID != resourceGroup {
					tgwToSkip[tgwUID] = true
					continue
				}
			} else {
				logging.Warnf("ignoring tgw with unknown resource-group, tgwID: %s\n", tgwUID)
				tgwToSkip[tgwUID] = true // to avoid having this tgw's same warning issued again from another transitConnection
				continue
			}
		}

		// filtering by region
		if len(regions) > 0 {
			if hasTgwConfig { // if there is a transit gateway in the config file
				if !slices.Contains(regions, *tgwFromConfig.Location) {
					tgwToSkip[tgwUID] = true
					continue
				}
			} else {
				logging.Warnf("ignoring tgw with unknown region, tgwID: %s\n", tgwUID)
				tgwToSkip[tgwUID] = true // to avoid having this tgw's same warning issued again from another transitConnection
				continue
			}
		}
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			logging.Warnf("ignoring vpc that does not exist in tgw config, vpcID: %s\n", vpcUID)
			continue
		}
		if _, ok := tgwMap[tgwUID]; !ok {
			region := ""
			if hasTgwConfig { // if there is a transit gateway in the config file
				region = *tgwFromConfig.Location
			}
			tgw := &TransitGateway{
				VPCResource: vpcmodel.VPCResource{
					ResourceName: tgwName,
					ResourceUID:  tgwUID,
					ResourceType: ResourceTypeTGW,
					Region:       region,
				},
				vpcs:            []*VPC{vpc},
				availableRoutes: map[string][]*ipblock.IPBlock{},
				vpcsAPToFilters: map[string][]IPBlockPrefixFilter{},
				region:          getRegionByName(region, regionToStructMap),
			}
			tgwMap[tgwUID] = tgw
		} else {
			tgwMap[tgwUID].vpcs = append(tgwMap[tgwUID].vpcs, vpc)
		}

		advertisedRoutes, vpcApsPrefixes, err := getVPCAdvertisedRoutes(tgwConn, vpc)
		if err != nil {
			logging.Warnf("ignoring prefix filters, vpcID: %s, tgwID: %s, err is: %s\n", vpcUID, tgwUID, err.Error())
		} else {
			// availableRoutes are the address prefixes from this VPC reaching to the TGW's routes table
			tgwMap[tgwUID].availableRoutes[vpcUID] = append(tgwMap[tgwUID].availableRoutes[vpcUID], advertisedRoutes...)
			// TGW's sourceSubnets contains all subnets from its connected VPCs
			tgwMap[tgwUID].sourceSubnets = append(tgwMap[tgwUID].sourceSubnets, vpc.subnets()...)
			// TGW's destSubnets contains subnets from its connected VPCs which are contained within routes from its table
			tgwMap[tgwUID].destSubnets = append(tgwMap[tgwUID].destSubnets, getVPCdestSubnetsByAdvertisedRoutes(tgwMap[tgwUID], vpc)...)
			tgwMap[tgwUID].addSourceAndDestNodes()

			// explainability related struct initialization
			tgwMap[tgwUID].vpcsAPToFilters[vpcUID] = vpcApsPrefixes
		}
	}
	return tgwMap
}

// validateVPCsAddressPrefixesForTGW checks that all VPCs address prefixes (connected by TGW) are disjoint,
// returns error if address prefixes are missing or overlapping
func validateVPCsAddressPrefixesForTGW(vpcsList []*VPC) (err error) {
	ipBlocksForAP := make([]*ipblock.IPBlock, len(vpcsList))
	for i, vpc := range vpcsList {
		if len(vpc.addressPrefixes) == 0 {
			return fmt.Errorf("TGW analysis requires all VPCs have configured address prefixes, but this is missing for vpc %s", vpc.NameAndUID())
		}
		ipBlocksForAP[i], err = ipblock.FromCidrList(vpc.addressPrefixes)
		if err != nil {
			return err
		}
	}

	// validate disjoint address prefixes for each VPCs pair
	for i1 := range ipBlocksForAP {
		for i2 := range ipBlocksForAP[i1+1:] {
			if !ipBlocksForAP[i1].Intersect(ipBlocksForAP[i1+1:][i2]).IsEmpty() {
				return fmt.Errorf("TGW analysis requires all VPCs have disjoint address prefixes, but found intersecting ones for vpcs %s, %s",
					vpcsList[i1].NameAndUID(), vpcsList[i1+1:][i2].NameAndUID())
			}
		}
	}
	return nil
}

// For each Transit Gateway, generate a config that combines multiple vpc entities, which are
// connected by the tgw and add the config to res
// currently assuming only all-to-all connectivity is configured
// in the analysis, such a config should only focus on connections cross-vpcs
// should make sure that the internal address ranges per all connected vpcs are disjoint
func addTGWbasedConfigs(tgws map[string]*TransitGateway, res vpcmodel.MultipleVPCConfigs) error {
	for _, tgw := range tgws {
		if len(tgw.vpcs) <= 1 {
			// skip tgw if it does not connect between at least 2 vpcs
			logging.Warnf("skipping TGW %s, as it is not connected to at least 2 VPCs\n", tgw.NameAndUID())
			continue
		}
		// TODO: for now, the analysis supports only disjoint VPCs address prefixes
		// consider adding support for overlapping address prefixes with conflict resolution logic
		if err := validateVPCsAddressPrefixesForTGW(tgw.vpcs); err != nil {
			logging.Warnf("skipping TGW %s: %s\n", tgw.NameAndUID(), err.Error())
			continue
		}
		newConfig := &vpcmodel.VPCConfig{
			UIDToResource:        map[string]vpcmodel.VPCResourceIntf{},
			IsMultipleVPCsConfig: true,
		}
		var vpcsAddressRanges *ipblock.IPBlock // collect all internal address ranges of involved VPCs
		nacls := &NaclLayer{VPCResource: vpcmodel.VPCResource{ResourceType: vpcmodel.NaclLayer}}
		sgs := &SecurityGroupLayer{VPCResource: vpcmodel.VPCResource{ResourceType: vpcmodel.SecurityGroupLayer}}
		for _, vpc := range tgw.vpcs { // iterate the involved VPCs -- all of them are connected (all to all)
			vpcConfig, ok := res[vpc.ResourceUID]
			if !ok {
				return fmt.Errorf("missing vpc config for vpc CRN %s", vpc.ResourceUID)
			}
			// merge vpc config to the new "combined" config, used to get conns between vpcs only
			newConfig.Nodes = append(newConfig.Nodes, vpcConfig.Nodes...)
			newConfig.NodeSets = append(newConfig.NodeSets, vpcConfig.NodeSets...)
			newConfig.Subnets = append(newConfig.Subnets, vpcConfig.Subnets...)
			newConfig.CloudName = vpcConfig.CloudName
			// FilterResources: merge NACLLayers to a single NACLLayer object, same for sg
			for _, fr := range vpcConfig.FilterResources {
				switch layer := fr.(type) {
				case *NaclLayer:
					nacls.naclList = append(nacls.naclList, layer.naclList...)
				case *SecurityGroupLayer:
					sgs.sgList = append(sgs.sgList, layer.sgList...)
				default:
					return fmt.Errorf("unexpected type for filter resource in VPC %s", vpc.ResourceUID)
				}
			}

			// omit routing resources -- assuming only internal vpc-to-vpc connectivity is of interest to analyze
			// TODO: is there a scenario of connectivity from one vpc's vsi to external entity through another vpc's pgw/fip ?

			// simple union for NameToResource map
			for n, r := range vpcConfig.UIDToResource {
				newConfig.UIDToResource[n] = r
			}
			if vpcsAddressRanges == nil {
				vpcsAddressRanges = vpcConfig.VPC.(*VPC).internalAddressRange
			} else {
				// currently supporting only disjoint address ranges for the connected VPCs
				intersection := vpcsAddressRanges.Intersect(vpcConfig.VPC.(*VPC).internalAddressRange)
				if !intersection.IsEmpty() {
					logging.Warnf("ignoring TGW %s, as currently not supporting connected VPCs with overlapping address ranges\n",
						tgw.ResourceName)
					continue
				}
				vpcsAddressRanges = vpcsAddressRanges.Union(vpcConfig.VPC.(*VPC).internalAddressRange)
			}
		}

		internalNodes := []vpcmodel.Node{}
		for _, n := range newConfig.Nodes {
			if n.IsInternal() {
				internalNodes = append(internalNodes, n)
			}
		}
		newConfig.Nodes = internalNodes
		// no need to add external nodes - analyzing cross-vpc connections between internal endpoints

		const vpcPrefix = "combined-vpc-"
		newConfig.VPC = &VPC{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: vpcPrefix + tgw.ResourceName,
				ResourceUID:  vpcPrefix + tgw.ResourceUID,
				ResourceType: ResourceTypeVPC,
			},
			internalAddressRange: vpcsAddressRanges,
			nodes:                internalNodes,
			region:               tgw.region,
		}
		nacls.VPCRef = newConfig.VPC
		sgs.VPCRef = newConfig.VPC
		// TODO: analysis should warn if more than one naclLayer/sgLayer is present in FilterTrafficResource, as it is going
		// to be ignored
		newConfig.FilterResources = []vpcmodel.FilterTrafficResource{nacls, sgs}
		newConfig.RoutingResources = []vpcmodel.RoutingResource{tgw}

		res[newConfig.VPC.UID()] = newConfig
	}
	return nil
}

func getSubnetByIPAddress(addressIPblock *ipblock.IPBlock, c *vpcmodel.VPCConfig) (subnet *Subnet, err error) {
	for _, s := range c.Subnets {
		if addressIPblock.ContainedIn(s.AddressRange()) {
			return s.(*Subnet), nil
		}
	}
	return nil, fmt.Errorf("could not find matching subnet for address %s", addressIPblock.ToIPAddressString())
}

func getVPEconfig(rc *datamodel.ResourcesContainerModel,
	res vpcmodel.MultipleVPCConfigs,
	skipByVPC map[string]bool,
) (err error) {
	for _, vpe := range rc.EndpointGWList {
		if skipByVPC[*vpe.VPC.CRN] {
			continue
		}
		vpcUID := *vpe.VPC.CRN
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		vpeResource := &Vpe{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: *vpe.Name,
				ResourceUID:  *vpe.CRN,
				ResourceType: ResourceTypeVPE,
				VPCRef:       vpc,
				Region:       vpc.RegionName(),
			},
		}
		res[vpcUID].NodeSets = append(res[vpcUID].NodeSets, vpeResource)
		rIPList := vpe.Ips // reserved ips bound to this endpoint gateway
		for _, rIP := range rIPList {
			rIPNode := &ReservedIP{
				VPCResource: vpcmodel.VPCResource{
					ResourceName: *rIP.Name,
					ResourceUID:  *rIP.ID,
					ResourceType: ResourceTypeReservedIP,
					Zone:         "",
					VPCRef:       vpc,
					Region:       vpc.RegionName(),
				}, // the zone gets updated later
				InternalNode: vpcmodel.InternalNode{
					AddressStr: *rIP.Address,
				},
				vpe: *vpe.Name,
			}
			if err := rIPNode.SetIPBlockFromAddress(); err != nil {
				return err
			}
			subnet, err := getSubnetByIPAddress(rIPNode.IPBlock(), res[vpcUID])
			if err != nil {
				return err
			}
			rIPNode.SubnetResource = subnet
			rIPNode.Zone = subnet.ZoneName()
			res[vpcUID].Nodes = append(res[vpcUID].Nodes, rIPNode)
			// TODO: make sure the address is in the subnet's reserved ips list?
			subnet.nodes = append(subnet.nodes, rIPNode)
			res[vpcUID].UIDToResource[rIPNode.ResourceUID] = rIPNode
			vpeResource.nodes = append(vpeResource.nodes, rIPNode)
		}
		res[vpcUID].UIDToResource[vpeResource.ResourceUID] = vpeResource
		// TODO: verify that vpe.SecurityGroups contain the reserved-ips as members? (not at this stage)
		// sgList := vpe.SecurityGroups
	}
	return nil
}

func getSubnetByCidr(res vpcmodel.MultipleVPCConfigs, cidr string) (*Subnet, error) {
	for _, config := range res {
		if subnet, err := config.SubnetCidrToSubnetElem(cidr); err == nil {
			return subnet.(*Subnet), nil
		}
	}
	return nil, fmt.Errorf("could not find subnet with cidr: %s", cidr)
}

func findSGWithClusterName(rc *datamodel.ResourcesContainerModel, clusterID string) *datamodel.SecurityGroup {
	for _, sg := range rc.SecurityGroupList {
		if *sg.Name == "kube-"+clusterID {
			return sg
		}
	}
	return nil
}

func findDefaultSGForVpc(rc *datamodel.ResourcesContainerModel, vpcUID string) *datamodel.SecurityGroup {
	for _, vpc := range rc.VpcList {
		if *vpc.CRN != vpcUID {
			continue
		}
		defaultSgCRN := vpc.DefaultSecurityGroup.CRN
		for _, sg := range rc.SecurityGroupList {
			if *sg.CRN == *defaultSgCRN {
				return sg
			}
		}
	}
	return nil
}

func addIKSNodesAsSGTarget(sg *datamodel.SecurityGroup, iksCluster *datamodel.IKSCluster) {
	if sg == nil {
		return
	}
	for _, iksNode := range iksCluster.WorkerNodes {
		resourceType := iksNodeResourceType
		target := &vpc1.SecurityGroupTargetReference{
			ID:           iksNode.ID,
			ResourceType: &resourceType,
		}
		sg.Targets = append(sg.Targets, target)
	}
}

// assuming getIKSnodesConfig is called before getSGconfig,
// because it updates the input SG targets with missing IKS nodes, if there are such
func getIKSnodesConfig(res vpcmodel.MultipleVPCConfigs,
	rc *datamodel.ResourcesContainerModel,
	skipByVPC map[string]bool) error {
	for _, iksCluster := range rc.IKSClusters {
		sg := findSGWithClusterName(rc, *iksCluster.ID)
		var defaultSG *datamodel.SecurityGroup
		for i, iksNode := range iksCluster.WorkerNodes {
			if len(iksNode.NetworkInterfaces) != 1 {
				return errIksParsing
			}
			iksNodeNetIntfObj := iksNode.NetworkInterfaces[0]

			subnet, err := getSubnetByCidr(res, *iksNodeNetIntfObj.Cidr)
			if err != nil {
				logging.Warnf("ignoring iksNode with ID %s (could not find subnet with iksNode's CIDR: %s)\n",
					*iksNode.ID, *iksNodeNetIntfObj.Cidr)
				continue
			}
			if skipByVPC[subnet.VPC().UID()] {
				continue
			}
			vpcUID := subnet.VPC().UID()
			if i == 0 {
				// first iksNode - assuming all cluster nodes are in the same vpc, thus sufficient to check vpc of the first node
				defaultSG = findDefaultSGForVpc(rc, vpcUID)
			}
			vpc := subnet.VPC()
			nodeObject := &IKSNode{
				VPCResource: vpcmodel.VPCResource{
					ResourceName: "iks-node",
					ResourceUID:  *iksNode.ID,
					ResourceType: ResourceTypeIKSNode,
					VPCRef:       vpc,
					Region:       vpc.RegionName(),
				},
				InternalNode: vpcmodel.InternalNode{
					AddressStr:     *iksNodeNetIntfObj.IpAddress,
					SubnetResource: subnet,
				},
			}
			res[vpcUID].UIDToResource[nodeObject.ResourceUID] = nodeObject
			if err := nodeObject.SetIPBlockFromAddress(); err != nil {
				return err
			}
			res[vpcUID].Nodes = append(res[vpcUID].Nodes, nodeObject)
			// attach the node to the subnet
			subnet.nodes = append(subnet.nodes, nodeObject)
		}
		// adding the IKS nodes as target of its relevant SGs (the input config object is missing those targets)
		addIKSNodesAsSGTarget(sg, iksCluster)
		addIKSNodesAsSGTarget(defaultSG, iksCluster)
	}
	return nil
}

func NewEmptyVPCConfig() *vpcmodel.VPCConfig {
	return &vpcmodel.VPCConfig{
		UIDToResource: map[string]vpcmodel.VPCResourceIntf{},
		CloudName:     "IBM Cloud",
	}
}

// filter VPCs with empty address ranges, then add for remaining VPCs the external nodes
func filterVPCSAndAddExternalNodes(vpcInternalAddressRange map[string]*ipblock.IPBlock, res map[string]*vpcmodel.VPCConfig) error {
	for vpcUID, vpcConfig := range res {
		if vpcInternalAddressRange[vpcUID] == nil {
			logging.Warnf("Ignoring VPC %s, no subnets found for this VPC\n", vpcUID)
			delete(res, vpcUID)
			continue
		}
		err := handlePublicInternetNodes(vpcConfig, vpcInternalAddressRange[vpcUID])
		if err != nil {
			return err
		}
	}
	return nil
}

func updateVPCSAddressRanges(vpcInternalAddressRange map[string]*ipblock.IPBlock,
	vpcsMap map[string]*vpcmodel.VPCConfig) error {
	// assign to each vpc object its internal address range, as inferred from its subnets
	for vpcUID, addressRange := range vpcInternalAddressRange {
		var vpc *VPC
		vpc, err := getVPCObjectByUID(vpcsMap, vpcUID)
		if err != nil {
			return err
		}
		vpc.internalAddressRange = addressRange
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
		if rFip, ok := r.(*FloatingIP); ok {
			rFip.destinations = publicInternetNodes
		}
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

func getVPCObjectByUID(res vpcmodel.MultipleVPCConfigs, uid string) (*VPC, error) {
	vpcConfig, ok := res[uid]
	if !ok {
		return nil, fmt.Errorf("missing VPC resource of uid %s", uid)
	}
	vpc, ok := vpcConfig.VPC.(*VPC)
	if !ok {
		return nil, fmt.Errorf("VPC missing from config of VPCConfig with uid %s", uid)
	}
	return vpc, nil
}

func setSubnetsFreeAddresses(rc *datamodel.ResourcesContainerModel,
	res map[string]*vpcmodel.VPCConfig) map[vpcmodel.Subnet]*ipblock.IPBlock {
	subnetsFreeAddresses := map[vpcmodel.Subnet]*ipblock.IPBlock{}
	for _, subnetObj := range rc.SubnetList {
		subnet := res[*subnetObj.VPC.CRN].UIDToResource[*subnetObj.CRN].(vpcmodel.Subnet)
		b, _ := ipblock.FromCidr(subnet.CIDR())
		for _, reservedIp := range subnetObj.ReservedIps {
			b2, _ := ipblock.FromIPAddress(*reservedIp.Address)
			b = b.Subtract(b2)
		}
		subnetsFreeAddresses[subnet] = b
	}
	return subnetsFreeAddresses
}

func allocSubnetFreeAddress(subnetsFreeAddresses map[vpcmodel.Subnet]*ipblock.IPBlock, subnet vpcmodel.Subnet) string {
	address := subnetsFreeAddresses[subnet].Split()[0].ToIPRanges()
	address = strings.Split(address, "-")[0]
	b2, _ := ipblock.FromIPAddress(address)
	subnetsFreeAddresses[subnet] = subnetsFreeAddresses[subnet].Subtract(b2)
	return address
}

// ////////////////////////////////////////////////////////////////
// Load Balancer Parsing: (I made it capital G, so lint will not cry)
func GetLoadBalancersConfig(rc *datamodel.ResourcesContainerModel,
	res map[string]*vpcmodel.VPCConfig,
	skipByVPC map[string]bool,
) (err error) {
	subnetsFreeAddresses := setSubnetsFreeAddresses(rc, res)
	for _, loadBalancerObj := range rc.LBList {
		vpcUID, err := getLoadBalancerVpcUID(rc, loadBalancerObj)
		if err != nil {
			return err
		}
		if skipByVPC[vpcUID] {
			continue
		}
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		loadBalancer := &LoadBalancer{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: *loadBalancerObj.Name,
				ResourceUID:  *loadBalancerObj.CRN,
				ResourceType: ResourceTypeLoadBalancer,
				VPCRef:       vpc,
			},
		}

		loadBalancer.listeners = getLoadBalancerServer(res, loadBalancerObj, vpcUID)
		privateIPs, err := getLoadBalancerIPs(res, loadBalancerObj, loadBalancer, vpcUID, vpc, subnetsFreeAddresses)
		if err != nil {
			return err
		}
		loadBalancer.nodes = privateIPs
		res[vpcUID].UIDToResource[loadBalancer.ResourceUID] = loadBalancer
		res[vpcUID].LoadBalancers = append(res[vpcUID].LoadBalancers, loadBalancer)
	}
	return nil
}

func getLoadBalancerVpcUID(rc *datamodel.ResourcesContainerModel, loadBalancerObj *datamodel.LoadBalancer) (string, error) {
	// somehow the load balancer does not have info on the vpc,
	// getting the vpc from one of the subnets:
	aSubnetUID := *loadBalancerObj.Subnets[0].CRN
	for _, subnet := range rc.SubnetList {
		if aSubnetUID == *subnet.CRN {
			return *subnet.VPC.CRN, nil
		}
	}
	return "", fmt.Errorf("VPC missing from config of loadBalancer %s", *loadBalancerObj.Name)
}

// getLoadBalancerServer() parse and return all the servers.
// currently as a list of listeners, TBD
func getLoadBalancerServer(res map[string]*vpcmodel.VPCConfig,
	loadBalancerObj *datamodel.LoadBalancer,
	vpcUID string) []LoadBalancerListener {
	pools := map[string]LoadBalancerPool{}
	listeners := []LoadBalancerListener{}
	for _, poolObj := range loadBalancerObj.Pools {
		pool := LoadBalancerPool{}
		// todo: handle pools currently we just collect them
		// pool.name = *poolObj.Name
		// pool.protocol = *poolObj.Protocol
		for _, memberObj := range poolObj.Members {
			// todo handle the ports:
			// member.port = *memberObj.Port
			address := *memberObj.Target.(*vpc1.LoadBalancerPoolMemberTarget).Address
			pool = append(pool, getCertainNodes(res[vpcUID].Nodes, func(n vpcmodel.Node) bool { return n.CidrOrAddress() == address })...)
		}
		pools[*poolObj.ID] = pool
	}
	for listenerIndex := range loadBalancerObj.Listeners {
		listenerObj := loadBalancerObj.Listeners[listenerIndex]
		listener := LoadBalancerListener{}
		// todo: handle listeners, currency we just collect them
		// if lisObj.Port != nil {
		// 	lis.port = *lisObj.Port
		// }
		// if lisObj.PortMin != nil {
		// 	lis.portMin = *lisObj.PortMin
		// 	lis.portMax = *lisObj.PortMax
		// }
		// lis.protocol = *lisObj.Protocol
		for _, policy := range listenerObj.Policies {
			if pool, ok := pools[*policy.Target.(*vpc1.LoadBalancerListenerPolicyTarget).ID]; ok {
				// todo  - handle rules:
				//rules := policy.Rules
				listener = append(listener, pool)
			}
		}
		if pool, ok := pools[*listenerObj.DefaultPool.ID]; ok {
			listener = append(listener, pool)
		}
		listeners = append(listeners, listener)
	}
	return listeners
}

// ///////////////////////////////////////////////////////////
// getLoadBalancerIPs() parse the private Ips
// create public IPs as routers of the private IPs
// returns the private IPs nodes
func getLoadBalancerIPs(res map[string]*vpcmodel.VPCConfig,
	loadBalancerObj *datamodel.LoadBalancer,
	loadBalancer *LoadBalancer,
	vpcUID string, vpc *VPC,
	subnetsFreeAddresses map[vpcmodel.Subnet]*ipblock.IPBlock) ([]vpcmodel.Node, error) {
	subnetsWithPrivateIPs := map[vpcmodel.Subnet]int{}
	hasPublicAddress := len(loadBalancerObj.PublicIps) > 0
	for i, pIP := range loadBalancerObj.PrivateIps {
		add, err := ipblock.FromIPAddress(*pIP.Address)
		if err != nil {
			return nil, err
		}
		subnet, err := getSubnetByIPAddress(add, res[vpcUID])
		if err != nil {
			return nil, err
		}
		subnetsWithPrivateIPs[subnet] = i
	}
	privateIPs := []vpcmodel.Node{}
	for _, subnetObj := range loadBalancerObj.Subnets {
		subnet := res[vpcUID].UIDToResource[*subnetObj.CRN].(*Subnet)
		var name, id, address, publicAddress string
		pipIndex, original := subnetsWithPrivateIPs[subnet]
		if original {
			pIP := loadBalancerObj.PrivateIps[pipIndex]
			name, id, address = *pIP.Name, *pIP.ID, *pIP.Address
			if hasPublicAddress {
				publicAddress = *loadBalancerObj.PublicIps[pipIndex].Address
			}
		} else {
			name = "pip-name-of-" + subnet.Name() + "-" + *loadBalancerObj.Name
			id = "pip-uid-of-" + subnet.UID() + *loadBalancerObj.ID
			address = allocSubnetFreeAddress(subnetsFreeAddresses, subnet)
			if hasPublicAddress {
				publicAddress = *loadBalancerObj.PublicIps[0].Address
			}
		}
		privateIP := &PrivateIP{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: name,
				ResourceUID:  id,
				ResourceType: ResourceTypePrivateIP,
				Zone:         "",
				VPCRef:       vpc,
			}, // the zone gets updated later
			InternalNode: vpcmodel.InternalNode{
				AddressStr: address,
			},
			loadBalancer: loadBalancer,
			original:     original,
		}
		if err := privateIP.SetIPBlockFromAddress(); err != nil {
			return nil, err
		}
		privateIP.SubnetResource = subnet
		privateIP.Zone = subnet.ZoneName()
		res[vpcUID].Nodes = append(res[vpcUID].Nodes, privateIP)
		subnet.nodes = append(subnet.nodes, privateIP)
		res[vpcUID].UIDToResource[privateIP.ResourceUID] = privateIP
		privateIPs = append(privateIPs, privateIP)
		// if the load balancer have public Ips, we attach every private ip a floating ip
		if hasPublicAddress {
			routerFip := &FloatingIP{
				VPCResource: vpcmodel.VPCResource{
					ResourceName: "fip-name-of-" + privateIP.Name(),
					ResourceUID:  "fip-uid-of-" + privateIP.UID(),
					Zone:         privateIP.ZoneName(),
					ResourceType: ResourceTypeFloatingIP,
					VPCRef:       vpc,
				},
				cidr: publicAddress, src: []vpcmodel.Node{privateIP}}
			res[vpcUID].RoutingResources = append(res[vpcUID].RoutingResources, routerFip)
			res[vpcUID].UIDToResource[routerFip.ResourceUID] = routerFip
		}
	}
	return privateIPs, nil
}

/********** Functions used in Debug mode ***************/

func printVPCConfigs(c vpcmodel.MultipleVPCConfigs) {
	fmt.Println("VPCs to analyze:")
	for vpcUID, config := range c {
		fmt.Printf("VPC UID: %s, Name: %s\n", vpcUID, config.VPC.Name())
	}
	printLineSection()
	for vpcUID, config := range c {
		fmt.Printf("config for vpc %s (vpc name: %s)\n", vpcUID, config.VPC.Name())
		printConfig(config)
	}
	printLineSection()
}

func printLineSection() {
	fmt.Println("-----------------------------------------")
}

func printConfig(c *vpcmodel.VPCConfig) {
	separator := " "
	fmt.Println("Nodes:")
	for _, n := range c.Nodes {
		if n.IsExternal() {
			continue
		}
		fmt.Println(strings.Join([]string{n.Kind(), n.CidrOrAddress(), n.Name(), n.UID()}, separator))
	}
	fmt.Println("Subnets:")
	for _, n := range c.Subnets {
		fmt.Println(strings.Join([]string{n.Kind(), n.CIDR(), n.Name(), n.UID()}, separator))
	}
	fmt.Println("LoadBalancers:")
	for _, lb := range c.LoadBalancers {
		fmt.Println(strings.Join([]string{lb.Kind(), lb.Name(), lb.AddressRange().ToIPRanges(), lb.UID()}, separator))
	}
	fmt.Println("NodeSets:")
	for _, n := range c.NodeSets {
		fmt.Println(strings.Join([]string{n.Kind(), n.AddressRange().ToIPRanges(), n.Name(), n.UID()}, separator))
	}
	fmt.Println("FilterResources:")
	for _, f := range c.FilterResources {
		switch filters := f.(type) {
		case *NaclLayer:
			for _, nacl := range filters.naclList {
				if len(nacl.subnets) == 0 {
					continue
				}
				fmt.Println(strings.Join([]string{nacl.ResourceType, nacl.ResourceName, nacl.UID()}, separator))
				printNACLRules(nacl)
			}
		case *SecurityGroupLayer:
			for _, sg := range filters.sgList {
				if len(sg.members) == 0 {
					continue
				}
				fmt.Println(strings.Join([]string{sg.ResourceType, sg.ResourceName, sg.UID()}, separator))
				printSGRules(sg)
			}
		}
	}
	fmt.Println("RoutingResources:")
	for _, r := range c.RoutingResources {
		fmt.Println(strings.Join([]string{r.Kind(), r.Name(), r.UID()}, separator))
		if tgw, ok := r.(*TransitGateway); ok {
			printTGWAvailableRoutes(tgw)
		}
	}
}

func printTGWAvailableRoutes(tgw *TransitGateway) {
	for vpcUID, rList := range tgw.availableRoutes {
		fmt.Printf("routes for vpc %s:\n", vpcUID)
		for _, r := range rList {
			fmt.Printf("%s\n", r.ToCidrList())
		}
	}
}

func printSGRules(sg *SecurityGroup) {
	fmt.Printf("num rules: %d\n", len(sg.analyzer.sgResource.Rules))
	numRules := len(sg.analyzer.sgResource.Rules)
	for i := 0; i < numRules; i++ {
		strRule, _, _, err := sg.analyzer.getSGRule(i)
		printRule(strRule, i, err)
	}
}

func printNACLRules(nacl *NACL) {
	numRules := len(nacl.analyzer.naclResource.Rules)
	for i := 0; i < numRules; i++ {
		strRule, _, _, err := nacl.analyzer.getNACLRule(i)
		printRule(strRule, i, err)
	}
}

func printRule(ruleStr string, index int, err error) {
	if err == nil {
		fmt.Println(ruleStr)
	} else {
		fmt.Printf("err for rule %d: %s\n", index, err.Error())
	}
}
