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
	// todo - do we need to run the load balancer at the right place?
	// err = GetLoadBalancersConfig(rc, res, shouldSkipVpcIds)
	// if err != nil {
	// 	return nil, err
	// }
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
	iksNodeResourceType          = "iks_node"          // used as the type within api objects (e.g. SecurityGroup.Targets.ResourceType)
	cidrSeparator                = ", "
	linesSeparator               = "---------------------"
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
			intfNode := &NetworkInterface{
				VPCResource: vpcmodel.VPCResource{
					ResourceName: *netintf.Name,
					ResourceUID:  *netintf.ID,
					ResourceType: ResourceTypeNetworkInterface,
					Zone:         *instance.Zone.Name,
					VPCRef:       vpc,
					Region:       vpc.RegionName(),
				},
				InternalNode: vpcmodel.InternalNode{
					AddressStr: *netintf.PrimaryIP.Address,
				},
				vsi: *instance.Name,
			}

			if err := intfNode.SetIPBlockFromAddress(); err != nil {
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
		subnetNode := &Subnet{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: *subnet.Name,
				ResourceUID:  *subnet.CRN,
				Zone:         *subnet.Zone.Name,
				ResourceType: ResourceTypeSubnet,
				VPCRef:       vpc,
				Region:       vpc.RegionName(),
			},
			cidr: *subnet.Ipv4CIDRBlock,
		}

		cidrIPBlock, err := ipblock.FromCidr(subnetNode.cidr)
		if err != nil {
			return nil, err
		}
		subnetNode.ipblock = cidrIPBlock
		if vpcInternalAddressRange[vpcUID] == nil {
			vpcInternalAddressRange[vpcUID] = cidrIPBlock
		} else {
			vpcInternalAddressRange[vpcUID] = vpcInternalAddressRange[vpcUID].Union(cidrIPBlock)
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
			fmt.Printf("warning: public gateway %s does not have any attached subnet, ignoring this pgw\n", pgwName)
			continue
		}
		srcNodes := getSubnetsNodes(pgwToSubnet[pgwName])
		vpcUID := *pgw.VPC.CRN
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		routerPgw := &PublicGateway{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: *pgw.Name,
				ResourceUID:  *pgw.CRN,
				Zone:         *pgw.Zone.Name,
				ResourceType: ResourceTypePublicGateway,
				VPCRef:       vpc,
				Region:       vpc.RegionName(),
			},
			cidr:       "",
			src:        srcNodes,
			srcSubnets: pgwToSubnet[pgwName],
			subnetCidr: getSubnetsCidrs(pgwToSubnet[pgwName]),
			vpc:        vpc,
		} // TODO: get cidr from fip of the pgw
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
	return fmt.Sprintf("warning: ignoring floatingIP %s: %s", fipName, details)
}

func warnSkippedFip(filteredOutUIDs map[string]bool, targetUID string, fip *datamodel.FloatingIP) {
	if !filteredOutUIDs[targetUID] {
		fmt.Printf("warning: skip fip %s - could not find attached network interface\n", *fip.Name)
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
				fmt.Println(ignoreFIPWarning(*fip.Name,
					fmt.Sprintf("target.ResourceType %s is not supported (only networkInterfaceResourceType supported)",
						*target.ResourceType)))
				continue
			}
			targetUID = *target.ID
		default:
			fmt.Println(ignoreFIPWarning(*fip.Name, "target (FloatingIPTargetIntf) is not of the expected type"))
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

		routerFip := &FloatingIP{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: *fip.Name,
				ResourceUID:  *fip.CRN,
				Zone:         *fip.Zone.Name,
				ResourceType: ResourceTypeFloatingIP,
				VPCRef:       vpc,
				Region:       vpc.RegionName(),
			},
			cidr: *fip.Address, src: srcNodes}
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

func getVPCconfig(rc *datamodel.ResourcesContainerModel,
	res vpcmodel.MultipleVPCConfigs,
	skipByVPC map[string]bool,
	regionToStructMap map[string]*Region) error {
	for _, vpc := range rc.VpcList {
		if skipByVPC[*vpc.CRN] {
			continue // skip vpc not specified to analyze
		}
		vpcName := *vpc.Name
		vpcNodeSet := &VPC{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: vpcName,
				ResourceUID:  *vpc.CRN,
				ResourceType: ResourceTypeVPC,
				Region:       vpc.Region,
			},
			nodes:           []vpcmodel.Node{},
			zones:           map[string]*Zone{},
			addressPrefixes: getVPCAddressPrefixes(vpc),
			region:          getRegionByName(vpc.Region, regionToStructMap),
		}
		vpcNodeSet.VPCRef = vpcNodeSet
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
				fmt.Printf("warning: ignoring tgw with unknown resource-group, tgwID: %s\n", tgwUID)
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
				fmt.Printf("warning: ignoring tgw with unknown region, tgwID: %s\n", tgwUID)
				tgwToSkip[tgwUID] = true // to avoid having this tgw's same warning issued again from another transitConnection
				continue
			}
		}
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			fmt.Printf("warning: ignoring vpc that does not exist in tgw config, vpcID: %s\n", vpcUID)
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
				region:          getRegionByName(region, regionToStructMap),
			}
			tgwMap[tgwUID] = tgw
		} else {
			tgwMap[tgwUID].vpcs = append(tgwMap[tgwUID].vpcs, vpc)
		}

		advertisedRoutes, err := getVPCAdvertisedRoutes(tgwConn, vpc)
		if err != nil {
			fmt.Printf("warning: ignoring prefix filters, vpcID: %s, tgwID: %s, err is: %s\n", vpcUID, tgwUID, err.Error())
		} else {
			// availableRoutes are the address prefixes from this VPC reaching to the TGW's routes table
			tgwMap[tgwUID].availableRoutes[vpcUID] = append(tgwMap[tgwUID].availableRoutes[vpcUID], advertisedRoutes...)
			// TGW's sourceSubnets contains all subnets from its connected VPCs
			tgwMap[tgwUID].sourceSubnets = append(tgwMap[tgwUID].sourceSubnets, vpc.subnets()...)
			// TGW's destSubnets contains subnets from its connected VPCs which are contained within routes from its table
			tgwMap[tgwUID].destSubnets = append(tgwMap[tgwUID].destSubnets, getVPCdestSubnetsByAdvertisedRoutes(tgwMap[tgwUID], vpc)...)
			tgwMap[tgwUID].addSourceAndDestNodes()
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
			fmt.Printf("skipping TGW %s, as it is not connected to at least 2 VPCs\n", tgw.NameAndUID())
			continue
		}
		// TODO: for now, the analysis supports only disjoint VPCs address prefixes
		// consider adding support for overlapping address prefixes with conflict resolution logic
		if err := validateVPCsAddressPrefixesForTGW(tgw.vpcs); err != nil {
			fmt.Printf("skipping TGW %s: %s\n", tgw.NameAndUID(), err.Error())
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
					fmt.Printf("warning: ignoring TGW %s, as currently not supporting connected VPCs with overlapping address ranges\n",
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
		sgCRN := vpc.DefaultSecurityGroup.CRN
		for _, sg := range rc.SecurityGroupList {
			if *sg.CRN == *sgCRN {
				return sg
			}
		}
	}
	return nil
}

func addIKSNodeAsSGTarget(sg *datamodel.SecurityGroup, iksCluster *datamodel.IKSCluster) {
	if sg == nil {
		return
	}
	// this sg should not have any targets
	targets := make([]vpc1.SecurityGroupTargetReferenceIntf, 0)
	for _, iksNode := range iksCluster.WorkerNodes {
		target := new(vpc1.SecurityGroupTargetReference)
		target.ID = iksNode.ID
		resourceType := new(string)
		*resourceType = iksNodeResourceType
		target.ResourceType = resourceType
		targets = append(targets, vpc1.SecurityGroupTargetReferenceIntf(target))
	}
	sg.Targets = targets
}

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
				fmt.Printf("warning: ignoring iksNode with ID %s (could not find subnet with iksNode's CIDR: %s)\n",
					*iksNode.ID, *iksNodeNetIntfObj.Cidr)
				continue
			}
			if skipByVPC[subnet.VPC().UID()] {
				continue
			}
			vpcUID := subnet.VPC().UID()
			if i == 0 {
				// first iksNode
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
			addIKSNodeAsSGTarget(sg, iksCluster)
			addIKSNodeAsSGTarget(defaultSG, iksCluster)
			if err := nodeObject.SetIPBlockFromAddress(); err != nil {
				return err
			}
			res[vpcUID].Nodes = append(res[vpcUID].Nodes, nodeObject)
			// attach the node to the subnet
			subnet.nodes = append(subnet.nodes, nodeObject)
		}
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
			fmt.Printf("Ignoring VPC %s, no subnets found for this VPC\n", vpcUID)
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

// ////////////////////////////////////////////////////////////////
// Load Balancer Parsing: (I made it capital G, so lint will not cry)
func GetLoadBalancersConfig(rc *datamodel.ResourcesContainerModel,
	res map[string]*vpcmodel.VPCConfig,
	skipByVPC map[string]bool,
) (err error) {
	for _, loadBalancerObj := range rc.LBList {
		if !checkLoadBalancerValidity(loadBalancerObj) {
			continue
		}
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
		privateIPs, err := getLoadBalancerIPs(res, loadBalancerObj, vpcUID, vpc)
		if err != nil {
			return err
		}
		loadBalancer.nodes = privateIPs
		res[vpcUID].UIDToResource[loadBalancer.ResourceUID] = loadBalancer
		res[vpcUID].LoadBalancers = append(res[vpcUID].LoadBalancers, loadBalancer)
	}
	return nil
}

// todo - handle this cases and remove this method:
func checkLoadBalancerValidity(loadBalancerObj *datamodel.LoadBalancer) bool {
	// todo - in case of more than two subnets, two subnets are chosen arbitrary
	// we do not know which subnets will be chosen to be in the config file.
	// in such case, the connectivity report is not representing the user configuration.
	if len(loadBalancerObj.Subnets) > 2 {
		fmt.Printf("warning: Ignoring Load Balancer %s, it has more than two subnets\n", *loadBalancerObj.Name)
		return false
	}
	// todo: handle different numbers of private and public ip
	if len(loadBalancerObj.PrivateIps) != 2 {
		fmt.Printf("warning: Ignoring Load Balancer %s, it has %d private IPs (currently only 2 are supported)\n",
			*loadBalancerObj.Name, len(loadBalancerObj.PrivateIps))
		return false
	}
	if len(loadBalancerObj.PublicIps) != 2 && len(loadBalancerObj.PublicIps) != 0 {
		fmt.Printf("warning: Ignoring Load Balancer %s, it has %d private IPs (currently only two or zero are supported)\n",
			*loadBalancerObj.Name, len(loadBalancerObj.PublicIps))
		return false
	}
	return true
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
	for poolIndex := range loadBalancerObj.Pools {
		poolObj := loadBalancerObj.Pools[poolIndex]
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
		// lis.policies = *lisObj.policies
		if pool, ok := pools[*listenerObj.DefaultPool.ID]; ok {
			listener = append(listener, pool)
		}
		listeners = append(listeners, listener)
	}
	return listeners
}

// ///////////////////////////////////////////////////////////
// getLoadBalancerIPs() parse the private Ips (should be one or two)
// create public IPs ase routers of the private IPs
// returns the private IPs nodes
func getLoadBalancerIPs(res map[string]*vpcmodel.VPCConfig,
	loadBalancerObj *datamodel.LoadBalancer,
	vpcUID string, vpc *VPC) ([]vpcmodel.Node, error) {
	privateIPs := []vpcmodel.Node{}
	for _, pIP := range loadBalancerObj.PrivateIps {
		pIPNode := &PrivateIP{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: *pIP.Name,
				ResourceUID:  *pIP.ID,
				ResourceType: ResourceTypePrivateIP,
				Zone:         "",
				VPCRef:       vpc,
			}, // the zone gets updated later
			InternalNode: vpcmodel.InternalNode{
				AddressStr: *pIP.Address,
			},
			loadBalancer: *loadBalancerObj.Name,
		}
		if err := pIPNode.SetIPBlockFromAddress(); err != nil {
			return nil, err
		}
		subnet, err := getSubnetByIPAddress(pIPNode.IPBlock(), res[vpcUID])
		if err != nil {
			return nil, err
		}
		pIPNode.SubnetResource = subnet
		pIPNode.Zone = subnet.ZoneName()
		res[vpcUID].Nodes = append(res[vpcUID].Nodes, pIPNode)
		subnet.nodes = append(subnet.nodes, pIPNode)
		res[vpcUID].UIDToResource[pIPNode.ResourceUID] = pIPNode
		privateIPs = append(privateIPs, pIPNode)
		// todo in case that both private IPs are in the same subnet, do we need add the second?
		if len(loadBalancerObj.Subnets) == 1 {
			break
		}
	}
	// if the load balancer have public Ips, we attach every private ip a floating ip
	for i, publicIPData := range loadBalancerObj.PublicIps {
		privateIP := privateIPs[i]
		routerFip := &FloatingIP{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: "fip-name-of-" + privateIP.Name(),
				ResourceUID:  "fip-uid-of-" + privateIP.UID(),
				Zone:         privateIP.ZoneName(),
				ResourceType: ResourceTypeFloatingIP,
				VPCRef:       vpc,
			},
			cidr: *publicIPData.Address, src: []vpcmodel.Node{privateIP}}
		res[vpcUID].RoutingResources = append(res[vpcUID].RoutingResources, routerFip)
		res[vpcUID].UIDToResource[routerFip.ResourceUID] = routerFip
		if len(loadBalancerObj.Subnets) == 1 {
			break
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
