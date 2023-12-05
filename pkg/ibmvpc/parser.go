package ibmvpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	vpcmodel "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const (
	protocolTCP                  = "tcp"
	protocolUDP                  = "udp"
	inbound                      = "inbound"
	outbound                     = "outbound"
	networkInterfaceResourceType = "network_interface" // used as the type within api objects (e.g. SecurityGroup.Targets.ResourceType)
	vpeResourceType              = "endpoint_gateway"  // used as the type within api objects (e.g. SecurityGroup.Targets.ResourceType)
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
	ResourceTypeReservedIP       = "ReservedIP"
)

type ResourcesContainer struct {
	naclList     []*vpc1.NetworkACL
	sgList       []*vpc1.SecurityGroup
	instanceList []*vpc1.Instance
	subnetsList  []*vpc1.Subnet
	vpcsList     []*vpc1.VPC
	fipList      []*vpc1.FloatingIP
	pgwList      []*vpc1.PublicGateway
	vpeList      []*vpc1.EndpointGateway
	iksNodes     []*iksNode
}

func NewResourcesContainer() *ResourcesContainer {
	res := &ResourcesContainer{
		naclList:     []*vpc1.NetworkACL{},
		sgList:       []*vpc1.SecurityGroup{},
		instanceList: []*vpc1.Instance{},
		subnetsList:  []*vpc1.Subnet{},
		vpcsList:     []*vpc1.VPC{},
		fipList:      []*vpc1.FloatingIP{},
		pgwList:      []*vpc1.PublicGateway{},
		iksNodes:     []*iksNode{},
	}
	return res
}

func (rc *ResourcesContainer) addNACL(n *vpc1.NetworkACL) {
	rc.naclList = append(rc.naclList, n)
}

func (rc *ResourcesContainer) addSG(n *vpc1.SecurityGroup) {
	rc.sgList = append(rc.sgList, n)
}

func (rc *ResourcesContainer) addInstance(n *vpc1.Instance) {
	rc.instanceList = append(rc.instanceList, n)
}

func (rc *ResourcesContainer) addSubnet(n *vpc1.Subnet) {
	rc.subnetsList = append(rc.subnetsList, n)
}

func (rc *ResourcesContainer) addVpc(n *vpc1.VPC) {
	rc.vpcsList = append(rc.vpcsList, n)
}

func (rc *ResourcesContainer) addFloatingIP(n *vpc1.FloatingIP) {
	rc.fipList = append(rc.fipList, n)
}

func (rc *ResourcesContainer) addPublicGateway(n *vpc1.PublicGateway) {
	rc.pgwList = append(rc.pgwList, n)
}

func (rc *ResourcesContainer) addVPE(n *vpc1.EndpointGateway) {
	rc.vpeList = append(rc.vpeList, n)
}

func (rc *ResourcesContainer) addIKSNode(n *iksNode) {
	rc.iksNodes = append(rc.iksNodes, n)
}

var _ = (*ResourcesContainer).printDetails // avoiding "unused" warning

func (rc *ResourcesContainer) printDetails() {
	fmt.Printf("Has %d nacl objects\n", len(rc.naclList))
	fmt.Printf("Has %d sg objects\n", len(rc.sgList))
	fmt.Printf("Has %d instance objects\n", len(rc.instanceList))
}

func addParsedNACL(vList []json.RawMessage, res *ResourcesContainer) error {
	for i := range vList {
		obj, err := JSONNaclToObject(vList[i])
		if err != nil {
			return err
		}
		res.addNACL(obj)
	}
	return nil
}

func addParsedSG(vList []json.RawMessage, res *ResourcesContainer) error {
	for i := range vList {
		obj, err := JSONSgToObject(vList[i])
		if err != nil {
			return err
		}
		res.addSG(obj)
	}
	return nil
}

func addParsedInstances(vList []json.RawMessage, res *ResourcesContainer) error {
	for i := range vList {
		obj, err := JSONInstanceToObject(vList[i])
		if err != nil {
			return err
		}
		res.addInstance(obj)
	}
	return nil
}

type iksNode struct {
	Cidr      string
	IPAddress string
	SubnetID  string
	ID        string
}

var errIksParsing = errors.New("issue parsing IKS node")

/*
assuming the following components are within input to parseIKSNode:
"networkInterfaces": [
                {
                    "cidr": "cidr-str",
                    "ipAddress": "ip-str",
                    "subnetID": "id-str"
                }
            ],
"id": "id-str",

*/

func parseIKSNode(m map[string]json.RawMessage) (*iksNode, error) {
	// parse the "networkInterfaces" section
	nis, ok := m["networkInterfaces"]
	if !ok {
		return nil, errIksParsing
	}
	netInterfaces, err := JSONToList(nis)
	if err != nil {
		return nil, err
	}
	if len(netInterfaces) != 1 {
		return nil, errIksParsing
	}

	var iksNodes []iksNode
	err = json.Unmarshal(nis, &iksNodes)
	if err != nil {
		return nil, err
	}

	if len(iksNodes) != 1 {
		return nil, errIksParsing
	}
	res := &iksNodes[0]

	// parse the "id" section
	id, ok := m["id"]
	if !ok {
		return nil, errIksParsing
	}
	err = json.Unmarshal(id, &res.ID)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func addParsedWorkerNodes(vList []json.RawMessage, res *ResourcesContainer) error {
	for i := range vList {
		nodesMap, err := JSONToMap(vList[i])
		if err != nil {
			return err
		}
		obj, err := parseIKSNode(nodesMap)
		if err != nil {
			return err
		}
		res.addIKSNode(obj)
	}

	return nil
}

func addParsedSubnets(vList []json.RawMessage, res *ResourcesContainer) error {
	for i := range vList {
		obj, err := JSONSubnetToObject(vList[i])
		if err != nil {
			return err
		}
		res.addSubnet(obj)
	}
	return nil
}

func addParsedVPCs(vList []json.RawMessage, res *ResourcesContainer) error {
	for i := range vList {
		obj, err := JSONVpcToObject(vList[i])
		if err != nil {
			return err
		}
		res.addVpc(obj)
	}
	return nil
}

func addParsedFips(vList []json.RawMessage, res *ResourcesContainer) error {
	for i := range vList {
		obj, err := JSONFipToObject(vList[i])
		if err != nil {
			return err
		}
		res.addFloatingIP(obj)
	}
	return nil
}

func addParsedPgw(vList []json.RawMessage, res *ResourcesContainer) error {
	for i := range vList {
		obj, err := JSONPgwTpObject(vList[i])
		if err != nil {
			return err
		}
		res.addPublicGateway(obj)
	}
	return nil
}

func addParsedVPE(vList []json.RawMessage, res *ResourcesContainer) error {
	for i := range vList {
		obj, err := JSONVpeToObject(vList[i])
		if err != nil {
			return err
		}
		res.addVPE(obj)
	}
	return nil
}

func parseSingleResourceList(key string, vList []json.RawMessage, res *ResourcesContainer) error {
	switch key {
	case "network_acls":
		return addParsedNACL(vList, res)
	case "security_groups":
		return addParsedSG(vList, res)
	case "instances":
		return addParsedInstances(vList, res)
	case "subnets":
		return addParsedSubnets(vList, res)
	case "vpcs":
		return addParsedVPCs(vList, res)
	case "floating_ips":
		return addParsedFips(vList, res)
	case "public_gateways":
		return addParsedPgw(vList, res)
	case "endpoint_gateways":
		return addParsedVPE(vList, res)
	case "iks_worker_nodes":
		return addParsedWorkerNodes(vList, res)
	default:
		fmt.Printf("%s resource type is not yet supported\n", key)
	}
	return nil
}

func ParseResourcesFromFile(fileName string) (*ResourcesContainer, error) {
	jsonContent, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return ParseResources(jsonContent)
}

func ParseResources(resourcesJSONFile []byte) (*ResourcesContainer, error) {
	var err error
	res := NewResourcesContainer()
	resourcesMap, err := JSONToMap(resourcesJSONFile)
	if err != nil {
		return nil, err
	}
	for k, v := range resourcesMap {
		vList, err := JSONToList(v)
		if err != nil {
			return nil, err
		}
		if err := parseSingleResourceList(k, vList, res); err != nil {
			return nil, err
		}
	}
	return res, nil
}

func getCertainNodes(allNodes []vpcmodel.Node, shouldTakeNode func(vpcmodel.Node) bool) (ret []vpcmodel.Node) {
	for _, s := range allNodes {
		if shouldTakeNode(s) {
			ret = append(ret, s)
		}
	}
	return
}

func addZone(zoneName, vpcUID string, res map[string]*vpcmodel.VPCConfig) error {
	vpc, err := getVPCObjectByUID(res, vpcUID)
	if err != nil {
		return err
	}
	if _, ok := vpc.zones[zoneName]; !ok {
		vpc.zones[zoneName] = &Zone{name: zoneName, vpc: vpc}
	}
	return nil
}

func getInstancesConfig(
	instanceList []*vpc1.Instance,
	subnetNameToNetIntf map[string][]*NetworkInterface,
	intfNameToIntf map[string]*NetworkInterface,
	res map[string]*vpcmodel.VPCConfig,
	skipByVPC func(string) bool,
) error {
	for _, instance := range instanceList {
		vpcUID := *instance.VPC.CRN
		if skipByVPC(vpcUID) {
			continue
		}
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		vsiNode := &Vsi{
			VPCResource: vpcmodel.VPCResource{ResourceName: *instance.Name, ResourceUID: *instance.CRN, Zone: *instance.Zone.Name,
				ResourceType: ResourceTypeVSI},
			nodes: []vpcmodel.Node{},
			vpc:   vpc,
		}

		if err := addZone(*instance.Zone.Name, vpcUID, res); err != nil {
			return err
		}
		res[vpcUID].NodeSets = append(res[vpcUID].NodeSets, vsiNode)
		res[vpcUID].NameToResource[vsiNode.Name()] = vsiNode
		for j := range instance.NetworkInterfaces {
			netintf := instance.NetworkInterfaces[j]
			// netintf has no CRN, thus using its PrimaryIP's ID for ResourceUID
			intfNode := &NetworkInterface{
				VPCResource: vpcmodel.VPCResource{ResourceName: *netintf.Name, ResourceUID: *netintf.PrimaryIP.ID,
					ResourceType: ResourceTypeNetworkInterface, Zone: *instance.Zone.Name},
				address: *netintf.PrimaryIP.Address, vsi: *instance.Name}
			res[vpcUID].Nodes = append(res[vpcUID].Nodes, intfNode)
			res[vpcUID].NameToResource[intfNode.Name()] = intfNode
			vsiNode.nodes = append(vsiNode.nodes, intfNode)
			intfNameToIntf[*netintf.Name] = intfNode
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
	res map[string]*vpcmodel.VPCConfig,
	pgwToSubnet map[string][]*Subnet,
	subnetNameToSubnet map[string]*Subnet,
	subnetNameToNetIntf map[string][]*NetworkInterface,
	rc *ResourcesContainer,
	skipByVPC func(string) bool,
) (vpcInternalAddressRange map[string]*common.IPBlock, err error) {
	vpcInternalAddressRange = map[string]*common.IPBlock{}
	for vpcUID := range res {
		vpcInternalAddressRange[vpcUID] = nil
	}
	for _, subnet := range rc.subnetsList {
		if skipByVPC(*subnet.VPC.CRN) {
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
				ResourceType: ResourceTypeSubnet},
			cidr: *subnet.Ipv4CIDRBlock,
			vpc:  vpc,
		}

		cidrIPBlock := common.NewIPBlockFromCidr(subnetNode.cidr)
		if vpcInternalAddressRange[vpcUID] == nil {
			vpcInternalAddressRange[vpcUID] = cidrIPBlock
		} else {
			vpcInternalAddressRange[vpcUID] = vpcInternalAddressRange[vpcUID].Union(cidrIPBlock)
		}
		res[vpcUID].NodeSets = append(res[vpcUID].NodeSets, subnetNode)
		if err := addZone(*subnet.Zone.Name, vpcUID, res); err != nil {
			return nil, err
		}
		res[vpcUID].NameToResource[subnetNode.Name()] = subnetNode
		subnetNameToSubnet[*subnet.Name] = subnetNode
		if subnet.PublicGateway != nil {
			if _, ok := pgwToSubnet[*subnet.PublicGateway.Name]; !ok {
				pgwToSubnet[*subnet.PublicGateway.Name] = []*Subnet{}
			}
			pgwToSubnet[*subnet.PublicGateway.Name] = append(pgwToSubnet[*subnet.PublicGateway.Name], subnetNode)
		}
		// add pointers from networkInterface to its subnet, given the current subnet created
		if subnetInterfaces, ok := subnetNameToNetIntf[*subnet.Name]; ok {
			for _, netIntf := range subnetInterfaces {
				netIntf.subnet = subnetNode
				subnetNodes = append(subnetNodes, netIntf)
			}
			subnetNode.nodes = subnetNodes
		}
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
	res map[string]*vpcmodel.VPCConfig,
	rc *ResourcesContainer,
	pgwToSubnet map[string][]*Subnet,
	skipByVPC func(string) bool,
) error {
	for _, pgw := range rc.pgwList {
		if skipByVPC(*pgw.VPC.CRN) {
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
			},
			cidr:       "",
			src:        srcNodes,
			subnetCidr: getSubnetsCidrs(pgwToSubnet[pgwName]),
			vpc:        vpc,
		} // TODO: get cidr from fip of the pgw
		res[vpcUID].RoutingResources = append(res[vpcUID].RoutingResources, routerPgw)
		res[vpcUID].NameToResource[routerPgw.Name()] = routerPgw
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

func getFipConfig(
	rc *ResourcesContainer,
	res map[string]*vpcmodel.VPCConfig,
	skipByVPC func(string) bool,
) error {
	for _, fip := range rc.fipList {
		targetIntf := fip.Target
		var targetUID string
		switch target := targetIntf.(type) {
		case *vpc1.FloatingIPTargetNetworkInterfaceReference:
			targetUID = *target.PrimaryIP.ID
		case *vpc1.FloatingIPTarget:
			if *target.ResourceType != networkInterfaceResourceType {
				fmt.Println(ignoreFIPWarning(*fip.Name,
					fmt.Sprintf("target.ResourceType %s is not supported (only networkInterfaceResourceType supported)",
						*target.ResourceType)))
				continue
			}
			targetUID = *target.PrimaryIP.ID
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
			fmt.Printf("warning: skip fip %s - could not find attached network interface\n", *fip.Name)
			continue // could not find network interface attached to configured fip -- skip that fip
		}

		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		if skipByVPC(vpc.ResourceUID) {
			continue // skip fip because of selected vpc to analyze
		}

		routerFip := &FloatingIP{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: *fip.Name,
				ResourceUID:  *fip.CRN,
				Zone:         *fip.Zone.Name,
				ResourceType: ResourceTypeFloatingIP},
			cidr: *fip.Address, src: srcNodes}
		res[vpcUID].RoutingResources = append(res[vpcUID].RoutingResources, routerFip)
		res[vpcUID].NameToResource[routerFip.Name()] = routerFip

		// node with fip should not have pgw
		for _, r := range res[vpcUID].RoutingResources {
			if pgw, ok := r.(*PublicGateway); ok {
				// a node captured by a fip should not be captured by a pgw
				for _, nodeWithFip := range srcNodes {
					if vpcmodel.HasNode(pgw.Src(), nodeWithFip) {
						pgw.src = getCertainNodes(pgw.Src(), func(n vpcmodel.Node) bool { return n.Cidr() != nodeWithFip.Cidr() })
					}
				}
			}
		}
	}
	return nil
}

func getVPCconfig(rc *ResourcesContainer, res map[string]*vpcmodel.VPCConfig, skipByVPC func(string) bool) error {
	for _, vpc := range rc.vpcsList {
		if skipByVPC(*vpc.CRN) {
			continue // skip vpc not specified to analyze
		}
		vpcName := *vpc.Name
		vpcNodeSet := &VPC{
			VPCResource: vpcmodel.VPCResource{ResourceName: vpcName, ResourceUID: *vpc.CRN, ResourceType: ResourceTypeVPC},
			nodes:       []vpcmodel.Node{},
			zones:       map[string]*Zone{},
		}
		newVPCConfig := NewEmptyVPCConfig()
		newVPCConfig.NodeSets = []vpcmodel.NodeSet{vpcNodeSet}
		newVPCConfig.NameToResource[vpcNodeSet.Name()] = vpcNodeSet
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
	c *vpcmodel.VPCConfig,
	intfNameToIntf map[string]*NetworkInterface) {
	targets := sg.Targets // *SecurityGroupTargetReference
	// type SecurityGroupTargetReference struct
	for _, target := range targets {
		if targetIntfRef, ok := target.(*vpc1.SecurityGroupTargetReference); ok {
			// get from target name + resource type -> find the address of the target
			targetType := *targetIntfRef.ResourceType
			targetName := *targetIntfRef.Name
			if targetType == networkInterfaceResourceType {
				if intfNode, ok := intfNameToIntf[targetName]; ok {
					sgResource.members[intfNode.address] = intfNode
				}
			} else if targetType == vpeResourceType {
				if vpe, ok := c.NameToResource[targetName]; ok {
					vpeObj := vpe.(*Vpe)
					for _, n := range vpeObj.nodes {
						nIP := n.(*ReservedIP)
						sgResource.members[nIP.address] = n
					}
				}
			}
		}
	}
}

func getSGconfig(rc *ResourcesContainer,
	res map[string]*vpcmodel.VPCConfig,
	intfNameToIntf map[string]*NetworkInterface,
	skipByVPC func(string) bool,
) error {
	sgMap := map[string]map[string]*SecurityGroup{} // map from vpc uid to map from sg name to its sg object
	sgLists := map[string][]*SecurityGroup{}
	for _, sg := range rc.sgList {
		if skipByVPC(*sg.VPC.CRN) {
			continue
		}
		vpcUID := *sg.VPC.CRN
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}

		sgResource := &SecurityGroup{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: *sg.Name, ResourceUID: *sg.CRN, ResourceType: ResourceTypeSG},
			analyzer: NewSGAnalyzer(sg), members: map[string]vpcmodel.Node{}, vpc: vpc,
		}
		if _, ok := sgMap[vpcUID]; !ok {
			sgMap[vpcUID] = map[string]*SecurityGroup{}
		}
		sgMap[vpcUID][*sg.Name] = sgResource
		parseSGTargets(sgResource, sg, res[vpcUID], intfNameToIntf)
		sgLists[vpcUID] = append(sgLists[vpcUID], sgResource)
	}
	for vpcUID, sgListInstance := range sgLists {
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		sgLayer := &SecurityGroupLayer{
			VPCResource: vpcmodel.VPCResource{ResourceType: vpcmodel.SecurityGroupLayer},
			sgList:      sgListInstance, vpc: vpc}
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

func getNACLconfig(rc *ResourcesContainer,
	res map[string]*vpcmodel.VPCConfig,
	subnetNameToSubnet map[string]*Subnet,
	skipByVPC func(string) bool,
) error {
	naclLists := map[string][]*NACL{} // map from vpc uid to its nacls
	for _, nacl := range rc.naclList {
		if skipByVPC(*nacl.VPC.CRN) {
			continue
		}
		naclAnalyzer, err := NewNACLAnalyzer(nacl)
		if err != nil {
			return err
		}
		vpcUID := *nacl.VPC.CRN
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}

		naclResource := &NACL{
			VPCResource: vpcmodel.VPCResource{ResourceName: *nacl.Name, ResourceUID: *nacl.CRN, ResourceType: ResourceTypeNACL},
			analyzer:    naclAnalyzer, subnets: map[string]*Subnet{}, vpc: vpc}
		naclLists[vpcUID] = append(naclLists[vpcUID], naclResource)
		for _, subnetRef := range nacl.Subnets {
			subnetName := *subnetRef.Name
			if subnet, ok := subnetNameToSubnet[subnetName]; ok {
				naclResource.subnets[subnet.cidr] = subnet
			}
		}
	}

	for vpcUID := range res {
		naclLayer := &NaclLayer{
			VPCResource: vpcmodel.VPCResource{ResourceType: vpcmodel.NaclLayer},
			naclList:    naclLists[vpcUID]}
		res[vpcUID].FilterResources = append(res[vpcUID].FilterResources, naclLayer)
	}
	return nil
}

func getSubnetByIPAddress(address string, c *vpcmodel.VPCConfig) (subnet *Subnet, err error) {
	addressIPblock := common.NewIPBlockFromCidrOrAddress(address)
	for _, s := range c.NodeSets {
		if s.Kind() == ResourceTypeSubnet {
			subnetRange := s.AddressRange()
			if addressIPblock.ContainedIn(subnetRange) {
				return s.(*Subnet), nil
			}
		}
	}
	return nil, fmt.Errorf("could not find matching subnet for address %s", address)
}

func getVPEconfig(rc *ResourcesContainer,
	res map[string]*vpcmodel.VPCConfig,
	skipByVPC func(string) bool,
) (err error) {
	for _, vpe := range rc.vpeList {
		if skipByVPC(*vpe.VPC.CRN) {
			continue
		}
		vpcUID := *vpe.VPC.CRN
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		vpeResource := &Vpe{
			VPCResource: vpcmodel.VPCResource{ResourceName: *vpe.Name, ResourceUID: *vpe.CRN, ResourceType: ResourceTypeVPE},
			vpc:         vpc,
		}
		res[vpcUID].NodeSets = append(res[vpcUID].NodeSets, vpeResource)
		rIPList := vpe.Ips // reserved ips bound to this endpoint gateway
		for _, rIP := range rIPList {
			rIPNode := &ReservedIP{
				VPCResource: vpcmodel.VPCResource{ResourceName: *rIP.Name, ResourceUID: *rIP.ID,
					ResourceType: ResourceTypeReservedIP, Zone: ""}, // the zone gets updated later
				vpe:     *vpe.Name,
				address: *rIP.Address,
			}
			subnet, err := getSubnetByIPAddress(*rIP.Address, res[vpcUID])
			if err != nil {
				return err
			}
			rIPNode.subnet = subnet
			rIPNode.Zone = subnet.ZoneName()
			res[vpcUID].Nodes = append(res[vpcUID].Nodes, rIPNode)
			// TODO: make sure the address is in the subnet's reserved ips list?
			subnet.nodes = append(subnet.nodes, rIPNode)
			res[vpcUID].NameToResource[rIPNode.Name()] = rIPNode
			vpeResource.nodes = append(vpeResource.nodes, rIPNode)
		}
		res[vpcUID].NameToResource[vpeResource.ResourceName] = vpeResource
		// TODO: verify that vpe.SecurityGroups contain the reserved-ips as members? (not at this stage)
		// sgList := vpe.SecurityGroups
	}
	return nil
}

func getSubnetByCidr(m map[string]*Subnet, cidr string) (*Subnet, error) {
	for _, subnet := range m {
		if subnet.cidr == cidr {
			return subnet, nil
		}
	}
	return nil, fmt.Errorf("could not find subnet with cidr: %s", cidr)
}

func getIKSnodesConfig(res map[string]*vpcmodel.VPCConfig,
	subnetNameToSubnet map[string]*Subnet,
	rc *ResourcesContainer,
	skipByVPC func(string) bool) {
	for _, iksNode := range rc.iksNodes {
		subnet, err := getSubnetByCidr(subnetNameToSubnet, iksNode.Cidr)
		if err != nil {
			fmt.Printf("warning: ignoring iksNode with ID %s\n", iksNode.ID)
			continue
		}
		if skipByVPC(subnet.vpc.ResourceUID) {
			continue
		}
		vpcUID := subnet.vpc.ResourceUID
		nodeObject := &IKSNode{
			VPCResource: vpcmodel.VPCResource{ResourceName: "iks-node", ResourceUID: iksNode.ID, ResourceType: ResourceTypeIKSNode},
			address:     iksNode.IPAddress,
			subnet:      subnet,
		}
		res[vpcUID].Nodes = append(res[vpcUID].Nodes, nodeObject)
		// attach the node to the subnet
		subnet.nodes = append(subnet.nodes, nodeObject)
	}
}

func NewEmptyVPCConfig() *vpcmodel.VPCConfig {
	return &vpcmodel.VPCConfig{
		Nodes:            []vpcmodel.Node{},
		NodeSets:         []vpcmodel.NodeSet{},
		FilterResources:  []vpcmodel.FilterTrafficResource{},
		RoutingResources: []vpcmodel.RoutingResource{},
		NameToResource:   map[string]vpcmodel.VPCResourceIntf{},
		CloudName:        "IBM Cloud",
	}
}

// VPCConfigsFromResources returns a map from VPC UID (string) to its corresponding VPCConfig object,
// containing the parsed resources in the relevant model objects
func VPCConfigsFromResources(rc *ResourcesContainer, vpcID string, debug bool) (map[string]*vpcmodel.VPCConfig, error) {
	res := map[string]*vpcmodel.VPCConfig{} // map from VPC UID to its config
	var err error

	// if certain VPC to analyze is specified, skip resources configured outside that VPC
	var shouldSkipByVPC = func(crn string) bool {
		return vpcID != "" && crn != vpcID
	}

	err = getVPCconfig(rc, res, shouldSkipByVPC)
	if err != nil {
		return nil, err
	}

	var vpcInternalAddressRange map[string]*common.IPBlock // map from vpc name to its internal address range

	subnetNameToNetIntf := map[string][]*NetworkInterface{}
	intfNameToIntf := map[string]*NetworkInterface{}
	err = getInstancesConfig(rc.instanceList, subnetNameToNetIntf, intfNameToIntf, res, shouldSkipByVPC)
	if err != nil {
		return nil, err
	}
	// pgw can be attached to multiple subnets in the zone
	pgwToSubnet := map[string][]*Subnet{} // map from pgw name to its attached subnet(s)
	subnetNameToSubnet := map[string]*Subnet{}
	vpcInternalAddressRange, err = getSubnetsConfig(res, pgwToSubnet, subnetNameToSubnet, subnetNameToNetIntf, rc, shouldSkipByVPC)
	if err != nil {
		return nil, err
	}
	// assign to each vpc object its internal address range, as inferred from its subnets
	err = updateVPCSAddressRanges(vpcInternalAddressRange, res)
	if err != nil {
		return nil, err
	}

	getIKSnodesConfig(res, subnetNameToSubnet, rc, shouldSkipByVPC)

	err = getPgwConfig(res, rc, pgwToSubnet, shouldSkipByVPC)
	if err != nil {
		return nil, err
	}

	err = getFipConfig(rc, res, shouldSkipByVPC)
	if err != nil {
		return nil, err
	}

	err = getVPEconfig(rc, res, shouldSkipByVPC)
	if err != nil {
		return nil, err
	}

	err = getSGconfig(rc, res, intfNameToIntf, shouldSkipByVPC)
	if err != nil {
		return nil, err
	}

	err = getNACLconfig(rc, res, subnetNameToSubnet, shouldSkipByVPC)
	if err != nil {
		return nil, err
	}

	err = filterVPCSAndAddExternalNodes(vpcInternalAddressRange, res)
	if err != nil {
		return nil, err
	}

	if debug {
		printVPCConfigs(res)
	}

	return res, nil
}

// filter VPCs with empty address ranges, then add for remaining VPCs the external nodes
func filterVPCSAndAddExternalNodes(vpcInternalAddressRange map[string]*common.IPBlock, res map[string]*vpcmodel.VPCConfig) error {
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

func updateVPCSAddressRanges(vpcInternalAddressRange map[string]*common.IPBlock,
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

func handlePublicInternetNodes(res *vpcmodel.VPCConfig, vpcInternalAddressRange *common.IPBlock) error {
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

func addExternalNodes(config *vpcmodel.VPCConfig, vpcInternalAddressRange *common.IPBlock) ([]vpcmodel.Node, error) {
	ipBlocks := []*common.IPBlock{}
	for _, f := range config.FilterResources {
		ipBlocks = append(ipBlocks, f.ReferencedIPblocks()...)
	}

	externalRefIPBlocks := []*common.IPBlock{}
	for _, ipBlock := range ipBlocks {
		if ipBlock.ContainedIn(vpcInternalAddressRange) {
			continue
		}
		externalRefIPBlocks = append(externalRefIPBlocks, ipBlock.Subtract(vpcInternalAddressRange))
	}

	disjointRefExternalIPBlocks := common.DisjointIPBlocks(externalRefIPBlocks, []*common.IPBlock{})

	externalNodes, err := vpcmodel.GetExternalNetworkNodes(disjointRefExternalIPBlocks)
	if err != nil {
		return nil, err
	}
	config.Nodes = append(config.Nodes, externalNodes...)
	for _, n := range externalNodes {
		config.NameToResource[n.Name()] = n
	}
	return externalNodes, nil
}

func getVPCObjectByUID(res map[string]*vpcmodel.VPCConfig, uid string) (*VPC, error) {
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

/********** Functions used in Debug mode ***************/

func printVPCConfigs(c map[string]*vpcmodel.VPCConfig) {
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
		fmt.Println(strings.Join([]string{n.Kind(), n.Cidr(), n.Name(), n.UID()}, separator))
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
				fmt.Println(strings.Join([]string{nacl.ResourceType, nacl.ResourceName, nacl.UID()}, separator))
			}
		case *SecurityGroupLayer:
			for _, sg := range filters.sgList {
				fmt.Println(strings.Join([]string{sg.ResourceType, sg.ResourceName, sg.UID()}, separator))
			}
		}
	}
	fmt.Println("RoutingResources:")
	for _, r := range c.RoutingResources {
		fmt.Println(strings.Join([]string{r.Kind(), r.Name(), r.UID()}, separator))
	}
}
