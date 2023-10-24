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

func addZone(c map[string]*vpcmodel.CloudConfig, zoneName, vpcName string) error {
	vpc, err := getVPCObjectByName(c, vpcName)
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
	res map[string]*vpcmodel.CloudConfig,
	skipByVPC func(string) bool) error {
	for _, instance := range instanceList {
		if skipByVPC(*instance.VPC.CRN) {
			continue
		}
		vpcName := *instance.VPC.Name
		vpc, err := getVPCObjectByName(res, vpcName)
		if err != nil {
			return err
		}
		vsiNode := &Vsi{
			VPCResource: vpcmodel.VPCResource{ResourceName: *instance.Name, ResourceUID: *instance.CRN, Zone: *instance.Zone.Name,
				ResourceType: ResourceTypeVSI},
			nodes: []vpcmodel.Node{},
			vpc:   vpc,
		}

		if err := addZone(res, *instance.Zone.Name, vpcName); err != nil {
			return err
		}
		res[vpcName].NodeSets = append(res[vpcName].NodeSets, vsiNode)
		res[vpcName].NameToResource[vsiNode.Name()] = vsiNode
		for j := range instance.NetworkInterfaces {
			netintf := instance.NetworkInterfaces[j]
			// netintf has no CRN, thus using its ID for ResourceUID
			intfNode := &NetworkInterface{
				VPCResource: vpcmodel.VPCResource{ResourceName: *netintf.Name, ResourceUID: *netintf.ID,
					ResourceType: ResourceTypeNetworkInterface, Zone: *instance.Zone.Name},
				address: *netintf.PrimaryIP.Address, vsi: *instance.Name}
			res[vpcName].Nodes = append(res[vpcName].Nodes, intfNode)
			res[vpcName].NameToResource[intfNode.Name()] = intfNode
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
	res map[string]*vpcmodel.CloudConfig,
	pgwToSubnet map[string][]*Subnet,
	subnetNameToSubnet map[string]*Subnet,
	subnetNameToNetIntf map[string][]*NetworkInterface,
	rc *ResourcesContainer,
	skipByVPC func(string) bool) (vpcInternalAddressRange map[string]*common.IPBlock, err error) {
	vpcInternalAddressRange = map[string]*common.IPBlock{}
	for vpcName := range res {
		vpcInternalAddressRange[vpcName] = nil
	}
	for _, subnet := range rc.subnetsList {
		if skipByVPC(*subnet.VPC.CRN) {
			continue
		}
		subnetNodes := []vpcmodel.Node{}
		vpcName := *subnet.VPC.Name
		vpc, err := getVPCObjectByName(res, vpcName)
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
		if vpcInternalAddressRange[vpcName] == nil {
			vpcInternalAddressRange[vpcName] = cidrIPBlock
		} else {
			vpcInternalAddressRange[vpcName] = vpcInternalAddressRange[vpcName].Union(cidrIPBlock)
		}
		res[vpcName].NodeSets = append(res[vpcName].NodeSets, subnetNode)
		if err := addZone(res, *subnet.Zone.Name, *subnet.VPC.Name); err != nil {
			return nil, err
		}
		res[vpcName].NameToResource[subnetNode.Name()] = subnetNode
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
	res map[string]*vpcmodel.CloudConfig,
	rc *ResourcesContainer,
	pgwToSubnet map[string][]*Subnet,
	skipByVPC func(string) bool) error {
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
		vpcName := *pgw.VPC.Name
		vpc, err := getVPCObjectByName(res, vpcName)
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
		res[vpcName].RoutingResources = append(res[vpcName].RoutingResources, routerPgw)
		res[vpcName].NameToResource[routerPgw.Name()] = routerPgw
		err = addZone(res, *pgw.Zone.Name, *pgw.VPC.Name)
		if err != nil {
			return err
		}
	}
	return nil
}

func getFipConfig(
	rc *ResourcesContainer,
	res map[string]*vpcmodel.CloudConfig,
	skipByVPC func(string) bool,
) error {
	for _, fip := range rc.fipList {
		targetIntf := fip.Target
		var targetAddress string
		switch target := targetIntf.(type) {
		case *vpc1.FloatingIPTargetNetworkInterfaceReference:
			targetAddress = *target.PrimaryIP.Address
		case *vpc1.FloatingIPTarget:
			if *target.ResourceType != networkInterfaceResourceType {
				continue
			}
			targetAddress = *target.PrimaryIP.Address
		default:
			return fmt.Errorf("unsupported fip target : %s", target)
		}

		if targetAddress == "" {
			continue
		}

		var srcNodes []vpcmodel.Node
		var vpcName string
		for name, vpcConfig := range res {
			srcNodes = getCertainNodes(vpcConfig.Nodes, func(n vpcmodel.Node) bool { return n.Cidr() == targetAddress })
			if len(srcNodes) > 0 {
				vpcName = name
				break
			}
		}

		if len(srcNodes) == 0 {
			fmt.Printf("warning: skip fip %s - could not find attached network interface\n", *fip.Name)
			continue // could not find network interface attached to configured fip -- skip that fip
		}

		vpc, err := getVPCObjectByName(res, vpcName)
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
		res[vpcName].RoutingResources = append(res[vpcName].RoutingResources, routerFip)
		res[vpcName].NameToResource[routerFip.Name()] = routerFip

		// node with fip should not have pgw
		for _, r := range res[vpcName].RoutingResources {
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

func getVPCconfig(rc *ResourcesContainer, res map[string]*vpcmodel.CloudConfig, skipByVPC func(string) bool) error {
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
		res[vpcName] = NewEmptyCloudConfig()
		res[vpcName].NodeSets = append(res[vpcName].NodeSets, vpcNodeSet)
		res[vpcName].NameToResource[vpcNodeSet.Name()] = vpcNodeSet
	}
	if len(res) == 0 {
		return errors.New("could not find any VPC to analyze")
	}
	return nil
}

func parseSGTargets(sgResource *SecurityGroup,
	sg *vpc1.SecurityGroup,
	res map[string]*vpcmodel.CloudConfig,
	intfNameToIntf map[string]*NetworkInterface,
	vpcName string) {
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
				if vpe, ok := res[vpcName].NameToResource[targetName]; ok {
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
	res map[string]*vpcmodel.CloudConfig,
	intfNameToIntf map[string]*NetworkInterface,
	skipByVPC func(string) bool) error {
	sgMap := map[string]*SecurityGroup{}
	sgList := map[string][]*SecurityGroup{}
	for vpcName := range res {
		sgList[vpcName] = []*SecurityGroup{}
	}
	for _, sg := range rc.sgList {
		if skipByVPC(*sg.VPC.CRN) {
			continue
		}
		vpcName := *sg.VPC.Name
		vpc, err := getVPCObjectByName(res, vpcName)
		if err != nil {
			return err
		}

		sgResource := &SecurityGroup{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: *sg.Name, ResourceUID: *sg.CRN, ResourceType: ResourceTypeSG},
			analyzer: NewSGAnalyzer(sg), members: map[string]vpcmodel.Node{}, vpc: vpc,
		}
		sgMap[*sg.Name] = sgResource
		parseSGTargets(sgResource, sg, res, intfNameToIntf, vpcName)
		sgList[vpcName] = append(sgList[vpcName], sgResource)
	}
	for vpcName, sgListInstance := range sgList {
		vpc, err := getVPCObjectByName(res, vpcName)
		if err != nil {
			return err
		}
		sgLayer := &SecurityGroupLayer{
			VPCResource: vpcmodel.VPCResource{ResourceType: vpcmodel.SecurityGroupLayer},
			sgList:      sgListInstance, vpc: vpc}
		res[vpcName].FilterResources = append(res[vpcName].FilterResources, sgLayer)
	}

	for _, sg := range sgMap {
		err := sg.analyzer.prepareAnalyzer(sgMap, sg)
		if err != nil {
			return err
		}
	}
	return nil
}

func getNACLconfig(rc *ResourcesContainer,
	res map[string]*vpcmodel.CloudConfig,
	subnetNameToSubnet map[string]*Subnet,
	skipByVPC func(string) bool) error {
	// nacl
	naclList := map[string][]*NACL{} // map from vpc name to its nacls
	for vpcnName := range res {
		naclList[vpcnName] = []*NACL{}
	}
	for _, nacl := range rc.naclList {
		if skipByVPC(*nacl.VPC.CRN) {
			continue
		}
		naclAnalyzer, err := NewNACLAnalyzer(nacl)
		if err != nil {
			return err
		}
		vpcName := *nacl.VPC.Name
		vpc, err := getVPCObjectByName(res, vpcName)
		if err != nil {
			return err
		}

		naclResource := &NACL{
			VPCResource: vpcmodel.VPCResource{ResourceName: *nacl.Name, ResourceUID: *nacl.CRN, ResourceType: ResourceTypeNACL},
			analyzer:    naclAnalyzer, subnets: map[string]*Subnet{}, vpc: vpc}
		naclList[vpcName] = append(naclList[vpcName], naclResource)
		for _, subnetRef := range nacl.Subnets {
			subnetName := *subnetRef.Name
			if subnet, ok := subnetNameToSubnet[subnetName]; ok {
				naclResource.subnets[subnet.cidr] = subnet
			}
		}
	}

	for vpcnName := range res {
		naclLayer := &NaclLayer{
			VPCResource: vpcmodel.VPCResource{ResourceType: vpcmodel.NaclLayer},
			naclList:    naclList[vpcnName]}
		res[vpcnName].FilterResources = append(res[vpcnName].FilterResources, naclLayer)
	}
	return nil
}

func getSubnetByIPAddress(address string, c *vpcmodel.CloudConfig) (subnet *Subnet, err error) {
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
	res map[string]*vpcmodel.CloudConfig,
	skipByVPC func(string) bool) (err error) {
	for _, vpe := range rc.vpeList {
		if skipByVPC(*vpe.VPC.CRN) {
			continue
		}
		vpcName := *vpe.VPC.Name
		vpc, err := getVPCObjectByName(res, vpcName)
		if err != nil {
			return err
		}
		vpeResource := &Vpe{
			VPCResource: vpcmodel.VPCResource{ResourceName: *vpe.Name, ResourceUID: *vpe.CRN, ResourceType: ResourceTypeVPE},
			vpc:         vpc,
		}
		res[vpcName].NodeSets = append(res[vpcName].NodeSets, vpeResource)
		rIPList := vpe.Ips // reserved ips bound to this endpoint gateway
		for _, rIP := range rIPList {
			rIPNode := &ReservedIP{
				VPCResource: vpcmodel.VPCResource{ResourceName: *rIP.Name, ResourceUID: *rIP.ID,
					ResourceType: ResourceTypeReservedIP, Zone: ""}, // the zone gets updated later
				vpe:     *vpe.Name,
				address: *rIP.Address,
			}
			subnet, err := getSubnetByIPAddress(*rIP.Address, res[vpcName])
			if err != nil {
				return err
			}
			rIPNode.subnet = subnet
			rIPNode.Zone = subnet.ZoneName()
			res[vpcName].Nodes = append(res[vpcName].Nodes, rIPNode)
			// TODO: make sure the address is in the subnet's reserved ips list?
			subnet.nodes = append(subnet.nodes, rIPNode)
			res[vpcName].NameToResource[rIPNode.Name()] = rIPNode
			vpeResource.nodes = append(vpeResource.nodes, rIPNode)
		}
		res[vpcName].NameToResource[vpeResource.ResourceName] = vpeResource
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

func getIKSnodesConfig(res map[string]*vpcmodel.CloudConfig,
	subnetNameToSubnet map[string]*Subnet,
	rc *ResourcesContainer,
	skipByVPC func(string) bool) error {
	for _, iksNode := range rc.iksNodes {
		subnet, err := getSubnetByCidr(subnetNameToSubnet, iksNode.Cidr)
		if err != nil {
			return err
		}

		if skipByVPC(subnet.vpc.ResourceUID) {
			continue
		}
		vpcName := subnet.vpc.Name()
		nodeObject := &IKSNode{
			VPCResource: vpcmodel.VPCResource{ResourceName: "iks-node", ResourceUID: iksNode.ID, ResourceType: ResourceTypeIKSNode},
			address:     iksNode.IPAddress,
			subnet:      subnet,
		}
		res[vpcName].Nodes = append(res[vpcName].Nodes, nodeObject)
		// attach the node to the subnet
		subnet.nodes = append(subnet.nodes, nodeObject)
	}
	return nil
}

func NewEmptyCloudConfig() *vpcmodel.CloudConfig {
	return &vpcmodel.CloudConfig{
		Nodes:            []vpcmodel.Node{},
		NodeSets:         []vpcmodel.NodeSet{},
		FilterResources:  []vpcmodel.FilterTrafficResource{},
		RoutingResources: []vpcmodel.RoutingResource{},
		NameToResource:   map[string]vpcmodel.VPCResourceIntf{},
		CloudName:        "IBM Cloud",
	}
}

// CloudConfigsFromResources returns a map from VPC name (string) to its corresponding CloudConfig object,
// containing the parsed resources in the relevant model objects
func CloudConfigsFromResources(rc *ResourcesContainer, vpcID string, debug bool) (map[string]*vpcmodel.CloudConfig, error) {
	res := map[string]*vpcmodel.CloudConfig{}

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

	err = getIKSnodesConfig(res, subnetNameToSubnet, rc, shouldSkipByVPC)
	if err != nil {
		return nil, err
	}

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
		printCloudConfigs(res)
	}

	return res, nil
}

// filter VPCs with empty address ranges, then add for remaining VPCs the external nodes
func filterVPCSAndAddExternalNodes(vpcInternalAddressRange map[string]*common.IPBlock, res map[string]*vpcmodel.CloudConfig) error {
	for vpcName, vpcCloudConfig := range res {
		if vpcInternalAddressRange[vpcName] == nil {
			fmt.Printf("Ignoring VPC %s, no subnets found fot this VPC\n", vpcName)
			delete(res, vpcName)
			continue
		}
		err := handlePublicInternetNodes(vpcCloudConfig, vpcInternalAddressRange[vpcName])
		if err != nil {
			return err
		}
	}
	return nil
}

func updateVPCSAddressRanges(vpcInternalAddressRange map[string]*common.IPBlock, res map[string]*vpcmodel.CloudConfig) error {
	// assign to each vpc object its internal address range, as inferred from its subnets
	for vpcName, addressRange := range vpcInternalAddressRange {
		var vpc *VPC
		vpc, err := getVPCObjectByName(res, vpcName)
		if err != nil {
			return err
		}
		vpc.internalAddressRange = addressRange
	}
	return nil
}

func handlePublicInternetNodes(res *vpcmodel.CloudConfig, vpcInternalAddressRange *common.IPBlock) error {
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

func addExternalNodes(config *vpcmodel.CloudConfig, vpcInternalAddressRange *common.IPBlock) ([]vpcmodel.Node, error) {
	ipBlocks := []*common.IPBlock{}
	for _, f := range config.FilterResources {
		ipBlocks = append(ipBlocks, f.ReferencedIPblocks()...)
	}

	externalRefIPBlocks := []*common.IPBlock{}
	for _, ipBlock := range ipBlocks {
		intersection := ipBlock.Intersection(vpcInternalAddressRange)
		if !intersection.Empty() {
			continue
		}
		externalRefIPBlocks = append(externalRefIPBlocks, ipBlock)
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

func getVPCObjectByName(c map[string]*vpcmodel.CloudConfig, vpcName string) (*VPC, error) {
	missingVPCErr := fmt.Errorf("missing VPC resource of name %s", vpcName)
	config, ok := c[vpcName]
	if !ok {
		return nil, missingVPCErr
	}
	if obj, ok := config.NameToResource[vpcName]; ok {
		if res, ok := obj.(*VPC); ok {
			return res, nil
		}
		return nil, fmt.Errorf("a resource of name %s is not a VPC as expected", vpcName)
	}
	return nil, missingVPCErr
}

func printCloudConfigs(c map[string]*vpcmodel.CloudConfig) {
	printLineSection()
	for vpcName, config := range c {
		fmt.Printf("config for vpc %s\n", vpcName)
		printConfig(config)
	}
	printLineSection()
}

func printLineSection() {
	fmt.Println("-----------------------------------------")
}

func printConfig(c *vpcmodel.CloudConfig) {
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
