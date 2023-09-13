package ibmvpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	vpcmodel "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const (
	protocolTCP                  = "tcp"
	protocolUDP                  = "udp"
	inbound                      = "inbound"
	outbound                     = "outbound"
	networkInterfaceResourceType = "network_interface"
	cidrSeparator                = ", "
	linesSeparator               = "---------------------"
)

type ResourcesContainer struct {
	naclList     []*vpc1.NetworkACL
	sgList       []*vpc1.SecurityGroup
	instanceList []*vpc1.Instance
	subnetsList  []*vpc1.Subnet
	vpcsList     []*vpc1.VPC
	fipList      []*vpc1.FloatingIP
	pgwList      []*vpc1.PublicGateway
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
		fmt.Println("warning: ignoring endpoint_gateways, TODO: add support")
	case "iks_worker_nodes":
		return addParsedWorkerNodes(vList, res)
	default:
		fmt.Printf("%s resource type is not yet supported\n", key)
	}
	return nil
}

func ParseResourrcesFromFile(fileName string) (*ResourcesContainer, error) {
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

func addZone(c *vpcmodel.CloudConfig, zoneName, vpcName string) error {
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
	res *vpcmodel.CloudConfig) error {
	for i := range instanceList {
		instance := instanceList[i]
		vpc, err := getVPCObjectByName(res, *instance.VPC.Name)
		if err != nil {
			return err
		}
		vsiNode := &Vsi{
			VPCResource: vpcmodel.VPCResource{ResourceName: *instance.Name, ResourceUID: *instance.CRN, Zone: *instance.Zone.Name},
			nodes:       []vpcmodel.Node{},
			vpc:         vpc,
		}
		if err := addZone(res, *instance.Zone.Name, *instance.VPC.Name); err != nil {
			return err
		}
		res.NodeSets = append(res.NodeSets, vsiNode)
		res.NameToResource[vsiNode.Name()] = vsiNode
		for j := range instance.NetworkInterfaces {
			netintf := instance.NetworkInterfaces[j]
			// TODO: ResourceUID as CRN or ID ???
			intfNode := &NetworkInterface{
				VPCResource: vpcmodel.VPCResource{ResourceName: *netintf.Name, ResourceUID: *netintf.ID},
				address:     *netintf.PrimaryIP.Address, vsi: *instance.Name}
			res.Nodes = append(res.Nodes, intfNode)
			res.NameToResource[intfNode.Name()] = intfNode
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
	res *vpcmodel.CloudConfig,
	pgwToSubnet map[string][]*Subnet,
	subnetNameToSubnet map[string]*Subnet,
	subnetNameToNetIntf map[string][]*NetworkInterface,
	rc *ResourcesContainer) (vpcInternalAddressRange *common.IPBlock, err error) {
	for i := range rc.subnetsList {
		subnet := rc.subnetsList[i]
		subnetNodes := []vpcmodel.Node{}
		vpc, err := getVPCObjectByName(res, *subnet.VPC.Name)
		if err != nil {
			return nil, err
		}
		subnetNode := &Subnet{
			VPCResource: vpcmodel.VPCResource{ResourceName: *subnet.Name, ResourceUID: *subnet.CRN, Zone: *subnet.Zone.Name},
			cidr:        *subnet.Ipv4CIDRBlock, vpc: vpc}
		cidrIPBlock := common.NewIPBlockFromCidr(subnetNode.cidr)
		if vpcInternalAddressRange == nil {
			vpcInternalAddressRange = cidrIPBlock
		} else {
			vpcInternalAddressRange = vpcInternalAddressRange.Union(cidrIPBlock)
		}
		res.NodeSets = append(res.NodeSets, subnetNode)
		if err := addZone(res, *subnet.Zone.Name, *subnet.VPC.Name); err != nil {
			return nil, err
		}
		res.NameToResource[subnetNode.Name()] = subnetNode
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
	res *vpcmodel.CloudConfig,
	rc *ResourcesContainer,
	pgwToSubnet map[string][]*Subnet) error {
	for i := range rc.pgwList {
		pgw := rc.pgwList[i]
		pgwName := *pgw.Name
		if _, ok := pgwToSubnet[pgwName]; !ok {
			fmt.Printf("warning: public gateway %s does not have any attached subnet, ignoring this pgw\n", pgwName)
			continue
		}
		srcNodes := getSubnetsNodes(pgwToSubnet[pgwName])
		vpc, err := getVPCObjectByName(res, *pgw.VPC.Name)
		if err != nil {
			return err
		}
		routerPgw := &PublicGateway{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: *pgw.Name,
				ResourceUID:  *pgw.CRN,
				Zone:         *pgw.Zone.Name,
			},
			cidr:       "",
			src:        srcNodes,
			subnetCidr: getSubnetsCidrs(pgwToSubnet[pgwName]),
			vpc:        vpc,
		} // TODO: get cidr from fip of the pgw
		res.RoutingResources = append(res.RoutingResources, routerPgw)
		res.NameToResource[routerPgw.Name()] = routerPgw
		err = addZone(res, *pgw.Zone.Name, *pgw.VPC.Name)
		if err != nil {
			return err
		}
	}
	return nil
}

func getFipConfig(
	rc *ResourcesContainer,
	res *vpcmodel.CloudConfig,
) error {
	for i := range rc.fipList {
		fip := rc.fipList[i]
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
		if targetAddress != "" {
			srcNodes := getCertainNodes(res.Nodes, func(n vpcmodel.Node) bool { return n.Cidr() == targetAddress })
			routerFip := &FloatingIP{
				VPCResource: vpcmodel.VPCResource{ResourceName: *fip.Name, ResourceUID: *fip.CRN, Zone: *fip.Zone.Name},
				cidr:        *fip.Address, src: srcNodes}
			res.RoutingResources = append(res.RoutingResources, routerFip)
			res.NameToResource[routerFip.Name()] = routerFip

			// node with fip should not have pgw
			for _, r := range res.RoutingResources {
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
	}
	return nil
}

func getVPCconfig(rc *ResourcesContainer, res *vpcmodel.CloudConfig) {
	for i := range rc.vpcsList {
		vpc := rc.vpcsList[i]
		vpcNodeSet := &VPC{
			VPCResource: vpcmodel.VPCResource{ResourceName: *vpc.Name, ResourceUID: *vpc.CRN},
			nodes:       []vpcmodel.Node{},
			zones:       map[string]*Zone{},
		}
		res.NodeSets = append(res.NodeSets, vpcNodeSet)
		res.NameToResource[vpcNodeSet.Name()] = vpcNodeSet
	}
}

func singleVPCErr() error {
	return errors.New("expecting single vpc")
}

func getSGconfig(rc *ResourcesContainer, res *vpcmodel.CloudConfig, intfNameToIntf map[string]*NetworkInterface) error {
	sgMap := map[string]*SecurityGroup{}
	sgList := []*SecurityGroup{}
	var layerVPC *VPC
	for i := range rc.sgList {
		sg := rc.sgList[i]

		vpc, err := getVPCObjectByName(res, *sg.VPC.Name)
		if err != nil {
			return err
		}
		if layerVPC == nil {
			layerVPC = vpc
		} else if layerVPC.Name() != vpc.Name() {
			return singleVPCErr()
		}

		sgResource := &SecurityGroup{VPCResource: vpcmodel.VPCResource{ResourceName: *sg.Name, ResourceUID: *sg.CRN},
			analyzer: NewSGAnalyzer(sg), members: map[string]*NetworkInterface{}, vpc: vpc,
		}

		sgMap[*sg.Name] = sgResource
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
				}
			}
		}
		sgList = append(sgList, sgResource)
	}
	sgLayer := &SecurityGroupLayer{sgList: sgList, vpc: layerVPC}
	res.FilterResources = append(res.FilterResources, sgLayer)
	for _, sg := range sgMap {
		err := sg.analyzer.prepareAnalyzer(sgMap, sg)
		if err != nil {
			return err
		}
	}
	return nil
}

func getNACLconfig(rc *ResourcesContainer, res *vpcmodel.CloudConfig, subnetNameToSubnet map[string]*Subnet) error {
	// nacl
	naclList := []*NACL{}
	var layerVPC *VPC
	for i := range rc.naclList {
		nacl := rc.naclList[i]
		naclAnalyzer, err := NewNACLAnalyzer(nacl)
		if err != nil {
			return err
		}
		vpc, err := getVPCObjectByName(res, *nacl.VPC.Name)
		if err != nil {
			return err
		}
		if layerVPC == nil {
			layerVPC = vpc
		} else if layerVPC.Name() != vpc.Name() {
			return singleVPCErr()
		}
		naclResource := &NACL{
			VPCResource: vpcmodel.VPCResource{ResourceName: *nacl.Name, ResourceUID: *nacl.CRN},
			analyzer:    naclAnalyzer, subnets: map[string]*Subnet{}, vpc: vpc}
		naclList = append(naclList, naclResource)
		for _, subnetRef := range nacl.Subnets {
			subnetName := *subnetRef.Name
			if subnet, ok := subnetNameToSubnet[subnetName]; ok {
				naclResource.subnets[subnet.cidr] = subnet
			}
		}
	}
	naclLayer := &NaclLayer{naclList: naclList}
	res.FilterResources = append(res.FilterResources, naclLayer)
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

func getIKSnodesConfig(res *vpcmodel.CloudConfig, subnetNameToSubnet map[string]*Subnet, rc *ResourcesContainer) error {
	for _, iksNode := range rc.iksNodes {
		subnet, err := getSubnetByCidr(subnetNameToSubnet, iksNode.Cidr)
		if err != nil {
			return err
		}

		nodeObject := &IKSNode{
			VPCResource: vpcmodel.VPCResource{ResourceName: "iks-node", ResourceUID: iksNode.ID},
			address:     iksNode.IPAddress,
			subnet:      subnet,
		}
		res.Nodes = append(res.Nodes, nodeObject)
		// attach the node to the subnet
		subnet.nodes = append(subnet.nodes, nodeObject)
	}
	return nil
}

func NewCloudConfig(rc *ResourcesContainer) (*vpcmodel.CloudConfig, error) {
	res := &vpcmodel.CloudConfig{
		Nodes:            []vpcmodel.Node{},
		NodeSets:         []vpcmodel.NodeSet{},
		FilterResources:  []vpcmodel.FilterTrafficResource{},
		RoutingResources: []vpcmodel.RoutingResource{},
		NameToResource:   map[string]vpcmodel.VPCResourceIntf{},
	}

	var err error

	getVPCconfig(rc, res)

	var vpcInternalAddressRange *common.IPBlock

	subnetNameToNetIntf := map[string][]*NetworkInterface{}
	intfNameToIntf := map[string]*NetworkInterface{}
	err = getInstancesConfig(rc.instanceList, subnetNameToNetIntf, intfNameToIntf, res)
	if err != nil {
		return nil, err
	}
	// pgw can be attached to multiple subnets in the zone
	pgwToSubnet := map[string][]*Subnet{} // map from pgw name to its attached subnet(s)
	subnetNameToSubnet := map[string]*Subnet{}
	vpcInternalAddressRange, err = getSubnetsConfig(res, pgwToSubnet, subnetNameToSubnet, subnetNameToNetIntf, rc)
	if err != nil {
		return nil, err
	}

	err = getIKSnodesConfig(res, subnetNameToSubnet, rc)
	if err != nil {
		return nil, err
	}

	err = getPgwConfig(res, rc, pgwToSubnet)
	if err != nil {
		return nil, err
	}

	err = getFipConfig(rc, res)
	if err != nil {
		return nil, err
	}

	err = getSGconfig(rc, res, intfNameToIntf)
	if err != nil {
		return nil, err
	}

	err = getNACLconfig(rc, res, subnetNameToSubnet)
	if err != nil {
		return nil, err
	}

	externalNodes, err := addExternalNodes(res, vpcInternalAddressRange)
	if err != nil {
		return nil, err
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
	return res, nil
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

func getVPCObjectByName(c *vpcmodel.CloudConfig, vpcName string) (*VPC, error) {
	if obj, ok := c.NameToResource[vpcName]; ok {
		if res, ok := obj.(*VPC); ok {
			return res, nil
		}
		return nil, fmt.Errorf("a resource of name %s is not a VPC as expected", vpcName)
	}
	return nil, fmt.Errorf("missing VPC resource of name %s", vpcName)
}
