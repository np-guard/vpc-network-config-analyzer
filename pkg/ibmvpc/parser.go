package ibmvpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	vpcmodel "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcModel"
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
	default:
		fmt.Printf("%s resource type is not yet supported\n", key)
		return errors.New("unsupported resource type: " + key)
	}
	return nil
}

func printLineStr(s string) {
	fmt.Printf("%s\n", s)
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
		vListLen := len(vList)
		printLineStr(k)
		fmt.Printf("%d\n", vListLen)
		if err := parseSingleResourceList(k, vList, res); err != nil {
			return nil, err
		}
	}
	res.printDetails()
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

func getInstancesConfig(
	instanceList []*vpc1.Instance,
	subnetNameToNetIntf map[string][]*NetworkInterface,
	intfNameToIntf map[string]*NetworkInterface,
	res *vpcmodel.CloudConfig) {
	for i := range instanceList {
		instance := instanceList[i]
		vsiNode := &Vsi{NamedResource: vpcmodel.NamedResource{ResourceName: *instance.Name}, nodes: []vpcmodel.Node{}}
		res.NodeSets = append(res.NodeSets, vsiNode)
		for j := range instance.NetworkInterfaces {
			netintf := instance.NetworkInterfaces[j]
			intfNode := &NetworkInterface{NamedResource: vpcmodel.NamedResource{ResourceName: *netintf.Name},
				address: *netintf.PrimaryIP.Address, vsi: *instance.Name}
			res.Nodes = append(res.Nodes, intfNode)
			vsiNode.nodes = append(vsiNode.nodes, intfNode)
			intfNameToIntf[*netintf.Name] = intfNode
			subnetName := *netintf.Subnet.Name
			if _, ok := subnetNameToNetIntf[subnetName]; !ok {
				subnetNameToNetIntf[subnetName] = []*NetworkInterface{}
			}
			subnetNameToNetIntf[subnetName] = append(subnetNameToNetIntf[subnetName], intfNode)
		}
	}
}

func getSubnetsConfig(
	res *vpcmodel.CloudConfig,
	pgwToSubnet map[string]*Subnet,
	subnetNameToSubnet map[string]*Subnet,
	subnetNameToNetIntf map[string][]*NetworkInterface,
	rc *ResourcesContainer) (vpcInternalAddressRange *common.IPBlock) {
	for i := range rc.subnetsList {
		subnet := rc.subnetsList[i]
		subnetNodes := []vpcmodel.Node{}
		subnetNode := &Subnet{NamedResource: vpcmodel.NamedResource{ResourceName: *subnet.Name}, cidr: *subnet.Ipv4CIDRBlock}
		cidrIPBlock := common.NewIPBlockFromCidr(subnetNode.cidr)
		if vpcInternalAddressRange == nil {
			vpcInternalAddressRange = cidrIPBlock
		} else {
			vpcInternalAddressRange = vpcInternalAddressRange.Union(cidrIPBlock)
		}
		res.NodeSets = append(res.NodeSets, subnetNode)
		subnetNameToSubnet[*subnet.Name] = subnetNode
		if subnet.PublicGateway != nil {
			pgwToSubnet[*subnet.PublicGateway.Name] = subnetNode
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
	return vpcInternalAddressRange
}

func getPgwConfig(
	res *vpcmodel.CloudConfig,
	rc *ResourcesContainer,
	pgwToSubnet map[string]*Subnet) {
	for i := range rc.pgwList {
		pgw := rc.pgwList[i]
		srcNodes := pgwToSubnet[*pgw.Name].Nodes()
		routerPgw := &PublicGateway{NamedResource: vpcmodel.NamedResource{ResourceName: *pgw.Name},
			cidr: "", src: srcNodes} // TODO: get cidr from fip of the pgw
		res.RoutingResources = append(res.RoutingResources, routerPgw)
	}
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
			routerFip := &FloatingIP{NamedResource: vpcmodel.NamedResource{ResourceName: *fip.Name}, cidr: *fip.Address, src: srcNodes}
			res.RoutingResources = append(res.RoutingResources, routerFip)

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
		vpcNodeSet := &VPC{NamedResource: vpcmodel.NamedResource{ResourceName: *vpc.Name}, nodes: []vpcmodel.Node{}}
		res.NodeSets = append(res.NodeSets, vpcNodeSet)
	}
}

func getSGconfig(rc *ResourcesContainer, res *vpcmodel.CloudConfig, intfNameToIntf map[string]*NetworkInterface) error {
	sgMap := map[string]*SecurityGroup{}
	sgList := []*SecurityGroup{}
	for i := range rc.sgList {
		sg := rc.sgList[i]
		sgResource := &SecurityGroup{NamedResource: vpcmodel.NamedResource{ResourceName: *sg.Name},
			analyzer: NewSGAnalyzer(sg), members: map[string]struct{}{}}
		sgMap[*sg.Name] = sgResource
		targets := sg.Targets // *SecurityGroupTargetReference
		// type SecurityGroupTargetReference struct
		for _, target := range targets {
			if targetIntfRef, ok := target.(*vpc1.SecurityGroupTargetReference); ok {
				fmt.Printf("%v", targetIntfRef)
				// get from target name + resource type -> find the address of the target
				targetType := *targetIntfRef.ResourceType
				targetName := *targetIntfRef.Name
				if targetType == networkInterfaceResourceType {
					if intfNode, ok := intfNameToIntf[targetName]; ok {
						sgResource.members[intfNode.address] = struct{}{}
					}
				}
			}
		}
		sgList = append(sgList, sgResource)
	}
	sgLayer := &SecurityGroupLayer{sgList: sgList}
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
	for i := range rc.naclList {
		nacl := rc.naclList[i]
		naclAnalyzer, err := NewNACLAnalyzer(nacl)
		if err != nil {
			return err
		}
		naclResource := &NACL{NamedResource: vpcmodel.NamedResource{ResourceName: *nacl.Name},
			analyzer: naclAnalyzer, subnets: map[string]struct{}{}}
		naclList = append(naclList, naclResource)
		for _, subnetRef := range nacl.Subnets {
			subnetName := *subnetRef.Name
			if subnet, ok := subnetNameToSubnet[subnetName]; ok {
				naclResource.subnets[subnet.cidr] = struct{}{}
			}
		}
	}
	naclLayer := &NaclLayer{naclList: naclList}
	res.FilterResources = append(res.FilterResources, naclLayer)
	return nil
}

func NewCloudConfig(rc *ResourcesContainer) (*vpcmodel.CloudConfig, error) {
	res := &vpcmodel.CloudConfig{
		Nodes:            []vpcmodel.Node{},
		NodeSets:         []vpcmodel.NodeSet{},
		FilterResources:  []vpcmodel.FilterTrafficResource{},
		RoutingResources: []vpcmodel.RoutingResource{},
	}
	var vpcInternalAddressRange *common.IPBlock

	subnetNameToNetIntf := map[string][]*NetworkInterface{}
	intfNameToIntf := map[string]*NetworkInterface{}
	getInstancesConfig(rc.instanceList, subnetNameToNetIntf, intfNameToIntf, res)

	pgwToSubnet := map[string]*Subnet{} // map from pgw name to its attached subnet
	subnetNameToSubnet := map[string]*Subnet{}
	vpcInternalAddressRange = getSubnetsConfig(res, pgwToSubnet, subnetNameToSubnet, subnetNameToNetIntf, rc)

	getPgwConfig(res, rc, pgwToSubnet)

	if err := getFipConfig(rc, res); err != nil {
		return nil, err
	}

	getVPCconfig(rc, res)

	if err := getSGconfig(rc, res, intfNameToIntf); err != nil {
		return nil, err
	}

	if err := getNACLconfig(rc, res, subnetNameToSubnet); err != nil {
		return nil, err
	}

	externalNodes := addExternalNodes(res, vpcInternalAddressRange)

	// update destination of routing resources
	for _, r := range res.RoutingResources {
		if rFip, ok := r.(*FloatingIP); ok {
			rFip.destinations = externalNodes
		}
		if rPgw, ok := r.(*PublicGateway); ok {
			rPgw.destinations = externalNodes
		}
	}
	return res, nil
}

/*
Public IP Ranges
https://phoenixnap.com/kb/public-vs-private-ip-address
The number of public IP addresses is far greater than the number of private ones because every
network on the Internet must have a unique public IP.

All public IP addresses belong to one of the following public IP address ranges:

	1.0.0.0-9.255.255.255
	11.0.0.0-100.63.255.255
	100.128.0.0-126.255.255.255
	128.0.0.0-169.253.255.255
	169.255.0.0-172.15.255.255
	172.32.0.0-191.255.255.255
	192.0.1.0/24
	192.0.3.0-192.88.98.255
	192.88.100.0-192.167.255.255
	192.169.0.0-198.17.255.255
	198.20.0.0-198.51.99.255
	198.51.101.0-203.0.112.255
	203.0.114.0-223.255.255.255

Your private IP address exists within specific private IP address ranges reserved by the Internet Assigned
Numbers Authority (IANA) and should never appear on the internet. There are millions of private networks across the globe,

	 all of which include devices assigned private IP addresses within these ranges:

		Class A: 10.0.0.0 — 10.255.255.255

		Class B: 172.16.0.0 — 172.31.255.255

		Class C: 192.168.0.0 — 192.168.255.255
*/
func addExternalNodes(config *vpcmodel.CloudConfig, vpcInternalAddressRange *common.IPBlock) []vpcmodel.Node {
	externalNodes := []vpcmodel.Node{}
	ipBlocks := []*common.IPBlock{}
	for _, f := range config.FilterResources {
		ipBlocks = append(ipBlocks, f.ReferencedIPblocks()...)
	}

	externalRefIPBlocks := []*common.IPBlock{}
	fmt.Println("referenced external ip blocks:")
	for _, ipBlock := range ipBlocks {
		intersection := ipBlock.Intersection(vpcInternalAddressRange)
		if !intersection.Empty() {
			continue
		}
		cidrList := strings.Join(ipBlock.ToCidrList(), cidrSeparator)
		printLineStr(cidrList)
		externalRefIPBlocks = append(externalRefIPBlocks, ipBlock)
	}
	fmt.Println(linesSeparator)
	fmt.Println("referenced external disjoint ip blocks:")
	// disjoint external ref ip blocks
	disjointRefExternalIPBlocks := common.DisjointIPBlocks(externalRefIPBlocks, []*common.IPBlock{})
	for index, ipBlock := range disjointRefExternalIPBlocks {
		cidrList := strings.Join(ipBlock.ToCidrList(), cidrSeparator)
		printLineStr(cidrList)
		nodeName := fmt.Sprintf("ref-address-%d", index)
		node := &vpcmodel.ExternalNetwork{NamedResource: vpcmodel.NamedResource{ResourceName: nodeName}, CidrStr: cidrList}
		config.Nodes = append(config.Nodes, node)
		externalNodes = append(externalNodes, node)
	}
	//TODO: add cidrs of external network outside the given above cidrs already added
	node := &vpcmodel.ExternalNetwork{NamedResource: vpcmodel.NamedResource{ResourceName: "public-internet"}, CidrStr: "192.0.1.0/24"}
	config.Nodes = append(config.Nodes, node)
	externalNodes = append(externalNodes, node)

	fmt.Println(linesSeparator)
	return externalNodes
	// goal: define connectivity between elements in the set {vsi address / referenced address in nacl or sg / rest of external range}
}

/*func NewVpcConfig(rc *ResourcesContainer) (*vpcConfig, error) {
	config := &vpcConfig{
		vsiMap:                map[string]*common.IPBlock{},
		subnetsMap:            map[string]*common.IPBlock{},
		nacl:                  map[string]*vpc1.NetworkACL{},
		sg:                    map[string]*vpc1.SecurityGroup{},
		vsiToSubnet:           map[string]string{},
		subnetToNacl:          map[string]string{},
		vsiToSg:               map[string][]string{},
		netInterfaceNameToVsi: map[string]string{},
	}
	for i := range rc.naclList {
		nacl := rc.naclList[i]
		config.nacl[*nacl.Name] = nacl
	}
	for i := range rc.sgList {
		sg := rc.sgList[i]
		config.sg[*sg.Name] = sg
	}
	for i := range rc.subnetsList {
		subnet := rc.subnetsList[i]
		subnetCIDR := common.NewIPBlockFromCidr(*subnet.Ipv4CIDRBlock)
		config.subnetsMap[*subnet.Name] = subnetCIDR
		naclName := *subnet.NetworkACL.Name
		if _, ok := config.nacl[naclName]; !ok {
			return nil, fmt.Errorf("subnet %s has nacl %s which is not defined", *subnet.Name, naclName)
		}
		config.subnetToNacl[*subnet.Name] = naclName
	}
	for i := range rc.instanceList {
		instance := rc.instanceList[i]
		if len(instance.NetworkInterfaces) != 1 {
			fmt.Printf("warning: ignoring multiple network interfaces for instance %s, considering only first one", *instance.Name)
		}
		if len(instance.NetworkInterfaces) == 0 {
			return nil, fmt.Errorf("instance %s has no network interfaces", *instance.Name)
		}
		netInterface := instance.NetworkInterfaces[0]
		if netInterface.PrimaryIP == nil {
			return nil, fmt.Errorf("PrimaryIP for net-interface of instance %s is empty", *instance.Name)
		}
		ipv4Address := *netInterface.PrimaryIP.Address
		if ipv4Address == "0.0.0.0" {
			return nil, fmt.Errorf("for instance %s the IP address has not yet been selected", *instance.Name)
		}
		config.netInterfaceNameToVsi[*netInterface.Name] = *instance.Name
		ipBlock, err := common.NewIPBlockFromIPAddress(ipv4Address)
		if err != nil {
			return nil, err
		}
		config.vsiMap[*instance.Name] = ipBlock
		subnetName := netInterface.Subnet.Name
		if _, ok := config.subnetsMap[*subnetName]; !ok {
			return nil, fmt.Errorf("instance %s has subnet %s which is not defined", *instance.Name, *subnetName)
		}
		config.vsiToSubnet[*instance.Name] = *subnetName
		config.vsiToSg[*instance.Name] = []string{}

	}
	// update map from vsi to sg
	for sgName, sgObj := range config.sg {
		for i := range sgObj.Targets {
			if target, ok := sgObj.Targets[i].(*vpc1.SecurityGroupTargetReference); ok {
				targetType := *target.ResourceType
				targetName := *target.Name // the network interface name
				if targetType == "network_interface" {
					var vsiName string
					if vsiName, ok = config.netInterfaceNameToVsi[targetName]; !ok {
						return nil, fmt.Errorf("sg %s has target interface %s which is not defined", sgName, targetName)
					}
					config.vsiToSg[vsiName] = append(config.vsiToSg[vsiName], sgName)
				} else {
					//return nil, fmt.Errorf("sg %s has target %s type not supported", sgName, targetType)
					fmt.Printf("sg %s has target %s type not supported - ignoring this target", sgName, targetType)
				}
			} else {
				return nil, fmt.Errorf("sg %s has target at index %d which is not SecurityGroupTargetReference", sgName, i)
			}
		}
	}

	return config, nil
}
*/

/*


// SecurityGroupTargetReference : The resource types that can be security group targets are
// expected to expand in the future. When iterating over
// security group targets, do not assume that every target resource will be from a known set of resource types.
// Optionally halt processing and surface an error, or bypass resources of unrecognized types.
// Models which "extend" this model:
// - SecurityGroupTargetReferenceNetworkInterfaceReferenceTargetContext
// - SecurityGroupTargetReferenceLoadBalancerReference
// - SecurityGroupTargetReferenceEndpointGatewayReference
// - SecurityGroupTargetReferenceVPNServerReference
type SecurityGroupTargetReference struct {
	// If present, this property indicates the referenced resource has been deleted, and provides
	// some supplementary information.
	Deleted *NetworkInterfaceReferenceTargetContextDeleted `json:"deleted,omitempty"`

	// The URL for this network interface.
	Href *string `json:"href,omitempty"`

	// The unique identifier for this network interface.
	ID *string `json:"id,omitempty"`

	// The name for this network interface.
	Name *string `json:"name,omitempty"`

	// The resource type.
	ResourceType *string `json:"resource_type,omitempty"`

	// The load balancer's CRN.
	CRN *string `json:"crn,omitempty"`
}

// SecurityGroupTargetReferenceEndpointGatewayReference : SecurityGroupTargetReferenceEndpointGatewayReference struct
// This model "extends" SecurityGroupTargetReference
type SecurityGroupTargetReferenceEndpointGatewayReference struct {

// SecurityGroupTargetReferenceLoadBalancerReference : SecurityGroupTargetReferenceLoadBalancerReference struct
// This model "extends" SecurityGroupTargetReference
type SecurityGroupTargetReferenceLoadBalancerReference struct {

// SecurityGroupTargetReferenceNetworkInterfaceReferenceTargetContext :
 SecurityGroupTargetReferenceNetworkInterfaceReferenceTargetContext struct
// This model "extends" SecurityGroupTargetReference
type SecurityGroupTargetReferenceNetworkInterfaceReferenceTargetContext struct {


// SecurityGroupTargetReferenceVPNServerReference : SecurityGroupTargetReferenceVPNServerReference struct
// This model "extends" SecurityGroupTargetReference
type SecurityGroupTargetReferenceVPNServerReference struct {



	type FloatingIPTargetNetworkInterfaceReference struct {
	// If present, this property indicates the referenced resource has been deleted, and provides
	// some supplementary information.
	Deleted *NetworkInterfaceReferenceDeleted `json:"deleted,omitempty"`

	// The URL for this network interface.
	Href *string `json:"href" validate:"required"`

	// The unique identifier for this network interface.
	ID *string `json:"id" validate:"required"`

	// The name for this network interface.
	Name *string `json:"name" validate:"required"`

	PrimaryIP *ReservedIPReference `json:"primary_ip" validate:"required"`

	// The resource type.
	ResourceType *string `json:"resource_type" validate:"required"`
}


// This model "extends" FloatingIPTarget
type FloatingIPTargetPublicGatewayReference struct {
	// The CRN for this public gateway.
	CRN *string `json:"crn" validate:"required"`

	// If present, this property indicates the referenced resource has been deleted, and provides
	// some supplementary information.
	Deleted *PublicGatewayReferenceDeleted `json:"deleted,omitempty"`

	// The URL for this public gateway.
	Href *string `json:"href" validate:"required"`

	// The unique identifier for this public gateway.
	ID *string `json:"id" validate:"required"`

	// The name for this public gateway. The name is unique across all public gateways in the VPC.
	Name *string `json:"name" validate:"required"`

	// The resource type.
	ResourceType *string `json:"resource_type" validate:"required"`
}


// FloatingIPTarget : The target of this floating IP.
// Models which "extend" this model:
// - FloatingIPTargetNetworkInterfaceReference
// - FloatingIPTargetPublicGatewayReference
type FloatingIPTarget struct {
	// If present, this property indicates the referenced resource has been deleted, and provides
	// some supplementary information.
	Deleted *NetworkInterfaceReferenceDeleted `json:"deleted,omitempty"`

	// The URL for this network interface.
	Href *string `json:"href,omitempty"`

	// The unique identifier for this network interface.
	ID *string `json:"id,omitempty"`

	// The name for this network interface.
	Name *string `json:"name,omitempty"`

	PrimaryIP *ReservedIPReference `json:"primary_ip,omitempty"`

	// The resource type.
	ResourceType *string `json:"resource_type,omitempty"`

	// The CRN for this public gateway.
	CRN *string `json:"crn,omitempty"`
}

*/
