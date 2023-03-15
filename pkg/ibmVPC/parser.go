package ibmvpc

import (
	"fmt"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"
	vpcmodel "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcModel"
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

func ParseResources(resourcesJsonFile []byte) *ResourcesContainer {
	res := NewResourcesContainer()
	resourcesMap := jsonToMap(resourcesJsonFile)
	for k, v := range resourcesMap {
		vList := jsonToList(v)
		vListLen := len(vList)
		fmt.Printf("%s\n", k)
		fmt.Printf("%d\n", vListLen)
		switch k {
		case "network_acls":
			for i := range vList {
				obj := JsonNaclToObject(vList[i])
				res.addNACL(obj)
			}
		case "security_groups":
			for i := range vList {
				obj := JsonSgToObject(vList[i])
				res.addSG(obj)
			}
		case "instances":
			for i := range vList {
				obj := JsonInstanceToObject(vList[i])
				res.addInstance(obj)
			}
		case "subnets":
			for i := range vList {
				obj := JsonSubnetToObject(vList[i])
				res.addSubnet(obj)
			}
		case "vpcs":
			for i := range vList {
				obj := JsonVpcToObject(vList[i])
				res.addVpc(obj)
			}
		case "floating_ips":
			for i := range vList {
				obj := JsonFipToObject(vList[i])
				res.addFloatingIP(obj)
			}
		case "public_gateways":
			for i := range vList {
				obj := JsonPgwTpObject(vList[i])
				res.addPublicGateway(obj)
			}
		default:
			fmt.Printf("%s resource type is not yet supported\n", k)
		}

	}
	res.printDetails()
	return res
}

func getCertainNodes(allNodes []vpcmodel.Node, shouldTakeNode func(vpcmodel.Node) bool) (ret []vpcmodel.Node) {
	for _, s := range allNodes {
		if shouldTakeNode(s) {
			ret = append(ret, s)
		}
	}
	return
}

func NewVPCFromConfig(rc *ResourcesContainer) *vpcmodel.VPCConfig {
	res := &vpcmodel.VPCConfig{
		Nodes:            []vpcmodel.Node{},
		NodeSets:         []vpcmodel.NodeSet{},
		FilterResources:  []vpcmodel.FilterTraffic{},
		RoutingResources: []vpcmodel.RoutingResource{},
	}
	addExternalNodes(res)

	for i := range rc.instanceList {
		instance := rc.instanceList[i]
		vsiNode := &Vsi{name: *instance.Name, nodes: []vpcmodel.Node{}}
		res.NodeSets = append(res.NodeSets, vsiNode)
		for j := range instance.NetworkInterfaces {
			netintf := instance.NetworkInterfaces[j]
			intfNode := &NetworkInterface{name: *netintf.Name, cidr: *netintf.PrimaryIP.Address, vsi: *instance.Name, subnet: *netintf.Subnet.Name}
			res.Nodes = append(res.Nodes, intfNode)
			vsiNode.nodes = append(vsiNode.nodes, intfNode)
		}
	}
	pgwToSubnet := map[string]*Subnet{} // map from pgw name to its attached subnet
	for i := range rc.subnetsList {
		subnet := rc.subnetsList[i]
		subnetNodes := getCertainNodes(res.Nodes, func(n vpcmodel.Node) bool {
			if intfNode, ok := n.(*NetworkInterface); ok {
				if intfNode.subnet == *subnet.Name {
					return true
				}
			}
			return false
		})
		subnetNode := &Subnet{name: *subnet.Name, cidr: *subnet.Ipv4CIDRBlock, nodes: subnetNodes}
		res.NodeSets = append(res.NodeSets, subnetNode)
		if subnet.PublicGateway != nil {
			pgwToSubnet[*subnet.PublicGateway.Name] = subnetNode
		}
	}

	for i := range rc.pgwList {
		pgw := rc.pgwList[i]
		srcNodes := pgwToSubnet[*pgw.Name].Nodes()
		dstNodes := getCertainNodes(res.Nodes, func(n vpcmodel.Node) bool { return !n.IsInternal() })
		routerPgw := &PublicGateway{name: *pgw.Name, cidr: "", src: srcNodes, destinations: dstNodes} // TODO: get cidr from fip of the pgw
		res.RoutingResources = append(res.RoutingResources, routerPgw)
	}

	for i := range rc.fipList {
		fip := rc.fipList[i]
		targetIntf := fip.Target
		var targetAddress string
		if target, ok := targetIntf.(*vpc1.FloatingIPTargetNetworkInterfaceReference); ok {
			targetAddress = *target.PrimaryIP.Address
		} else if target, ok := targetIntf.(*vpc1.FloatingIPTarget); ok {
			if *target.ResourceType != "network_interface" {
				continue
			}
			targetAddress = *target.PrimaryIP.Address
		}
		if targetAddress != "" {
			srcNodes := getCertainNodes(res.Nodes, func(n vpcmodel.Node) bool { return n.Cidr() == targetAddress })
			dstNodes := getCertainNodes(res.Nodes, func(n vpcmodel.Node) bool { return !n.IsInternal() })
			routerFip := &FloatingIP{name: *fip.Name, cidr: *fip.Address, src: srcNodes, destinations: dstNodes}
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
	for i := range rc.vpcsList {
		vpc := rc.vpcsList[i]
		vpcNodeSet := &VPC{name: *vpc.Name, nodes: []vpcmodel.Node{}}
		res.NodeSets = append(res.NodeSets, vpcNodeSet)

	}

	return res
}

/*
Public IP Ranges
https://phoenixnap.com/kb/public-vs-private-ip-address
The number of public IP addresses is far greater than the number of private ones because every network on the Internet must have a unique public IP.

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

Your private IP address exists within specific private IP address ranges reserved by the Internet Assigned Numbers Authority (IANA) and should never appear on the internet. There are millions of private networks across the globe, all of which include devices assigned private IP addresses within these ranges:

    Class A: 10.0.0.0 — 10.255.255.255

    Class B: 172.16.0.0 — 172.31.255.255

    Class C: 192.168.0.0 — 192.168.255.255

*/
func addExternalNodes(config *vpcmodel.VPCConfig) {
	config.Nodes = append(config.Nodes, &ExternalNetwork{name: "public-internet", cidr: "192.0.1.0/24"})

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


// SecurityGroupTargetReference : The resource types that can be security group targets are expected to expand in the future. When iterating over
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

// SecurityGroupTargetReferenceNetworkInterfaceReferenceTargetContext : SecurityGroupTargetReferenceNetworkInterfaceReferenceTargetContext struct
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
