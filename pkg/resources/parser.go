package resources

import (
	"fmt"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

type ResourcesContainer struct {
	naclList     []*vpc1.NetworkACL
	sgList       []*vpc1.SecurityGroup
	instanceList []*vpc1.Instance
	subnetsList  []*vpc1.Subnet
	vpcsList     []*vpc1.VPC
}

func NewResourcesContainer() *ResourcesContainer {
	res := &ResourcesContainer{
		naclList:     []*vpc1.NetworkACL{},
		sgList:       []*vpc1.SecurityGroup{},
		instanceList: []*vpc1.Instance{},
		subnetsList:  []*vpc1.Subnet{},
		vpcsList:     []*vpc1.VPC{},
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
		default:
			fmt.Printf("%s resource type is not yet supported\n", k)
		}

	}
	res.printDetails()
	return res
}

func NewVpcConfig(rc *ResourcesContainer) (*vpcConfig, error) {
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


*/
