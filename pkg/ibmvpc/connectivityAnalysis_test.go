package ibmvpc

import (
	"fmt"
	"testing"

	vpcmodel "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func addInterfaceNode(config *vpcmodel.CloudConfig, name, uid, address, vsiName, subnetName string) {
	intfNode := &NetworkInterface{
		NamedResource: vpcmodel.NamedResource{ResourceName: name, ResourceUID: uid},
		address:       address,
		vsi:           vsiName,
	}
	// add references between subnet to interface (both directions)
	for _, subnet := range config.NodeSets {
		if subnet.Name() == subnetName {
			subnetActual := subnet.(*Subnet)
			intfNode.subnet = subnetActual
			subnetActual.nodes = append(subnetActual.nodes, intfNode)
		}
	}

	config.Nodes = append(config.Nodes, intfNode)

}

func addSubnet(config *vpcmodel.CloudConfig, name, uid, cidr, zone string) {
	subnetNode := &Subnet{
		zonalNamedResource: zonalNamedResource{vpcmodel.NamedResource{ResourceName: name, ResourceUID: uid}, zone},
		cidr:               cidr,
	}
	config.NodeSets = append(config.NodeSets, subnetNode)
}

func NewSimpleCloudConfig() *vpcmodel.CloudConfig {
	config := &vpcmodel.CloudConfig{
		Nodes:            []vpcmodel.Node{},
		NodeSets:         []vpcmodel.NodeSet{},
		FilterResources:  []vpcmodel.FilterTrafficResource{},
		RoutingResources: []vpcmodel.RoutingResource{},
	}
	addSubnet(config, "subnet-1", "uid-s1", "10.0.20.0/22", "z1")
	addInterfaceNode(config, "intf-1", "uid-1", "10.0.20.15", "vsi-1", "subnet-1")
	return config
}

func TestBasicCloudConfig(t *testing.T) {
	c := NewSimpleCloudConfig()
	strC := c.String()
	fmt.Println(strC)
	fmt.Println("done")
}
