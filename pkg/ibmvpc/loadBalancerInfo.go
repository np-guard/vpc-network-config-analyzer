package ibmvpc

import (
	"fmt"

	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
	vpcmodel "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

type resIp struct {
	id     string
	subnet *Subnet
}
type loadBalancer struct {
	name      string
	resIPs    []resIp
	listeners []listener
	pools     []*pool
	subnets   []*Subnet
}

type listener struct {
	portMax, portMin, port int64
	protocol               string
	service                string // todo
	defaultPool            *pool
	pools                  []*pool
}

type poolMember struct {
	port   int64
	address string
	node *vpcmodel.Node
}

type pool struct {
	id       string
	name     string
	protocol string
	members  []poolMember
}

var lb loadBalancer

func parseLoadBalancers(rc *datamodel.ResourcesContainerModel, res map[string]*vpcmodel.VPCConfig) {
	// _, vpc := common.AnyMapEntry[string, *vpcmodel.VPCConfig](res)
	for _, lbData := range rc.LBList {
		lb = loadBalancer{}
		lb.name = *lbData.Name
		for _, resIpData := range lbData.PrivateIps {
			rIp := resIp{}
			rIp.id = *resIpData.ID
			for _, subnetData := range rc.SubnetList {
				for _, subnetResIpData := range subnetData.ReservedIps {
					if *subnetResIpData.ID == rIp.id {
						rIp.subnet, _ = getSubnetByCidr(res, *subnetData.Ipv4CIDRBlock)
					}
				}
			}
			lb.resIPs = append(lb.resIPs, rIp)
		}
		for _, poolData := range lbData.Pools {
			pool := pool{}
			pool.id = *poolData.ID
			pool.name = *poolData.Name
			pool.protocol = *poolData.Protocol
			for _, memberData := range poolData.Members {
				member := poolMember{}
				member.port = *memberData.Port
				member.address = *memberData.Target.(*vpcv1.LoadBalancerPoolMemberTarget).Address
				for _, subnetData := range rc.SubnetList {
					subnet, _ := getSubnetByCidr(res, *subnetData.Ipv4CIDRBlock)
					for _,node := range subnet.nodes{
						if node.CidrOrAddress() == member.address{
							member.node = &node
						}
					}
				}
				pool.members = append(pool.members, member)

			}
			lb.pools = append(lb.pools, &pool)
		}
		for _, lbSubnetData := range lbData.Subnets {
			for _, subnetData := range rc.SubnetList {
				if *lbSubnetData.ID == *subnetData.ID {
					subnet, _ := getSubnetByCidr(res, *subnetData.Ipv4CIDRBlock)
					lb.subnets = append(lb.subnets, subnet)
				}
			}
		}

		for _, lisData := range lbData.Listeners {
			lis := listener{}
			if lisData.Port != nil {
				lis.port = *lisData.Port
			}
			if lisData.PortMin != nil {
				lis.portMin = *lisData.PortMin
				lis.portMax = *lisData.PortMax
			}
			lis.protocol = *lisData.Protocol

			poolData := lisData.DefaultPool
			for _, pool := range lb.pools {
				if pool.id == *poolData.ID {
					lis.defaultPool = pool
					lis.pools = append(lis.pools, pool)
				}
			}
			lb.listeners = append(lb.listeners, lis)
		}

		fmt.Println(lb)
	}
}

var marked bool

func markLoadBalancer(gen *vpcmodel.DrawioGenerator) {
	if marked {
		return
	}
	marked = true
	network := gen.Network()
	publicNetwork := gen.PublicNetwork()
	lbTn := drawio.NewInternetServiceTreeNode(publicNetwork, "load Balancer")
	poolTNs := map[*pool]drawio.IconTreeNodeInterface{}
	for _, resIp := range lb.resIPs {
		drawio.NewConnectivityLineTreeNode(network, gen.TreeNode(resIp.subnet), lbTn, true, "interface")
	}
	for _, pool := range lb.pools {
		poolTNs[pool] = drawio.NewInternetServiceTreeNode(publicNetwork, "pool "+pool.name)
		for _,member := range pool.members{
			drawio.NewConnectivityLineTreeNode(network, poolTNs[pool], gen.TreeNode(*member.node), true, fmt.Sprintf("/%s:%d", member.address, member.port))
		}
	}
	for _, listener := range lb.listeners {
		lisTn := drawio.NewInternetServiceTreeNode(publicNetwork, "listener")
		label := fmt.Sprintf("/%s:%d", listener.protocol, listener.port)
		drawio.NewConnectivityLineTreeNode(network, lbTn, lisTn, true, label)
		for _, pool := range listener.pools {
			drawio.NewConnectivityLineTreeNode(network, lisTn, poolTNs[pool], true, "")
		}
	}
}
