package ibmvpc

import (
	"fmt"

	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
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
	subnet *Subnet
}

type pool struct {
	id       string
	name     string
	protocol string
	members  []poolMember
}

func parseLoadBalancers(rc *datamodel.ResourcesContainerModel, res map[string]*vpcmodel.VPCConfig) {
	// _, vpc := common.AnyMapEntry[string, *vpcmodel.VPCConfig](res)
	for _, lbData := range rc.LBList {
		lb := loadBalancer{}
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
				for _, subnetData := range rc.SubnetList {
					for _, subnetResIpData := range subnetData.ReservedIps {
						if *subnetResIpData.Address == *memberData.Target.(*vpcv1.LoadBalancerPoolMemberTarget).Address {
							member.subnet, _ = getSubnetByCidr(res, *subnetData.Ipv4CIDRBlock)
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
