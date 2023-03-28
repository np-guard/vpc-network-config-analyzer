package resources

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	v1 "k8s.io/api/core/v1"
)

func isIngressRule(direction *string) bool {
	if direction == nil {
		return false
	}
	if *direction == "inbound" {
		return true
	}
	return false
}

/*func isEgressRule(direction *string) bool {
	if direction == nil {
		return false
	}
	if *direction == "outbound" {
		return true
	}
	return false
}*/

func getProtocolConn(Protocol *string, PortMax, PortMin *int64) *ConnectionSet {
	res := getEmptyConnSet()
	ports := PortSet{Ports: common.CanonicalIntervalSet{IntervalSet: []common.Interval{{Start: *PortMin, End: *PortMax}}}}
	if *Protocol == "tcp" {
		res.AddConnection(v1.ProtocolTCP, ports)
	}
	return res
}
