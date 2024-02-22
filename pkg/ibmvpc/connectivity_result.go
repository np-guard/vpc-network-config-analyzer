package ibmvpc

import (
	"github.com/np-guard/models/pkg/ipblocks"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// ConnectivityResult is built on disjoint ip-blocks for targets of all relevant sg/nacl results
// ConnectivityResult is per VSI network interface: contains allowed connectivity (with connection attributes) per target
type ConnectivityResult struct {
	isIngress    bool
	allowedConns map[*ipblocks.IPBlock]*common.ConnectionSet // allowed target and its allowed connections
	allowRules   map[*ipblocks.IPBlock][]int                 // indexes of (positive) allowRules contributing to this connectivity
	// the following are relevant only to filters with deny rules - nacl
	deniedConns map[*ipblocks.IPBlock]*common.ConnectionSet // denied target and its allowed connections, by deny rules.
	denyRules   map[*ipblocks.IPBlock][]int                 // indexes of deny rules relevant to this connectivity
}
