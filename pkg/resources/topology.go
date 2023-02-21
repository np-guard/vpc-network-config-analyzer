package resources

import (
	"fmt"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"
)

type vpcTopology struct {
	vsiMap       map[string]*IPBlock            // map from vsi name to its network interface address
	subnetsMap   map[string]*IPBlock            // map from subnet name to its cidr range
	nacl         map[string]*vpc1.NetworkACL    // map from nacl name to its object
	sg           map[string]*vpc1.SecurityGroup // map from sg name to its object
	vsiToSubnet  map[string]string              // map from vsi name to its subnet
	subnetToNacl map[string]string              // map from subnet name to its nacl
	vsiToSg      map[string][]string            // map from vsi to its list of sg
}

// connectivity analysis per VSI (network interface): connectivity based on SG and based on NCAL of its subnet
func analyzeConnectivity(t *vpcTopology) {
	for vsi, vsiIP := range t.vsiMap {
		subnet := t.vsiToSubnet[vsi]
		nacl := t.subnetToNacl[subnet]
		sgList := t.vsiToSg[vsi]

		naclObj := t.nacl[nacl]
		sgObjList := []*vpc1.SecurityGroup{}
		for _, sg := range sgList {
			sgObjList = append(sgObjList, t.sg[sg])
		}
		//ingressSgConn, egressSgConn, ingressConnectivityRes, egressConnectivityRes := AnalyzeSGListPerInstance(vsiIP, sgObjList)
		ingressSgConn, egressSgConn, _, _ := AnalyzeSGListPerInstance(vsiIP, sgObjList)
		ingressNACLConn, egressNACLCon := AnalyzeNACL(naclObj, t.subnetsMap[subnet])
		fmt.Println("sg analysis:")
		fmt.Printf("%v\n", ingressSgConn)
		fmt.Printf("%v\n", egressSgConn)

		fmt.Println("nacl analysis:")
		fmt.Printf("%v\n", ingressNACLConn)
		fmt.Printf("%v\n", egressNACLCon)
	}
}
