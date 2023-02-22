package resources

import (
	"fmt"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"
)

type vpcConfig struct {
	vsiMap       map[string]*IPBlock            // map from vsi name to its network interface address
	subnetsMap   map[string]*IPBlock            // map from subnet name to its cidr range
	nacl         map[string]*vpc1.NetworkACL    // map from nacl name to its object
	sg           map[string]*vpc1.SecurityGroup // map from sg name to its object
	vsiToSubnet  map[string]string              // map from vsi name to its subnet
	subnetToNacl map[string]string              // map from subnet name to its nacl
	vsiToSg      map[string][]string            // map from vsi to its list of sg
}

// connectivity analysis per VSI (network interface): connectivity based on SG and based on NCAL of its subnet
func analyzeConnectivity(t *vpcConfig) {
	for vsi, vsiIP := range t.vsiMap {
		subnet := t.vsiToSubnet[vsi]
		nacl := t.subnetToNacl[subnet]
		sgList := t.vsiToSg[vsi]

		naclObj := t.nacl[nacl]
		sgObjList := []*vpc1.SecurityGroup{}
		for _, sg := range sgList {
			sgObjList = append(sgObjList, t.sg[sg])
		}
		//ingressSgConnStr, egressSgConnStr, ingressConnectivityRes, egressConnectivityRes := AnalyzeSGListPerInstance(vsiIP, sgObjList)
		ingressSgConnStr, egressSgConnStr, ingressSgConn, egressSgConn := AnalyzeSGListPerInstance(vsiIP, sgObjList)
		ingressNACLConnStr, egressNACLConStr, ingressNACLConn, egressNACLCon := AnalyzeNACL(naclObj, t.subnetsMap[subnet], vsiIP) //ingressNACLConn, egressNACLCon
		fmt.Println("sg analysis:")
		fmt.Printf("%v\n", ingressSgConnStr)
		fmt.Printf("%v\n", egressSgConnStr)

		fmt.Println("nacl analysis:")
		fmt.Printf("%v\n", ingressNACLConnStr)
		fmt.Printf("%v\n", egressNACLConStr)

		//fmt.Printf("%v %v %v %v", ingressSgConn, egressSgConn, ingressNACLConn, egressNACLCon)

		// combined analysis -- intersection of sg and nacl results
		ingressConnectivityRes := ingressSgConn.intersection(ingressNACLConn)
		egressConnectivityRes := egressSgConn.intersection(egressNACLCon)

		fmt.Printf("ingress connectivity result for vsi %s , considering sg + nacl:\n", vsiIP.ToIPRanges())
		fmt.Printf("%s\n", ingressConnectivityRes.string())
		fmt.Printf("egress connectivity result for vsi %s , considering sg + nacl:\n", vsiIP.ToIPRanges())
		fmt.Printf("%s\n", egressConnectivityRes.string())

	}
}
