package resources

import (
	"fmt"
	"strings"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"
)

type vpcConfig struct {
	vsiMap                map[string]*IPBlock            // map from vsi name to its network interface address
	subnetsMap            map[string]*IPBlock            // map from subnet name to its cidr range
	nacl                  map[string]*vpc1.NetworkACL    // map from nacl name to its object
	sg                    map[string]*vpc1.SecurityGroup // map from sg name to its object
	vsiToSubnet           map[string]string              // map from vsi name to its subnet
	subnetToNacl          map[string]string              // map from subnet name to its nacl
	vsiToSg               map[string][]string            // map from vsi to its list of sg
	netInterfaceNameToVsi map[string]string              // map from network interface name to its vsi
}

func (v *vpcConfig) details() string {
	res := ""
	res += "vsi details:\n"
	for vsi, ip := range v.vsiMap {
		ipCidr := ip.ToCidrList()
		ipCidrStr := strings.Join(ipCidr, ",")
		interfaceName := ""
		for netInterface, vsiName := range v.netInterfaceNameToVsi {
			if vsiName == vsi {
				interfaceName = netInterface
			}
		}
		subnetName := v.vsiToSubnet[vsi]
		sgNames := strings.Join(v.vsiToSg[vsi], ",")
		naclName := v.subnetToNacl[subnetName]
		res += fmt.Sprintf("vsi name: %s\tip: %s\tinterface name: %s\tsubnetName: %s\tsg names: %s\t nacl name: %s\n", vsi, ipCidrStr, interfaceName, subnetName, sgNames, naclName)
	}
	for subnet, ip := range v.subnetsMap {
		ipCidr := ip.ToCidrList()
		ipCidrStr := strings.Join(ipCidr, ",")
		res += fmt.Sprintf("subnet name: %s\tip cidr: %s\n", subnet, ipCidrStr)
	}
	for naclName, naclObj := range v.nacl {
		res += fmt.Sprintf("nacl %s rules:\n", naclName)
		res += getNACLDetails(naclObj)
	}
	for sgName, sgObj := range v.sg {
		res += fmt.Sprintf("sg %s rules:\n", sgName)
		res += getSGDetails(sgObj)
	}

	//getSGDetails

	return res
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
