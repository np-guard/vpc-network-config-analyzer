package resources

import (
	_ "embed"
	"fmt"
	"strings"
	"testing"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	v1 "k8s.io/api/core/v1"
)

//go:embed other_examples/nwacl_1.json
var nwacl1 []byte

//go:embed other_examples/nwacl_2.json
var nwacl2 []byte

//go:embed other_examples/nwacl_3.json
var nwacl3 []byte

//go:embed other_examples/sg_1.json
var sg1 []byte

//go:embed other_examples/sg_2.json
var sg2 []byte

/*func TestSgJsonUnmarshal(t *testing.T) {
	sgExamples := [][]byte{sg1}
	for index, sg := range sgExamples {
		sgObj := JsonSgToObject(sg)
		sgJson, err := ObjectSgToJson(sgObj)
		if err != nil {
			t.Errorf("error ObjectNaclToJson: %v", err)
		}
		if getJsonStr(sgJson) != getJsonStr(sg) {
			os.WriteFile("actual.json", sgJson, 0600)
			t.Errorf("test index %d: error sgJson not equal to original json string", index)
			fmt.Printf("expected:\n%s\n actual:\n%s\n", getJsonStr(sg), getJsonStr(sgJson))
		}
	}
}*/

/* func TestNaclJsonUnmarshal(t *testing.T) {
	naclExamples := [][]byte{nwacl1, nwacl2, nwacl3}
	for index, nwacl := range naclExamples {
		naclObj := JsonNaclToObject(nwacl)
		naclJson, err := ObjectNaclToJson(naclObj)
		if err != nil {
			t.Errorf("error ObjectNaclToJson: %v", err)
		}
		if getJsonStr(naclJson) != getJsonStr(nwacl) {
			os.WriteFile("actual.json", naclJson, 0600)
			t.Errorf("test index %d: error naclJson not equal to original json string", index)
		}
	}
} */

func getJsonStr(b []byte) string {
	res := string(b)
	res = strings.ReplaceAll(res, " ", "")
	res = strings.ReplaceAll(res, "\n", "")
	return res
}

func TestGetSGrule(t *testing.T) {
	sg := JsonSgToObject(sg1)
	getSGrules(sg)
}

func TestGetNACLrule(t *testing.T) {
	naclExamples := [][]byte{nwacl1, nwacl2, nwacl3}
	for index, nwacl := range naclExamples {
		fmt.Printf("nacl rules for example %d:\n", index+1)
		naclObj := JsonNaclToObject(nwacl)
		for index := range naclObj.Rules {
			rule := naclObj.Rules[index]
			ruleStr, _, _ := getNACLRule(rule)
			fmt.Printf("%s", ruleStr)
		}
	}
}

func TestAnalyzeNACL(t *testing.T) {
	naclObj := JsonNaclToObject(nwacl1)
	subnet, _ := common.NewIPBlock("10.0.0.0/24", []string{})
	AnalyzeNACL(naclObj, subnet, nil)
}

func getTCPconn(startPort int64, endPort int64) *ConnectionSet {
	res := MakeConnectionSet(false)
	ports := PortSet{Ports: common.CanonicalIntervalSet{IntervalSet: []common.Interval{{Start: startPort, End: endPort}}}}
	res.AddConnection(v1.ProtocolTCP, ports)
	return &res
}

func TestGetAllowedIngressConnections(t *testing.T) {
	// sets of ingress rules to test with
	rulesTest1 := []*NACLRule{
		{
			src:         common.NewIPBlockFromCidr("1.2.3.4/32"),
			dst:         common.NewIPBlockFromCidr("10.0.0.1/32"),
			connections: getAllConnSet(),
			action:      "deny",
		},
		{
			src:         common.NewIPBlockFromCidr("0.0.0.0/0"),
			dst:         common.NewIPBlockFromCidr("0.0.0.0/0"),
			connections: getAllConnSet(),
			action:      "allow",
		},
	}

	rulesTest2 := []*NACLRule{
		{
			src:         common.NewIPBlockFromCidr("1.2.3.4/32"),
			dst:         common.NewIPBlockFromCidr("10.0.0.1/32"),
			connections: getTCPconn(80, 80),
			action:      "allow",
		},
		{
			src:         common.NewIPBlockFromCidr("1.2.3.4/32"),
			dst:         common.NewIPBlockFromCidr("10.0.0.1/32"),
			connections: getTCPconn(1, 100),
			action:      "deny",
		},
		{
			src:         common.NewIPBlockFromCidr("0.0.0.0/0"),
			dst:         common.NewIPBlockFromCidr("0.0.0.0/0"),
			connections: getAllConnSet(),
			action:      "allow",
		},
	}

	rulesTest3 := []*NACLRule{
		{
			dst:         common.NewIPBlockFromCidr("1.2.3.4/32"),
			src:         common.NewIPBlockFromCidr("10.0.0.1/32"),
			connections: getAllConnSet(),
			action:      "deny",
		},
		{
			dst:         common.NewIPBlockFromCidr("0.0.0.0/0"),
			src:         common.NewIPBlockFromCidr("0.0.0.0/0"),
			connections: getAllConnSet(),
			action:      "allow",
		},
	}

	subnet := common.NewIPBlockFromCidr("10.0.0.0/24")

	//res1 := ingressConnResFromInput(rulesTest1, subnet)
	res1, _ := AnalyzeNACLRules(rulesTest1, subnet, true, nil)
	fmt.Printf("res for test %s:\n%s\n", "rulesTest1", res1)

	//res2 := ingressConnResFromInput(rulesTest2, subnet)
	res2, _ := AnalyzeNACLRules(rulesTest2, subnet, true, nil)
	fmt.Printf("res for test %s:\n%s\n", "rulesTest2", res2)

	res3, _ := AnalyzeNACLRules(rulesTest3, subnet, false, nil)
	fmt.Printf("res for test %s:\n%s\n", "rulesTest3", res3)
}

//////////////////////////////////////////////////////////////////////////////////////////////

func TestGetSGLrule(t *testing.T) {
	sgObj := JsonSgToObject(sg1)
	for index := range sgObj.Rules {
		rule := sgObj.Rules[index]
		ruleStr, _, _ := getSGRule(rule)
		fmt.Printf("%s", ruleStr)
	}
}

func TestAnalyzeSG(t *testing.T) {
	sgObj := JsonSgToObject(sg2)
	ingressRules, _ := getSGrules(sgObj)
	res := AnalyzeSGRules(ingressRules, true)
	resStr := res.string()
	fmt.Printf("%s", resStr)
}

//////////////////////////////////////////////////////////////////////////////////////////////

//topology analysis example

func getExampleTopology() *vpcConfig {
	res := &vpcConfig{}
	res.vsiMap = map[string]*common.IPBlock{"b": common.NewIPBlockFromCidr("10.0.0.4/32")}
	res.subnetsMap = map[string]*common.IPBlock{"a": common.NewIPBlockFromCidr("10.0.0.0/24")}
	res.vsiToSubnet = map[string]string{"b": "a"}
	res.nacl = map[string]*vpc1.NetworkACL{"n1": JsonNaclToObject(nwacl1)}
	res.sg = map[string]*vpc1.SecurityGroup{"s1": JsonSgToObject(sg1)}
	res.subnetToNacl = map[string]string{"a": "n1"}
	res.vsiToSg = map[string][]string{"b": {"s1"}}
	return res

}

func TestTopologyAnalysis(t *testing.T) {
	topology := getExampleTopology()
	analyzeConnectivity(topology)
}

func TestIntervalToCidrList(t *testing.T) {
	ipb1 := common.NewIPBlockFromCidr("192.168.1.0/32")
	ipb2 := common.NewIPBlockFromCidr("192.168.1.9/32")
	ipStart := ipb1.StartIPNum()
	ipEnd := ipb2.StartIPNum()

	res := common.IntervalToCidrList(ipStart, ipEnd)
	for _, ipStr := range res {
		fmt.Printf("%s", ipStr)
	}
}

func TestIPRangeToCidrList(t *testing.T) {
	ipb, err := common.IPBlockFromIPRangeStr("192.168.1.0-192.168.1.9")
	//ipb, err := IPBlockFromIPRangeStr("0.0.0.0-255.255.255.255")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	cidrList := ipb.ToCidrList()
	for _, ipStr := range cidrList {
		fmt.Printf("%s", ipStr)
	}
}

//go:embed other_examples/resources.json
var r1 []byte

func TestParseResources(t *testing.T) {
	ParseResources(r1)
}

func TestNewVpcConfig(t *testing.T) {
	resources := ParseResources(r1)
	vpcConfig, err := NewVpcConfig(resources)
	fmt.Printf("%s", vpcConfig.details())
	if err != nil {
		fmt.Printf("error: %v", err)
	}
	analyzeConnectivity(vpcConfig)

}
