package resources

import (
	_ "embed"
	"fmt"
	"os"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
)

//go:embed nwacl_1.json
var nwacl1 []byte

//go:embed nwacl_2.json
var nwacl2 []byte

//go:embed nwacl_3.json
var nwacl3 []byte

//go:embed sg_1.json
var sg1 []byte

//go:embed sg_2.json
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

func TestNaclJsonUnmarshal(t *testing.T) {
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
}

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
	subnet, _ := NewIPBlock("10.0.0.0/24", []string{})
	AnalyzeNACL(naclObj, subnet)
}

func getTCPconn(startPort int64, endPort int64) *ConnectionSet {
	res := MakeConnectionSet(false)
	ports := PortSet{Ports: CanonicalIntervalSet{IntervalSet: []Interval{{Start: startPort, End: endPort}}}}
	res.AddConnection(v1.ProtocolTCP, ports)
	return &res
}

func TestGetAllowedIngressConnections(t *testing.T) {
	// sets of ingress rules to test with
	rulesTest1 := []*NACLRule{
		{
			src:         NewIPBlockFromCidr("1.2.3.4/32"),
			dst:         NewIPBlockFromCidr("10.0.0.1/32"),
			connections: getAllConnSet(),
			action:      "deny",
		},
		{
			src:         NewIPBlockFromCidr("0.0.0.0/0"),
			dst:         NewIPBlockFromCidr("0.0.0.0/0"),
			connections: getAllConnSet(),
			action:      "allow",
		},
	}

	rulesTest2 := []*NACLRule{
		{
			src:         NewIPBlockFromCidr("1.2.3.4/32"),
			dst:         NewIPBlockFromCidr("10.0.0.1/32"),
			connections: getTCPconn(80, 80),
			action:      "allow",
		},
		{
			src:         NewIPBlockFromCidr("1.2.3.4/32"),
			dst:         NewIPBlockFromCidr("10.0.0.1/32"),
			connections: getTCPconn(1, 100),
			action:      "deny",
		},
		{
			src:         NewIPBlockFromCidr("0.0.0.0/0"),
			dst:         NewIPBlockFromCidr("0.0.0.0/0"),
			connections: getAllConnSet(),
			action:      "allow",
		},
	}

	rulesTest3 := []*NACLRule{
		{
			dst:         NewIPBlockFromCidr("1.2.3.4/32"),
			src:         NewIPBlockFromCidr("10.0.0.1/32"),
			connections: getAllConnSet(),
			action:      "deny",
		},
		{
			dst:         NewIPBlockFromCidr("0.0.0.0/0"),
			src:         NewIPBlockFromCidr("0.0.0.0/0"),
			connections: getAllConnSet(),
			action:      "allow",
		},
	}

	subnet := NewIPBlockFromCidr("10.0.0.0/24")

	//res1 := ingressConnResFromInput(rulesTest1, subnet)
	res1 := AnalyzeNACLRules(rulesTest1, subnet, true)
	fmt.Printf("res for test %s:\n%s\n", "rulesTest1", res1)

	//res2 := ingressConnResFromInput(rulesTest2, subnet)
	res2 := AnalyzeNACLRules(rulesTest2, subnet, true)
	fmt.Printf("res for test %s:\n%s\n", "rulesTest2", res2)

	res3 := AnalyzeNACLRules(rulesTest3, subnet, false)
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
