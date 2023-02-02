package resources

import (
	_ "embed"
	"fmt"
	"os"
	"strings"
	"testing"
)

//go:embed nwacl_1.json
var nwacl1 []byte

//go:embed nwacl_2.json
var nwacl2 []byte

//go:embed nwacl_3.json
var nwacl3 []byte

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

func getDisjointPeers(rules []*Rule, subnet *IPBlock) []*IPBlock {
	peers := []*IPBlock{subnet}
	for _, rule := range rules {
		peers = append(peers, rule.src)
		peers = append(peers, rule.dst)
	}
	return DisjointIPBlocks(peers, []*IPBlock{subnet})
}

func TestGetAllowedIngressConnections(t *testing.T) {
	// sets of ingress rules to test with
	rulesTest1 := []*Rule{
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

	subnet := NewIPBlockFromCidr("10.0.0.0/24")
	disjointPeers := getDisjointPeers(rulesTest1, subnet)

	res := []string{}
	for _, src := range disjointPeers {
		allowedIngressConns := getAllowedIngressConnections(rulesTest1, src, subnet, disjointPeers)
		for dst, conn := range allowedIngressConns {
			res = append(res, fmt.Sprintf("%s => %s : %s\n", src.ToIPRanges(), dst, conn.String()))
		}
	}
	fmt.Printf("%s", strings.Join(res, "\n"))
}
