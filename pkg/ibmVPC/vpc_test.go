package ibmvpc

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

/*
old test:
//go:embed examples/sg_testing1.json
var inputResources []byte
*/

//go:embed examples/sg_testing1_new.json
var inputResources1 []byte

//go:embed examples/acl_testing3.json
var inputResources2 []byte

func TestWithParsing(t *testing.T) {
	rc, err := ParseResources(inputResources2)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	cloudConfig, err := NewCloudConfig(rc)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	fmt.Println("nodes in the vpc config:")
	for _, n := range cloudConfig.Nodes {
		fmt.Printf("%s %s\n", n.Name(), n.Cidr())
	}
	vpcConn := cloudConfig.GetVPCNetworkConnectivity()
	actualOutput := vpcConn.String()
	fmt.Printf("%s", actualOutput)
	fmt.Println("done")
	return
	// check output
	generateActualOutput := false
	currentDir, _ := os.Getwd()
	expectedOutputFile := filepath.Join(currentDir, "examples", "TestWithParsing.txt")
	if generateActualOutput {
		// update expected output: override expected output with actual output
		if err = os.WriteFile(expectedOutputFile, []byte(actualOutput), 0o600); err != nil {
			t.Fatalf("TestWithParsing WriteFile err: %v", err)
		}
	} else {
		// compare actual output to expected output
		expectedStr, err := os.ReadFile(expectedOutputFile)
		if err != nil {
			t.Fatalf("TestWithParsing:  ReadFile err: %v", err)
		}
		if string(expectedStr) != actualOutput {
			fmt.Printf("%s", actualOutput)
			t.Fatalf("TestWithParsing unexpected output result ")
		}
	}
}

/*func TestExampleBasicFromAPImanual(t *testing.T) {
	// additional attributes per VPC to consider: region / zone/ default_network_acl /
	default_routing_table / default_security_group /id / resource_group
	vpc := VPC{name: "test-vpc1-ky"} // should fill in nodes, and connectivityRules? / cidr?

	subnets := []Subnet{ // should fill in nodes, and connectivityRules?
		{name: "pub-subnet-ky", cidr: "10.240.10.0/24"},
	}

	nifList := []NetworkInterface{
		{
			//name: "",
			cidr: "",
		},
	}
	fmt.Printf("%v", vpc)
	fmt.Printf("%v", subnets)
	fmt.Printf("%v", nifList)
}*/

/*
func TestVPC(t *testing.T) {
	vpc1 := NewVPC("VPC1", "", "Region A")
	fmt.Printf("%v", vpc1)
	zone1 := NewZone("zone1", "10.10.0.0/18", vpc1)
	zone2 := NewZone("zone2", "10.20.0.0/18", vpc1)
	subnet1 := NewSubnet("subnet1", "10.10.10.0/24", zone1.(*zone))
	subnet2 := NewSubnet("subnet2", "10.10.20.0/24", zone1.(*zone))
	subnet3 := NewSubnet("subnet3", "10.20.30.0/24", zone2.(*zone))
	subnet4 := NewSubnet("subnet4", "10.20.40.0/24", zone2.(*zone))

	fmt.Printf("%v", zone1)
	fmt.Printf("%v", zone2)
	fmt.Printf("%v", subnet1)
	fmt.Printf("%v", subnet2)
	fmt.Printf("%v", subnet3)
	fmt.Printf("%v", subnet4)
	nwintf1 := NewNwInterface("intf1", "10.10.10.5", subnet1)
	nwintf2 := NewNwInterface("intf2", "10.10.10.6", subnet1)
	vsi1 := NewVSI("vsi1", []*NWInterface{nwintf1.(*NWInterface)}, zone1.(*zone))
	vsi2 := NewVSI("vsi2", []*NWInterface{nwintf2.(*NWInterface)}, zone1.(*zone))
	fmt.Printf("%v", vsi1)
	fmt.Printf("%v", vsi2)
}
*/
