package ibmvpc

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// getConfigs returns  map[string]*vpcmodel.VPCConfig obj for the input test (config json file)
func getConfig(t *testing.T, fileName string) *vpcmodel.VPCConfig {
	inputConfigFile := filepath.Join(getTestsDir(), fileName+".json")
	rc, err := ParseResourcesFromFile(inputConfigFile)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	vpcConfigs, err := VPCConfigsFromResources(rc, "", false)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	for _, vpcConfig := range vpcConfigs {
		return vpcConfig
	}
	return nil
}

type explainGeneralTest struct {
	name        string // test name
	inputConfig string // name (relative path) of input config file (json)
	ESrc        string
	EDst        string
	EProtocol   common.ProtocolStr
	ESrcMinPort int64
	ESrcMaxPort int64
	EDstMinPort int64
	EDstMaxPort int64
	out         string
}

var explainTests = []*explainGeneralTest{
	{
		name:        "VsiToVsi1",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi2-ky[10.240.20.4]",
		EDst:        "vsi3b-ky[10.240.30.4]",
		out: "The following connection exists between vsi2-ky[10.240.20.4] and vsi3b-ky[10.240.30.4]: protocol: TCP; " +
			"its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl2-ky:\n" +
			"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg2-ky:\n\tindex: 5, direction: outbound, protocol: all, cidr: 10.240.30.0/24\n" +
			"\tindex: 6, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 10.240.20.4/32,10.240.30.4/32\nIngress Rules:\n" +
			"~~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl3-ky:\n" +
			"\tindex: 1, direction: inbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg2-ky:\n" +
			"\tindex: 7, direction: inbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 10.240.20.4/32,10.240.30.4/32\n\n",
	},
	{
		name:        "VsiToVsi2",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi2-ky[10.240.20.4]",
		EDst:        "vsi1-ky[10.240.10.4]",
		out: "The following connection exists between vsi2-ky[10.240.20.4] and vsi1-ky[10.240.10.4]: " +
			"All Connections; its enabled by\n" +
			"Egress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl2-ky:\n" +
			"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg2-ky:\n\tindex: 1, direction: outbound, protocol: all, cidr: 10.240.10.0/24\n" +
			"Ingress Rules:\n~~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n" +
			"\tindex: 1, direction: inbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, " +
			"action: allow\nSecurityGroupLayer Rules\n------------------------\n" +
			"enabling rules from sg1-ky:\n\tindex: 3, direction: inbound, protocol: all, cidr: 10.240.20.4/32,10.240.30.4/32\n\n",
	},
	{
		name:        "VsiToVsi3",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi1-ky[10.240.10.4]",
		out: "The following connection exists between vsi3a-ky[10.240.30.5] and vsi1-ky[10.240.10.4]: " +
			"All Connections; its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\n" +
			"enabling rules from acl3-ky:\n\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\n" +
			"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg3-ky:\n" +
			"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n" +
			"\tindex: 2, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 0.0.0.0/0\n" +
			"\tindex: 3, direction: outbound,  conns: protocol: tcp,  dstPorts: 100-200, cidr: 0.0.0.0/0\n" +
			"Ingress Rules:\n~~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n" +
			"\tindex: 1, direction: inbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg1-ky:\n\tindex: 4, direction: inbound, " +
			"protocol: all, cidr: 10.240.30.5/32,10.240.30.6/32\n\n",
	},
	{
		name:        "VsiToVsi4",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "vsi2-ky[10.240.20.4]",
		out: "No connection between vsi1-ky[10.240.10.4] and vsi2-ky[10.240.20.4]; connection blocked by egress\nIngress Rules:\n" +
			"~~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl2-ky:\n" +
			"\tindex: 1, direction: inbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\n" +
			"SecurityGroupLayer Rules\n------------------------\n" +
			"enabling rules from sg2-ky:\n\tindex: 4, direction: inbound, protocol: all, cidr: 10.240.10.4/32\n\n",
	},
	{
		name:        "VsiToVsi5",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi2-ky[10.240.20.4]",
		out: "No connection between vsi3a-ky[10.240.30.5] and vsi2-ky[10.240.20.4]; " +
			"connection blocked by ingress\nEgress Rules:\n~~~~~~~~~~~~~\n" +
			"NaclLayer Rules\n------------------------\nenabling rules from acl3-ky:\n" +
			"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\n" +
			"SecurityGroupLayer Rules\n------------------------\n" +
			"enabling rules from sg3-ky:\n\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n" +
			"\tindex: 2, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 0.0.0.0/0\n" +
			"\tindex: 3, direction: outbound,  conns: protocol: tcp,  dstPorts: 100-200, cidr: 0.0.0.0/0\n\n",
	},
	{
		name:        "SimpleExternalSG1",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/16",
		out: "The following connection exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16: " +
			"protocol: UDP; its enabled by\nExternal Router PublicGateway: public-gw-ky\nEgress Rules:\n" +
			"~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n" +
			"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg1-ky:\n" +
			"\tindex: 2, direction: outbound,  conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n",
	},
	{
		name:        "SimpleExternalSG2",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "161.26.0.0/16",
		EDst:        "vsi1-ky[10.240.10.4]",
		out: "No connection between Public Internet 161.26.0.0/16 and vsi1-ky[10.240.10.4]; " +
			"no fip router and src is external (fip is required for outbound external connection)\n\n",
	},
	{
		name:        "SimpleExternalSG3",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/32",
		out: "The following connection exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/32: " +
			"protocol: UDP; its enabled by\nExternal Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\n" +
			"NaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n" +
			"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg1-ky:\n\tindex: 2, direction: outbound,  " +
			"conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n",
	},
	{
		name:        "SimpleExternalSG4",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi3b-ky[10.240.30.4]",
		EDst:        "161.26.0.0/32",
		out: "No connection between vsi3b-ky[10.240.30.4] and Public Internet 161.26.0.0/32; " +
			"no router (fip/pgw) and dst is external\n\n",
	},
	{
		name:        "GroupingExternalSG1",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/8",
		out: "No connection between vsi1-ky[10.240.10.4] and Public Internet 161.0.0.0-161.25.255.255,161.27.0.0-161.255.255.255; " +
			"connection blocked by egress\n\nThe following connection exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16: " +
			"protocol: UDP; its enabled by\nExternal Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n" +
			"------------------------\nenabling rules from acl1-ky:\n" +
			"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg1-ky:\n" +
			"\tindex: 2, direction: outbound,  conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n",
	},
	//todo: now that external and internal IPs are treated differently, deffer cidrAll test to the time we properly support internal IP #305
	/*{
		name:        "GroupingExternalSG2",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi2-ky[10.240.20.4]",
		EDst:        "0.0.0.0/0",
		out: "No connection between vsi2-ky[10.240.20.4] and Public Internet 0.0.0.0-141.255.255.255,143.0.0.0-255.255.255.255; " +
			"connection blocked by egress\n\n" +
			"The following connection exists between vsi2-ky[10.240.20.4] and Public Internet 142.0.0.0/8: protocol: ICMP; its enabled by\n" +
			"Egress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg2-ky:\n" +
			"\tindex: 3, direction: outbound,  conns: protocol: icmp,  icmpType: protocol: ICMP, cidr: 142.0.0.0/8\n\n",
	},
	{
		name:        "GroupingExternalSG3",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "0.0.0.0/0",
		EDst:        "vsi2-ky[10.240.20.4]",
		out: "No connection between vsi2-ky[10.240.20.4] and Public Internet 0.0.0.0-141.255.255.255,143.0.0.0-255.255.255.255; " +
			"connection blocked by egress\n\nThe following connection exists between vsi2-ky[10.240.20.4] " +
			"and Public Internet 142.0.0.0/8: protocol: ICMP; its enabled by\nEgress Rules:\n" +
			"~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg2-ky:\n\t" +
			"index: 3, direction: outbound,  conns: protocol: icmp,  icmpType: protocol: ICMP, cidr: 142.0.0.0/8\n\n",
	},*/
	{
		// the existing connection is exactly the one required by the query
		name:        "QueryConnectionSGBasic1",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/16",
		EProtocol:   common.ProtocolUDP,
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
		out: "Connection protocol: UDP exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16; its enabled by\n" +
			"External Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\n" +
			"enabling rules from acl1-ky:\n\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, " +
			"conn: all, action: allow\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg1-ky:\n\tindex: 2, direction: outbound,  " +
			"conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n",
	},
	// the required connection is contained in the existing one per connection
	{
		name:        "QueryConnectionSGBasic2",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/16",
		EProtocol:   common.ProtocolUDP,
		ESrcMinPort: 10,
		ESrcMaxPort: 100,
		EDstMinPort: 443,
		EDstMaxPort: 443,
		out: "Connection protocol: UDP src-ports: 10-100 dst-ports: 443 exists between vsi1-ky[10.240.10.4] and " +
			"Public Internet 161.26.0.0/16; its enabled by\nExternal Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\n" +
			"NaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n" +
			"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg1-ky:\n\tindex: 2, direction: outbound,  " +
			"conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n",
	},
	//  the required connection is contained in the existing one per ip of src/dst
	{
		name:        "QueryConnectionSGBasic3",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/20",
		EProtocol:   common.ProtocolUDP,
		ESrcMinPort: 10,
		ESrcMaxPort: 100,
		EDstMinPort: 443,
		EDstMaxPort: 443,
		out: "Connection protocol: UDP src-ports: 10-100 dst-ports: 443 exists between vsi1-ky[10.240.10.4] and " +
			"Public Internet 161.26.0.0/20; its enabled by\nExternal Router PublicGateway: public-gw-ky\n" +
			"Egress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n" +
			"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg1-ky:\n\tindex: 2, direction: outbound,  " +
			"conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n",
	},
	// the required connection exists for part of the dst ip
	{
		name:        "QueryConnectionSGBasic4",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/12",
		EProtocol:   common.ProtocolUDP,
		ESrcMinPort: 10,
		ESrcMaxPort: 100,
		EDstMinPort: 443,
		EDstMaxPort: 443,
		out: "Connection protocol: UDP src-ports: 10-100 dst-ports: 443 exists between vsi1-ky[10.240.10.4] and " +
			"Public Internet 161.26.0.0/16; its enabled by\nExternal Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\n" +
			"NaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n\t" +
			"index: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\n" +
			"SecurityGroupLayer Rules\n------------------------\n" +
			"enabling rules from sg1-ky:\n\t" +
			"index: 2, direction: outbound,  conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\nThere is no connection \"" +
			"protocol: UDP src-ports: 10-100 dst-ports: 443\" between vsi1-ky[10.240.10.4] and " +
			"Public Internet 161.16.0.0-161.25.255.255,161.27.0.0-161.31.255.255; " +
			"connection blocked by egress\n\n",
	},
	// a connection does not exist regardless of the query
	{
		name:        "QueryConnectionSGBasic5",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "vsi3a-ky[10.240.30.5]",
		EProtocol:   common.ProtocolUDP,
		ESrcMinPort: 10,
		ESrcMaxPort: 100,
		EDstMinPort: 443,
		EDstMaxPort: 443,
		out: "There is no connection \"protocol: UDP src-ports: 10-100 dst-ports: 443\" " +
			"between vsi1-ky[10.240.10.4] and vsi3a-ky[10.240.30.5]; " +
			"connection blocked both by ingress and egress\n\n",
	},
	// a subset of the required ports exists
	{
		name:        "QueryConnectionSGSubsetPorts",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "147.235.219.206/32",
		EDst:        "vsi2-ky[10.240.20.4]",
		EProtocol:   common.ProtocolTCP,
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: 10,
		EDstMaxPort: 30,
		out: "Connection protocol: TCP dst-ports: 22 exists between Public Internet 147.235.219.206/32 and vsi2-ky[10.240.20.4]; " +
			"its enabled by\nExternal Router FloatingIP: floating-ip-ky\nIngress Rules:\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg2-ky:\n" +
			"\tindex: 2, direction: inbound,  conns: protocol: tcp,  dstPorts: 22-22, cidr: 147.235.219.206/32\n\n",
	},
	//  all rules are relevant (for comparison)
	{
		name:        "QueryConnectionSGRules1",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi1-ky[10.240.10.4]",
		out: "The following connection exists between vsi3a-ky[10.240.30.5] " +
			"and vsi1-ky[10.240.10.4]: All Connections; its enabled by\n" +
			"Egress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl3-ky:\n" +
			"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\n" +
			"SecurityGroupLayer Rules\n------------------------\n" +
			"enabling rules from sg3-ky:\n\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n" +
			"\tindex: 2, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 0.0.0.0/0\n" +
			"\tindex: 3, direction: outbound,  conns: protocol: tcp,  dstPorts: 100-200, cidr: 0.0.0.0/0\nIngress Rules:\n~~~~~~~~~~~~~~\n" +
			"NaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n" +
			"\tindex: 1, direction: inbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg1-ky:\n\tindex: 4, direction: inbound, " +
			"protocol: all, cidr: 10.240.30.5/32,10.240.30.6/32\n\n",
	},
	// only a subset of the rules are relevant, protocol wise
	{
		name:        "QueryConnectionSGRules2",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi1-ky[10.240.10.4]",
		EProtocol:   common.ProtocolUDP,
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
		out: "Connection protocol: UDP exists between vsi3a-ky[10.240.30.5] and vsi1-ky[10.240.10.4]; its enabled by\n" +
			"Egress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl3-ky:\n" +
			"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\n" +
			"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg3-ky:\n" +
			"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\nIngress Rules:\n~~~~~~~~~~~~~~\n" +
			"NaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n" +
			"\tindex: 1, direction: inbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg1-ky:\n\tindex: 4, direction: inbound, " +
			"protocol: all, cidr: 10.240.30.5/32,10.240.30.6/32\n\n",
	},
	// only a subset of the rules are relevant, port wise and protocol wise
	{
		name:        "QueryConnectionSGRules3",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi1-ky[10.240.10.4]",
		EProtocol:   common.ProtocolTCP,
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: 50,
		EDstMaxPort: 54,
		out: "Connection protocol: TCP dst-ports: 50-54 exists between vsi3a-ky[10.240.30.5] " +
			"and vsi1-ky[10.240.10.4]; its enabled by\n" +
			"Egress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl3-ky:\n\t" +
			"index: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\n" +
			"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg3-ky:\n\t" +
			"index: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n\t" +
			"index: 2, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 0.0.0.0/0\nIngress Rules:\n~~~~~~~~~~~~~~\n" +
			"NaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n" +
			"\tindex: 1, direction: inbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\n" +
			"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n" +
			"\tindex: 4, direction: inbound, protocol: all, cidr: 10.240.30.5/32,10.240.30.6/32\n\n",
	},
	//  all rules are relevant, with specified port wise protocol
	{
		name:        "QueryConnectionSGRules4",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi1-ky[10.240.10.4]",
		EProtocol:   common.ProtocolTCP,
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: 120,
		EDstMaxPort: 230,
		out: "Connection protocol: TCP dst-ports: 120-230 exists between vsi3a-ky[10.240.30.5] " +
			"and vsi1-ky[10.240.10.4]; its enabled by\n" +
			"Egress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl3-ky:\n" +
			"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg3-ky:\n\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n" +
			"\tindex: 2, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 0.0.0.0/0\n" +
			"\tindex: 3, direction: outbound,  conns: protocol: tcp,  dstPorts: 100-200, cidr: 0.0.0.0/0\nIngress Rules:\n~~~~~~~~~~~~~~\n" +
			"NaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n" +
			"\tindex: 1, direction: inbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg1-ky:\n\tindex: 4, direction: inbound, " +
			"protocol: all, cidr: 10.240.30.5/32,10.240.30.6/32\n\n",
	},
	// connection exists to external
	{
		name:        "NACLExternal1",
		inputConfig: "input_acl_testing3",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/16",
		out: "The following connection exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16: protocol: UDP; " +
			"its enabled by\nExternal Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\n" +
			"NaclLayer Rules\n------------------------\n" +
			"enabling rules from acl1-ky:\n\tindex: 1, direction: outbound , src: 10.240.10.0/24 , dst: 161.26.0.0/16, conn: protocol: udp, " +
			"srcPorts: 1-65535, dstPorts: 1-65535, action: allow\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg1-ky:\n" +
			"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n\n",
	},
	//// connection does not exist to external, blocked by egress
	{
		name:        "NACLExternal2",
		inputConfig: "input_acl_testing3",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "100.128.0.0/32",
		out: "No connection between vsi1-ky[10.240.10.4] and Public Internet 100.128.0.0/32;" +
			" connection blocked by egress\n\n",
	},
	// connection does not exist to external, no fip router
	{
		name:        "NACLExternal3",
		inputConfig: "input_acl_testing3",
		ESrc:        "100.128.0.0/32",
		EDst:        "vsi1-ky[10.240.10.4]",
		out: "No connection between Public Internet 100.128.0.0/32 and vsi1-ky[10.240.10.4]; no fip router and src is external" +
			" (fip is required for outbound external connection)\n\n",
	},
	// todo: add unit test that simulates merging rules when there is more than one nacl table
	{
		// todo: misleading since deny not supported yet
		name:        "NACLInternal1",
		inputConfig: "input_acl_testing3",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "vsi2-ky[10.240.20.4]",
		out: "The following connection exists between vsi1-ky[10.240.10.4] and vsi2-ky[10.240.20.4]: " +
			"protocol: TCP,UDP; its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\n" +
			"enabling rules from acl1-ky:\n\tindex: 0, direction: outbound , src: 10.240.10.0/24 , dst: 10.240.20.0/24, conn: protocol: icmp, action: deny\n" +
			"\tindex: 2, direction: outbound , src: 10.240.10.0/24 , dst: 10.240.20.0/24, conn: all, action: allow\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg1-ky:\n\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n" +
			"Ingress Rules:\n~~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl2-ky:\n" +
			"\tindex: 6, direction: inbound , src: 10.240.10.0/24 , dst: 10.240.20.0/24, " +
			"conn: all, action: allow\nSecurityGroupLayer Rules\n------------------------\n" +
			"enabling rules from sg1-ky:\n\tindex: 1, direction: inbound, protocol: all, cidr: 0.0.0.0/0\n\n",
	},
	//{
	//	name:        "NACLInternal2",
	//	inputConfig: "input_acl_testing3",
	//	ESrc:        "vsi2-ky[10.240.20.4]",
	//	EDst:        "vsi1-ky[10.240.10.4]",
	//	out: "The following connection exists between vsi2-ky[10.240.20.4] and vsi1-ky[10.240.10.4]: " +
	//		"All Connections; its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\n" +
	//		"enabling rules from acl2-ky:\n\tindex: 2, direction: outbound , src: 10.240.20.0/24 , dst: 10.240.10.0/24, " +
	//		"conn: all, action: allow\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n" +
	//		"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\nIngress Rules:\n~~~~~~~~~~~~~~\n" +
	//		"NaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n" +
	//		"\tindex: 4, direction: inbound , src: 10.240.20.0/24 , dst: 10.240.10.0/24, conn: all, action: allow\n" +
	//		"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n" +
	//		"\tindex: 1, direction: inbound, protocol: all, cidr: 0.0.0.0/0\n\n",
	//},
	//{
	//	name:        "NACLInternal3",
	//	inputConfig: "input_acl_testing3",
	//	ESrc:        "vsi1-ky[10.240.10.4]",
	//	EDst:        "vsi3a-ky[10.240.30.5]",
	//	out: "No connection between vsi1-ky[10.240.10.4] and vsi3a-ky[10.240.30.5]; connection blocked by egress\nIngress Rules:\n" +
	//		"~~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl3-ky:\n" +
	//		"\tindex: 2, direction: inbound , src: 10.240.10.0/24 , dst: 0.0.0.0/0, conn: all, action: allow\n" +
	//		"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n" +
	//		"\tindex: 1, direction: inbound, protocol: all, cidr: 0.0.0.0/0\n\n",
	//},
	//{
	//	// same subnet: no actual rules in nacl, but connection enabled
	//	name:        "NACLInternal4",
	//	inputConfig: "input_acl_testing3",
	//	ESrc:        "vsi3b-ky[10.240.30.6]",
	//	EDst:        "vsi3a-ky[10.240.30.5]",
	//	out: "The following connection exists between vsi3b-ky[10.240.30.6] and vsi3a-ky[10.240.30.5]: " +
	//		"All Connections; its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\n" +
	//		"enabling rules from sg1-ky:\n" +
	//		"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\nIngress Rules:\n~~~~~~~~~~~~~~\n" +
	//		"SecurityGroupLayer Rules\n------------------------\n" +
	//		"enabling rules from sg1-ky:\n\tindex: 1, direction: inbound, protocol: all, cidr: 0.0.0.0/0\n\n",
	//},
	//{
	//	name:        "NACLGrouping",
	//	inputConfig: "input_acl_testing3",
	//	ESrc:        "vsi1-ky[10.240.10.4]",
	//	EDst:        "161.26.0.0/15",
	//	out: "No connection between vsi1-ky[10.240.10.4] and Public Internet 161.27.0.0/16; connection blocked by egress\n\n" +
	//		"The following connection exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16: protocol: UDP; " +
	//		"its enabled by\nExternal Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\n" +
	//		"NaclLayer Rules\n------------------------\n" +
	//		"enabling rules from acl1-ky:\n\tindex: 1, direction: outbound , src: 10.240.10.0/24 , dst: 161.26.0.0/16, conn: protocol: udp, " +
	//		"srcPorts: 1-65535, dstPorts: 1-65535, action: allow\n" +
	//		"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n" +
	//		"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n\n",
	//},
	//{
	//	name:        "NACLQueryConnection1",
	//	inputConfig: "input_acl_testing3",
	//	ESrc:        "vsi1-ky[10.240.10.4]",
	//	EDst:        "161.26.0.0/16",
	//	EProtocol:   common.ProtocolUDP,
	//	ESrcMinPort: common.MinPort,
	//	ESrcMaxPort: common.MaxPort,
	//	EDstMinPort: common.MinPort,
	//	EDstMaxPort: common.MaxPort,
	//	out: "Connection protocol: UDP exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16; " +
	//		"its enabled by\nExternal Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n" +
	//		"------------------------\nenabling rules from acl1-ky:\n" +
	//		"\tindex: 1, direction: outbound , src: 10.240.10.0/24 , dst: 161.26.0.0/16, conn: " +
	//		"protocol: udp, srcPorts: 1-65535, dstPorts: 1-65535, " +
	//		"action: allow\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n\tindex: 0, direction: outbound, " +
	//		"protocol: all, cidr: 0.0.0.0/0\n\n",
	//},
	//{
	//	name:        "NACLQueryConnection2",
	//	inputConfig: "input_acl_testing3",
	//	ESrc:        "vsi1-ky[10.240.10.4]",
	//	EDst:        "161.26.0.0/16",
	//	EProtocol:   common.ProtocolTCP,
	//	ESrcMinPort: common.MinPort,
	//	ESrcMaxPort: common.MaxPort,
	//	EDstMinPort: common.MinPort,
	//	EDstMaxPort: common.MaxPort,
	//	out: "There is no connection \"protocol: TCP\" between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16; " +
	//		"connection blocked by egress\n\n",
	//},
	//// all rules
	//{
	//	name:        "NACLQueryConnectionRules2",
	//	inputConfig: "input_acl_testing3_3rd",
	//	ESrc:        "vsi1-ky[10.240.10.4]",
	//	EDst:        "161.26.0.0/16",
	//	out: "The following connection exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16: " +
	//		"All Connections; its enabled by\nExternal Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n" +
	//		"------------------------\nenabling rules from acl1-ky:\n" +
	//		"\tindex: 1, direction: outbound , src: 10.240.10.0/24 , dst: 161.26.0.0/16, " +
	//		"conn: protocol: udp, srcPorts: 1-65535, dstPorts: 1-65535, action: allow\n" +
	//		"\tindex: 2, direction: outbound , src: 10.240.10.0/24 , dst: 161.26.0.0/16, conn: all, action: allow\n" +
	//		"SecurityGroupLayer Rules\n------------------------\n" +
	//		"enabling rules from sg1-ky:\n\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n\n",
	//},
	//// without the udp rule
	//{
	//	name:        "NACLQueryConnectionRules2",
	//	inputConfig: "input_acl_testing3_3rd",
	//	ESrc:        "vsi1-ky[10.240.10.4]",
	//	EDst:        "161.26.0.0/16",
	//	EProtocol:   common.ProtocolTCP,
	//	ESrcMinPort: common.MinPort,
	//	ESrcMaxPort: common.MaxPort,
	//	EDstMinPort: common.MinPort,
	//	EDstMaxPort: common.MaxPort,
	//	out: "Connection protocol: TCP exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16; its enabled by\n" +
	//		"External Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\n" +
	//		"enabling rules from acl1-ky:\n\t" +
	//		"index: 2, direction: outbound , src: 10.240.10.0/24 , dst: 161.26.0.0/16, conn: all, action: allow\n" +
	//		"SecurityGroupLayer Rules\n------------------------\n" +
	//		"enabling rules from sg1-ky:\n\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n\n",
	//},
	//// without the "all" rule since udp rule has higher priority
	//{
	//	name:        "NACLQueryConnectionRules2",
	//	inputConfig: "input_acl_testing3_3rd",
	//	ESrc:        "vsi1-ky[10.240.10.4]",
	//	EDst:        "161.26.0.0/16",
	//	EProtocol:   common.ProtocolUDP,
	//	ESrcMinPort: common.MinPort,
	//	ESrcMaxPort: common.MaxPort,
	//	EDstMinPort: common.MinPort,
	//	EDstMaxPort: common.MaxPort,
	//	out: "Connection protocol: UDP exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16; " +
	//		"its enabled by\nExternal Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\n" +
	//		"NaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n" +
	//		"\tindex: 1, direction: outbound , src: 10.240.10.0/24 , dst: 161.26.0.0/16, conn: protocol: udp, " +
	//		"srcPorts: 1-65535, dstPorts: 1-65535, action: allow\n" +
	//		"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n" +
	//		"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n\n",
	//},
}

func TestAll(t *testing.T) {
	// explainTests is the list of tests to run
	for testIdx := range explainTests {
		tt := explainTests[testIdx]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.runTest(t)
		})
	}
	fmt.Println("done")
}

func (tt *explainGeneralTest) runTest(t *testing.T) {
	// get vpcConfigs obj from parsing + analyzing input config file
	vpcConfig := getConfig(t, tt.inputConfig)
	explanationArgs := vpcmodel.NewExplanationArgs(tt.ESrc, tt.EDst, string(tt.EProtocol),
		tt.ESrcMinPort, tt.ESrcMaxPort, tt.EDstMinPort, tt.EDstMaxPort)
	connQuery := explanationArgs.GetConnectionSet()
	explanation, err := vpcConfig.ExplainConnectivity(explanationArgs.Src(), explanationArgs.Dst(), connQuery)
	if err != nil {
		require.Fail(t, err.Error())
	}
	require.Equal(t, tt.out, explanation.String())
}

func TestInputValidity(t *testing.T) {
	vpcConfig := getConfig(t, "input_sg_testing1_new")
	if vpcConfig == nil {
		require.Fail(t, "vpcConfig equals nil")
	}
	cidr1 := "0.0.0.0/0"
	cidr2 := "161.26.0.0/16"
	nonExistingVSI := "vsi2-ky[10.240.10.4]"
	_, err1 := vpcConfig.ExplainConnectivity(cidr1, cidr2, nil)
	fmt.Println(err1.Error())
	if err1 == nil {
		require.Fail(t, err1.Error())
	}
	_, err2 := vpcConfig.ExplainConnectivity(cidr1, nonExistingVSI, nil)
	fmt.Println(err2.Error())
	if err2 == nil {
		require.Fail(t, err1.Error())
	}
}
