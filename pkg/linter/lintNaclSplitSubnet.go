package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

type naclSplitSubnet struct {
	basicLinter
	finding []splitSubnet
}

type splitSubnet struct {
	nacl   int
	rule   int
	subnet *vpcmodel.Subnet
	cidrs  []string
}

func (lint *naclSplitSubnet) check() []string {
	// todo getFilterTrafficResourceOfKind from vpcmodel needs to be exported
	return []string{"test1", "test2", "test3"}
}

func (lint *naclSplitSubnet) getName() string {
	return "naclSplitSubnet"
}

func (lint *naclSplitSubnet) getFindings() []any {
	return nil
}
