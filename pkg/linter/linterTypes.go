package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

type linter interface {
	check() []string // returns []string of size 0 if no lint issues
	getName() string
	getFindings() []any
}

type basicLinter struct {
	config *vpcmodel.VPCConfig
}
