/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

type linter interface {
	check() error
	getFindings() []finding        // returns all findings detected by the linter
	addFinding(f finding)          // add a single finding
	lintName() string              // this lint Name
	lintDescription() string       // this string Name
	string(lintDesc string) string // string with this lint's finding
	toJSON() []any                 // this lint finding in JSON
	enableByDefault() bool         //
}

type finding interface {
	vpc() []vpcmodel.VPCResourceIntf
	string() string
	toJSON() any
}

type basicLinter struct {
	configs     map[string]*vpcmodel.VPCConfig
	findings    []finding
	name        string
	description string
	enable      bool
}

type connectionLinter struct {
	basicLinter
	nodesConn map[string]*vpcmodel.VPCConnectivity
}

func (lint *basicLinter) lintName() string {
	return lint.name
}

func (lint *basicLinter) lintDescription() string {
	return lint.description
}

func (lint *basicLinter) addFinding(f finding) {
	lint.findings = append(lint.findings, f)
}
func (lint *basicLinter) addFindings(f []finding) {
	lint.findings = append(lint.findings, f...)
}

func (lint *basicLinter) getFindings() []finding {
	return lint.findings
}

func (lint *basicLinter) enableByDefault() bool {
	return lint.enable
}

func (lint *basicLinter) string(lintDesc string) string {
	findingsRes := make([]string, len(lint.findings))
	for i, thisFinding := range lint.findings {
		findingsRes[i] = thisFinding.string()
	}
	sort.Strings(findingsRes)
	header := fmt.Sprintf("%q %s\n", lintDesc, issues) +
		strings.Repeat("~", len(lintDesc)+len(issues)+3) + "\n"
	return header + strings.Join(findingsRes, "\n")
}

func (lint *basicLinter) toJSON() []any {
	res := make([]any, len(lint.findings))
	for i, thisFinding := range lint.findings {
		res[i] = thisFinding.toJSON()
	}
	return res
}

type filterLinter struct {
	basicLinter
	layer          string
	checkForFilter func(map[string]*vpcmodel.VPCConfig, string) ([]finding, error)
}

func (fLint *filterLinter) check() error {
	findings, err := fLint.checkForFilter(fLint.configs, fLint.layer)
	if err != nil {
		return err
	}
	fLint.addFindings(findings)
	return nil
}
