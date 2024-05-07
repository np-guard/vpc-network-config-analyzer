/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

// InArgs contains the input arguments for the analyzer
type InArgs struct {
	InputConfigFileList   []string
	InputSecondConfigFile string
	OutputFile            string
	OutputFormat          formatSetting
	AnalysisType          vpcmodel.OutputUseCase
	Grouping              bool
	VPC                   string
	Debug                 bool
	Version               *bool
	ESrc                  string
	EDst                  string
	EProtocol             protocolSetting
	ESrcMinPort           int64
	ESrcMaxPort           int64
	EDstMinPort           int64
	EDstMaxPort           int64
	Provider              provider
	RegionList            []string
	ResourceGroup         string
	DumpResources         string
	Quiet                 bool
	Verbose               bool
}

const separator = ", "
