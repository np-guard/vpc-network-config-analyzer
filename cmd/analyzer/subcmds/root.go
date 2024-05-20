/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/logging"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/version"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const (
	vpcConfigFlag = "vpc-config"
	providerFlag  = "provider"
	regionFlag    = "region"
	rgFlag        = "resource-group"
	vpcFlag       = "vpc"

	outputFileFlag   = "output-file"
	outputFormatFlag = "format"
	dumpFlag         = "dump-resources"
	quietFlag        = "quiet"
	verboseFlag      = "verbose"
	debugFlag        = "debug"
)

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
	VpcConfigs            *vpcmodel.MultipleVPCConfigs
}

func NewRootCommand(args *InArgs) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:     "vpcanalyzer",
		Short:   "vpcanalyzer is a CLI that analyzes network connectivity in VPCs",
		Long:    `vpcanalyzer analyzes VPC connectivity as set by the given cloud configuration.`,
		Version: version.VersionCore,
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			verbosity := logging.MediumVerbosity
			if args.Quiet {
				verbosity = logging.LowVerbosity
			} else if args.Verbose {
				verbosity = logging.HighVerbosity
			}
			logging.Init(verbosity) // initializes a thread-safe singleton logger
		},
		PersistentPostRunE: func(_ *cobra.Command, _ []string) error {
			err := buildConfigs(args)
			if err != nil {
				return err
			}
			return analysisVPCConfigs(args)
		},
	}

	rootCmd.PersistentFlags().StringArrayVarP(&args.InputConfigFileList, vpcConfigFlag, "c", nil,
		"file paths to input configs, can pass multiple config files")
	rootCmd.PersistentFlags().VarP(&args.Provider, providerFlag, "p", "collect resources from an account in this cloud provider")
	rootCmd.PersistentFlags().StringVar(&args.DumpResources, dumpFlag, "", "file path to store resources collected from the cloud provider")
	rootCmd.MarkFlagsOneRequired(vpcConfigFlag, providerFlag)
	rootCmd.MarkFlagsMutuallyExclusive(vpcConfigFlag, providerFlag)
	rootCmd.MarkFlagsMutuallyExclusive(vpcConfigFlag, dumpFlag)

	rootCmd.PersistentFlags().StringArrayVarP(&args.RegionList, regionFlag, "r", nil,
		"cloud region from which to collect resources, can pass multiple regions")
	rootCmd.PersistentFlags().StringVar(&args.ResourceGroup, rgFlag, "", "resource group id or name from which to collect resources")
	rootCmd.PersistentFlags().StringVar(&args.VPC, vpcFlag, "", "CRN of the VPC to analyze")

	rootCmd.PersistentFlags().StringVar(&args.OutputFile, outputFileFlag, "", "file path to store results")
	rootCmd.PersistentFlags().VarP(&args.OutputFormat, outputFormatFlag, "o", "output format; "+mustBeOneOf(allFormats))

	rootCmd.PersistentFlags().BoolVarP(&args.Quiet, quietFlag, "q", false, "runs quietly, reports only severe errors and results")
	rootCmd.PersistentFlags().BoolVarP(&args.Verbose, verboseFlag, "v", false, "runs with more informative messages printed to log")
	rootCmd.MarkFlagsMutuallyExclusive(quietFlag, verboseFlag)

	rootCmd.PersistentFlags().BoolVar(&args.Debug, debugFlag, false, "runs in debug mode")

	rootCmd.PersistentFlags().SortFlags = false

	rootCmd.AddCommand(NewReportCommand(args))
	rootCmd.AddCommand(NewDiffCommand(args))
	rootCmd.AddCommand(NewExplainCommand(args))
	rootCmd.CompletionOptions.HiddenDefaultCmd = true
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true}) // disable help command. should use --help flag instead

	cobra.EnableTraverseRunHooks = true

	return rootCmd
}

func mustBeOneOf(values []string) string {
	return fmt.Sprintf("must be one of [%s]", strings.Join(values, ", "))
}
