/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//	package subcmds defines vpcanalyzer's subcommands, their flags and their behavior.
//
// We use the various Run methods of cobra.Command as follows (order corresponds to execution order).
// 1. PersistentPreRun (root) - initialize logger
// 2. PersistentPreRunE/PreRunE (subcommands and subsubcommands) - check flag validity
// 3. RunE (subcommands and subsubcommands) - build vpc-configs and call the analyzer with parsed flag values
//
// This order prevents code duplication - all common code is in root; subcommand-specific code is in its subcommand
package subcmds

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/np-guard/cloud-resource-collector/pkg/common"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/logging"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/version"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const (
	vpcConfigFlag = "config"
	providerFlag  = "provider"
	regionFlag    = "region"
	rgFlag        = "resource-group"
	vpcFlag       = "vpc"

	outputFileFlag   = "filename"
	outputFormatFlag = "output"
	dumpFlag         = "dump-resources"
	quietFlag        = "quiet"
	verboseFlag      = "verbose"
)

// inArgs holds parsed flag values
type inArgs struct {
	inputConfigFileList   []string
	inputSecondConfigFile string
	outputFile            string
	outputFormat          formatSetting
	grouping              bool
	lbAbstraction         bool
	vpcList               []string
	eSrc                  string
	eDst                  string
	eProtocol             protocolSetting
	eSrcMinPort           int64
	eSrcMaxPort           int64
	eDstMinPort           int64
	eDstMaxPort           int64
	detailExplain         bool
	provider              common.Provider
	regionList            []string
	resourceGroup         string
	dumpResources         string
	quiet                 bool
	verbose               bool
	explanationArgs       *vpcmodel.ExplanationArgs
	enableLinters         []string
	disableLinters        []string
	printAllLinters       bool
}

func NewRootCommand() *cobra.Command {
	args := &inArgs{}

	rootCmd := &cobra.Command{
		Use:     "vpcanalyzer",
		Short:   "vpcanalyzer is a CLI that analyzes network connectivity in VPCs",
		Long:    `vpcanalyzer analyzes VPC connectivity as set by the given cloud configuration.`,
		Version: version.VersionCore,
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			verbosity := logging.MediumVerbosity
			if args.quiet {
				verbosity = logging.LowVerbosity
			} else if args.verbose {
				verbosity = logging.HighVerbosity
			}
			logging.Init(verbosity) // initializes a thread-safe singleton logger
		},
	}

	rootCmd.PersistentFlags().StringArrayVarP(&args.inputConfigFileList, vpcConfigFlag, "c", nil,
		"file paths to input VPC configs, can pass multiple config files")
	rootCmd.PersistentFlags().VarP(&args.provider, providerFlag, "p", "collect resources from an account in this cloud provider")
	rootCmd.PersistentFlags().StringVar(&args.dumpResources, dumpFlag, "", "file path to store resources collected from the cloud provider")
	rootCmd.MarkFlagsOneRequired(vpcConfigFlag, providerFlag)
	rootCmd.MarkFlagsMutuallyExclusive(vpcConfigFlag, providerFlag)
	rootCmd.MarkFlagsMutuallyExclusive(vpcConfigFlag, dumpFlag)

	rootCmd.PersistentFlags().StringArrayVarP(&args.regionList, regionFlag, "r", nil,
		"cloud region from which to collect resources, can pass multiple regions")
	rootCmd.PersistentFlags().StringVar(&args.resourceGroup, rgFlag, "", "resource group id or name from which to collect resources")
	rootCmd.PersistentFlags().StringArrayVarP(&args.vpcList, vpcFlag, "", nil, "CRN of the VPC to analyze")

	rootCmd.PersistentFlags().StringVarP(&args.outputFile, outputFileFlag, "f", "", "file path to store results")
	rootCmd.PersistentFlags().VarP(&args.outputFormat, outputFormatFlag, "o", "output format; "+mustBeOneOf(allFormats))

	rootCmd.PersistentFlags().BoolVarP(&args.quiet, quietFlag, "q", false, "runs quietly, reports only severe errors and results")
	rootCmd.PersistentFlags().BoolVarP(&args.verbose, verboseFlag, "v", false, "runs with more informative messages printed to log")
	rootCmd.MarkFlagsMutuallyExclusive(quietFlag, verboseFlag)

	rootCmd.PersistentFlags().SortFlags = false

	rootCmd.AddCommand(NewReportCommand(args))
	rootCmd.AddCommand(NewDiffCommand(args))
	rootCmd.AddCommand(NewExplainCommand(args))
	rootCmd.AddCommand(NewLintCommand(args))
	rootCmd.CompletionOptions.HiddenDefaultCmd = true
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true}) // disable help command. should use --help flag instead

	cobra.EnableTraverseRunHooks = true

	return rootCmd
}

func mustBeOneOf(values []string) string {
	return fmt.Sprintf("must be one of [%s]", strings.Join(values, ", "))
}
