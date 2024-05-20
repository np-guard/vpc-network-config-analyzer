/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/np-guard/vpc-network-config-analyzer/cmd/analyzer/subcmds"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const (
	ParsingErr       = "error parsing arguments:"
	OutGenerationErr = "output generation error:"
	ErrorFormat      = "%s %w"
)

func analysisVPCConfigs(inArgs *subcmds.InArgs) (string, error) {
	var explanationArgs *vpcmodel.ExplanationArgs
	if inArgs.AnalysisType == vpcmodel.Explain {
		explanationArgs = vpcmodel.NewExplanationArgs(inArgs.ESrc, inArgs.EDst, string(inArgs.EProtocol),
			inArgs.ESrcMinPort, inArgs.ESrcMaxPort, inArgs.EDstMinPort, inArgs.EDstMaxPort)
	}

	outFormat := inArgs.OutputFormat.ToModelFormat()
	og, err := vpcmodel.NewOutputGenerator(inArgs.VpcConfigs,
		inArgs.Grouping,
		inArgs.AnalysisType,
		false,
		explanationArgs, outFormat)
	if err != nil {
		return "", err
	}

	analysisOut, err := og.Generate(outFormat, inArgs.OutputFile)
	if err != nil {
		return "", fmt.Errorf(ErrorFormat, OutGenerationErr, err)
	}

	return analysisOut, nil
}

// The actual main function
// Takes command-line flags and returns an error rather than exiting, so it can be more easily used in testing
func _main(cmdlineArgs []string) error {
	inArgs := &subcmds.InArgs{AnalysisType: vpcmodel.InvalidUseCase}

	rootCmd := subcmds.NewRootCommand(inArgs)
	rootCmd.SetArgs(cmdlineArgs)
	err := rootCmd.Execute()
	if err != nil {
		return fmt.Errorf(ErrorFormat, ParsingErr, err)
	}
	if inArgs.AnalysisType == vpcmodel.InvalidUseCase {
		// TODO: the below check is not good enough - doesn't cover cases like "vpcanalyzer report --help"
		if subcmds.FlagSet(rootCmd, "help") || subcmds.FlagSet(rootCmd, "version") {
			return nil
		}
		return fmt.Errorf("command is missing or not available")
	}

	vpcAnalysisOutput, err := analysisVPCConfigs(inArgs)
	if err != nil {
		return err
	}
	fmt.Println(vpcAnalysisOutput)

	return nil
}

func main() {
	err := _main(os.Args[1:])
	if err != nil {
		log.Fatalf("%v. exiting...", err)
	}
}
