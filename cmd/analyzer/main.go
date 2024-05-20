/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"log"
	"os"

	"github.com/np-guard/vpc-network-config-analyzer/cmd/analyzer/subcmds"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// The actual main function
// Takes command-line flags and returns an error rather than exiting, so it can be more easily used in testing
func _main(cmdlineArgs []string) error {
	inArgs := &subcmds.InArgs{AnalysisType: vpcmodel.InvalidUseCase}

	rootCmd := subcmds.NewRootCommand(inArgs)
	rootCmd.SetArgs(cmdlineArgs)
	return rootCmd.Execute()
}

func main() {
	err := _main(os.Args[1:])
	if err != nil {
		log.Fatalf("%v. exiting...", err)
	}
}
