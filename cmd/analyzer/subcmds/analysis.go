/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"fmt"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func analysisVPCConfigs(inArgs *InArgs) error {
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
		return err
	}

	analysisOut, err := og.Generate(outFormat, inArgs.OutputFile)
	if err != nil {
		return fmt.Errorf(errorFormat, "output generation error:", err)
	}

	fmt.Println(analysisOut)

	return nil
}
