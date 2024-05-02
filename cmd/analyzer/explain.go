/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"github.com/np-guard/models/pkg/connection"
	"github.com/spf13/cobra"
)

const (
	srcFlag        = "src"
	dstFlag        = "dst"
	protocolFlag   = "protocol"
	srcMinPortFlag = "src-min-port"
	srcMaxPortFlag = "src-max-port"
	dstMinPortFlag = "dst-min-port"
	dstMaxPortFlag = "dst-max-port"

	srcDstUsage = "endpoint for explanation; can be specified as a VSI name/CRN or an internal/external IP-address/CIDR;\n" +
		"VSI name can be specified as <vsi-name> or  <vpc-name>/<vsi-name>"
)

func NewExplainCommand(args *InArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Explain connectivity between two endpoints",
		Long:  `explains how the given cloud configuration affects connectivity between two endpoints`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	cmd.Flags().StringVar(&args.ESrc, srcFlag, "", "source "+srcDstUsage)
	cmd.Flags().StringVar(&args.EDst, dstFlag, "", "destination "+srcDstUsage)
	cmd.Flags().StringVar(&args.EProtocol, protocolFlag, "", "protocol for connection description")
	cmd.Flags().Int64Var(&args.ESrcMinPort, srcMinPortFlag, connection.MinPort, "minimum source port for connection description")
	cmd.Flags().Int64Var(&args.ESrcMaxPort, srcMaxPortFlag, connection.MaxPort, "maximum source port for connection description")
	cmd.Flags().Int64Var(&args.EDstMinPort, dstMinPortFlag, connection.MinPort, "minimum destination port for connection description")
	cmd.Flags().Int64Var(&args.EDstMaxPort, dstMaxPortFlag, connection.MaxPort, "maximum destination port for connection description")

	cmd.MarkFlagRequired(srcFlag)
	cmd.MarkFlagRequired(dstFlag)

	return cmd
}
