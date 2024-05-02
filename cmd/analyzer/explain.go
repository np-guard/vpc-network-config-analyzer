/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/np-guard/models/pkg/netp"
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

type protocolSetting netp.ProtocolString

func (ps *protocolSetting) String() string {
	return string(*ps)
}

func (ps *protocolSetting) Set(v string) error {
	allowedProtocols := []string{string(netp.ProtocolStringICMP), string(netp.ProtocolStringTCP), string(netp.ProtocolStringUDP)}
	v = strings.ToUpper(v)
	if slices.Contains(allowedProtocols, v) {
		*ps = protocolSetting(v)
		return nil
	}
	return fmt.Errorf(`must be one of %s`, strings.Join(allowedProtocols, ", "))
}

func (ps *protocolSetting) Type() string {
	return "string"
}

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
	cmd.Flags().Var(&args.EProtocol, protocolFlag, "protocol for connection description")
	cmd.Flags().Int64Var(&args.ESrcMinPort, srcMinPortFlag, netp.MinPort, "minimum source port for connection description")
	cmd.Flags().Int64Var(&args.ESrcMaxPort, srcMaxPortFlag, netp.MaxPort, "maximum source port for connection description")
	cmd.Flags().Int64Var(&args.EDstMinPort, dstMinPortFlag, netp.MinPort, "minimum destination port for connection description")
	cmd.Flags().Int64Var(&args.EDstMaxPort, dstMaxPortFlag, netp.MaxPort, "maximum destination port for connection description")

	cmd.MarkFlagRequired(srcFlag)
	cmd.MarkFlagRequired(dstFlag)

	return cmd
}
