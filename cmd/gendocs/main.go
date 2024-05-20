/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"log"

	"github.com/spf13/cobra/doc"

	"github.com/np-guard/vpc-network-config-analyzer/cmd/analyzer/subcmds"
)

func main() {
	inArgs := &subcmds.InArgs{}

	cmd := subcmds.NewRootCommand(inArgs)
	cmd.DisableAutoGenTag = true

	err := doc.GenMarkdownTree(cmd, ".")
	if err != nil {
		log.Fatal(err)
	}
}
