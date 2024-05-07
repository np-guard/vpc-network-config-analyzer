/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

type formatSetting string

const (
	jsonFormat       formatSetting = "json"
	textFormat       formatSetting = "txt"
	mdFormat         formatSetting = "md"
	drawioFormat     formatSetting = "drawio"
	archDrawioFormat formatSetting = "arch_drawio"
	svgFormat        formatSetting = "svg"
	archSVGFormat    formatSetting = "arch_svg"
	htmlFormat       formatSetting = "html"
	archHtmlFormat   formatSetting = "arch_html"
	debugFormat      formatSetting = "debug"
)

var allFormats = []string{
	string(jsonFormat),
	string(textFormat),
	string(mdFormat),
	string(drawioFormat),
	string(archDrawioFormat),
	string(svgFormat),
	string(archSVGFormat),
	string(htmlFormat),
	string(archHtmlFormat),
	string(debugFormat),
}

func (fs *formatSetting) String() string {
	return string(*fs)
}

func (fs *formatSetting) Set(v string) error {
	v = strings.ToLower(v)
	if slices.Contains(allFormats, v) {
		*fs = formatSetting(v)
		return nil
	}
	return fmt.Errorf("must be one of [%s]", strings.Join(allFormats, separator))
}

func (fs *formatSetting) Type() string {
	return "string"
}

func (fs *formatSetting) ToModelFormat() vpcmodel.OutFormat {
	switch *fs {
	case textFormat:
		return vpcmodel.Text
	case mdFormat:
		return vpcmodel.MD
	case jsonFormat:
		return vpcmodel.JSON
	case drawioFormat:
		return vpcmodel.DRAWIO
	case archDrawioFormat:
		return vpcmodel.ARCHDRAWIO
	case svgFormat:
		return vpcmodel.SVG
	case archSVGFormat:
		return vpcmodel.ARCHSVG
	case htmlFormat:
		return vpcmodel.HTML
	case archHtmlFormat:
		return vpcmodel.ARCHHTML
	case debugFormat:
		return vpcmodel.Debug
	}
	return vpcmodel.Text
}
