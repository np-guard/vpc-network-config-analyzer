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
	return fmt.Errorf(`must be one of %s`, strings.Join(allFormats, ", "))
}

func (fs *formatSetting) Type() string {
	return "string"
}

func (fs *formatSetting) ToModelFormat() vpcmodel.OutFormat {
	switch *fs {
	case TEXTFormat:
		return vpcmodel.Text
	case MDFormat:
		return vpcmodel.MD
	case JSONFormat:
		return vpcmodel.JSON
	case DRAWIOFormat:
		return vpcmodel.DRAWIO
	case ARCHDRAWIOFormat:
		return vpcmodel.ARCHDRAWIO
	case SVGFormat:
		return vpcmodel.SVG
	case ARCHSVGFormat:
		return vpcmodel.ARCHSVG
	case HTMLFormat:
		return vpcmodel.HTML
	case ARCHHTMLFormat:
		return vpcmodel.ARCHHTML
	case DEBUGFormat:
		return vpcmodel.Debug
	}
	return vpcmodel.Text
}
