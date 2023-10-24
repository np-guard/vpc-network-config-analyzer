package vpcmodel

import (
	"errors"
	"fmt"
	"os"
)

type OutFormat int64

const (
	JSON OutFormat = iota
	Text
	MD
	CSV
	DRAWIO
	ARCHDRAWIO
	Debug // extended txt format with more details
)

const (
	writeFileMde = 0o600
)

type OutputUseCase int

const (
	AllEndpoints    OutputUseCase = iota // connectivity between network interfaces and external ip-blocks
	SingleSubnet                         // connectivity per single subnet with nacl
	AllSubnets                           // connectivity between subnets (consider nacl + pgw)
	AllSubnetsNoPGW                      // connectivity between subnets (consider nacl only)
)

type OutputGenerator struct {
	config         *CloudConfig
	outputGrouping bool
	useCase        OutputUseCase
	nodesConn      *VPCConnectivity
	subnetsConn    *VPCsubnetConnectivity
}

func NewOutputGenerator(c *CloudConfig, grouping bool, uc OutputUseCase, archOnly bool) (*OutputGenerator, error) {
	res := &OutputGenerator{
		config:         c,
		outputGrouping: grouping,
		useCase:        uc,
	}
	if !archOnly {
		if uc == AllEndpoints {
			nodesConn, err := c.GetVPCNetworkConnectivity(grouping)
			if err != nil {
				return nil, err
			}
			res.nodesConn = nodesConn
		}
		if uc == AllSubnets {
			subnetsConn, err := c.GetSubnetsConnectivity(true, grouping)
			if err != nil {
				return nil, err
			}
			res.subnetsConn = subnetsConn
		}
	}
	// todo: add for diff
	return res, nil
}

func (o *OutputGenerator) Generate(f OutFormat, outFile string, numVPCs int, vpcName string) (string, error) {
	var formatter OutputFormatter
	switch f {
	case JSON:
		formatter = &JSONoutputFormatter{}
	case Text:
		formatter = &TextOutputFormatter{}
	case MD:
		formatter = &MDoutputFormatter{}
	case DRAWIO:
		formatter = &DrawioOutputFormatter{}
	case ARCHDRAWIO:
		formatter = &ArchDrawioOutputFormatter{}
	case Debug:
		formatter = &DebugOutputFormatter{}
	default:
		return "", errors.New("unsupported output format")
	}

	var res string
	var err error

	switch o.useCase {
	case AllEndpoints:
		res, err = formatter.WriteOutputAllEndpoints(o.config, o.nodesConn, outFile, o.outputGrouping)
	case SingleSubnet:
		res, err = formatter.WriteOutputSingleSubnet(o.config, outFile)
	case AllSubnets:
		res, err = formatter.WriteOutputAllSubnets(o.subnetsConn, outFile)
	default:
		return "", errors.New("unsupported useCase argument")
	}

	return finalizeOutput(res, numVPCs, vpcName, f), err
}

// finalizeOutput adds info line about the name of the VPC before its analysis output,
// in case multiple VPCs are analyzed separately
func finalizeOutput(output string, numVPCs int, vpcName string, f OutFormat) string {
	if numVPCs == 1 {
		return output
	}
	res := output
	switch f {
	case Text, MD, Debug:
		res = fmt.Sprintf("Analysis for VPC %s:\n%s", vpcName, output)
		// TODO: handle the other output formats
	}
	return res
}

// OutputFormatter has several write functions per each use-case
type OutputFormatter interface {
	WriteOutputAllEndpoints(c *CloudConfig, conn *VPCConnectivity, outFile string, grouping bool) (string, error)
	WriteOutputAllSubnets(subnetsConn *VPCsubnetConnectivity, outFile string) (string, error)
	WriteOutputSingleSubnet(c *CloudConfig, outFile string) (string, error)
}

func writeOutput(out, file string) (string, error) {
	err := WriteToFile(out, file)
	return out, err
}

func WriteToFile(content, fileName string) error {
	if fileName != "" {
		return os.WriteFile(fileName, []byte(content), writeFileMde)
	}
	return nil
}
