package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/ibmvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// The actual main function
// Takes command-line flags and returns an error rather than exiting, so it can be more easily used in testing
func _main(cmdlineArgs []string) error {
	inArgs, err := ParseInArgs(cmdlineArgs)
	if err == flag.ErrHelp {
		return nil
	}
	if err != nil {
		return fmt.Errorf("error parsing arguments: %w", err)
	}

	rc, err := ibmvpc.ParseResourrcesFromFile(*inArgs.InputConfigFile)
	if err != nil {
		return fmt.Errorf("error parsing input vpc resources file: %w", err)
	}

	cloudConfig, err := ibmvpc.NewCloudConfig(rc)
	if err != nil {
		return fmt.Errorf("error generating cloud config from input vpc resources file: %w", err)
	}

	vpcConn := cloudConfig.GetVPCNetworkConnectivity()
	o := vpcmodel.NewOutputGenerator(cloudConfig, vpcConn)
	textOutput, err := o.Generate(vpcmodel.Text)
	if err != nil {
		return fmt.Errorf("output generation error: %w", err)
	}
	fmt.Println(textOutput)

	return nil
}

func main() {
	err := _main(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v. exiting...", err)
		os.Exit(1)
	}

}
