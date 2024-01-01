package ibmvpc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
)

func TestCollector(t *testing.T) {
	inputConfig := "input_experiments_env.json"
	inputConfigFile := filepath.Join(getTestsDir(), inputConfig)
	inputConfigContent, err := os.ReadFile(inputConfigFile)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	config := datamodel.ResourcesContainerModel{}
	err = json.Unmarshal(inputConfigContent, &config)
	if err != nil {
		t.Errorf("Unmarshal failed with error message: %v", err)
	}
	fmt.Println("done")
}
