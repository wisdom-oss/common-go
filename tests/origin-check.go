package tests

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func ErrorOriginatedFromHost(error map[string]interface{}, t *testing.T) {
	host, valid := error["host"].(string)
	if !valid {
		t.Errorf("host field did not contain a string value, detected value '%T", error["host"])
	}
	hostname, err := os.Hostname()
	if err != nil {
		t.Errorf("error getting host name of machine: %v", err)
	}
	assert.Equal(t, host, hostname)
}
