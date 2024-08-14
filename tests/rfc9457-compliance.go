package tests

import (
	"testing"
)

func ErrorRfc9457Compliant(err map[string]interface{}, t *testing.T) {
	_, validType := err["type"].(string)
	if !validType {
		t.Errorf("rfc9457 violated, expected 'type' field to be 'string', got '%T'", err["type"])
	}

	_, validType = err["status"].(float64)
	if !validType {
		t.Errorf("rfc9457 violated, expected 'status' field to be 'int', got '%T'", err["status"])
	}

	_, validType = err["title"].(string)
	if !validType {
		t.Errorf("rfc9457 violated, expected 'title' field to be 'string', got '%T'", err["title"])
	}

	_, validType = err["detail"].(string)
	if !validType {
		t.Errorf("rfc9457 violated, expected 'detail' field to be 'string', got '%T'", err["detail"])
	}

	_, validType = err["instance"].(string)
	if !validType {
		t.Errorf("rfc9457 violated, expected 'instance' field to be 'string', got '%T'", err["instance"])
	}
}
