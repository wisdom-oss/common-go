package types

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/iancoleman/strcase"
)

// ErrorContentType is used as the content type when sending an error response
const ErrorContentType = "application/problem+json; charset=utf-8"

const tagFormattingString = `tag:%s,%s:%s:%d`

// ServiceError is the commonly used error response in the WISdoM environment.
// It implements [RFC 9457] to enable an easy usage of the error responses in
// other systems.
//
// It contains the following extension members
//   - Errors: []error
//   - Host: string
//
// The Host field is automatically filled during the marshaling of the error
// into an JSON object
//
// [RFC 9457]: https://datatracker.ietf.org/doc/html/rfc9457
type ServiceError struct {
	// Type contains a URI reference that identifies the problem type. This
	// identifier should be used as primary identifier and may point to an
	// external resource.
	//
	// See more: https://datatracker.ietf.org/doc/html/rfc9457#section-3.1.1
	Type string

	// Status contains the HTTP Status Code as defined in [RFC 9110]
	//
	// [RFC 9110]: https://www.rfc-editor.org/rfc/rfc9110#section-15
	Status uint

	// Title contains a short, human-readable summary of the problem (e.g.
	// Missing Authorization Information)
	Title string

	// Detail contains a human-readable description of the problem type while
	// focusing on problem correction instead of debugging
	Detail string

	// Instance contains a (possibly dereferenceable) URI which identifies the
	// specific occurrence of the error
	Instance string

	// Errors is an extension member that contains one or multiple error objects
	// which will be transformed into plain strings using the error interface
	Errors []error

	// Host contains the hostname of the server the error occurred on
	Host string
}

// SetInstance generates a URI of the TAG format containing a unique identifier
// for this error and assignes it to the Instance field
func (se *ServiceError) SetInstance() error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	ts := time.Now()
	se.Instance = fmt.Sprintf(tagFormattingString, hostname, ts.Format(`2006-01-02`), strcase.ToCamel(se.Title), ts.Unix())
	return nil
}

// Send transmits the error using the supplied http.ResponseWriter
func (se *ServiceError) Send(w http.ResponseWriter) {
	if se.Host == "" || strings.TrimSpace(se.Host) == "" {
		se.Host, _ = os.Hostname()
	}
	if se.Instance == "" || strings.TrimSpace(se.Instance) == "" {
		_ = se.SetInstance()
	}

	w.Header().Set("Content-Type", ErrorContentType)
	w.WriteHeader(int(se.Status))

	err := json.NewEncoder(w).Encode(se)
	if err != nil {
		panic(err)
	}
}

// MarshalJSON is used to change the serialization of the Errors
func (se ServiceError) MarshalJSON() ([]byte, error) {
	output := struct {
		Type     string   `json:"type"`
		Status   int      `json:"status"`
		Title    string   `json:"title"`
		Detail   string   `json:"detail"`
		Instance string   `json:"instance,omitempty"`
		Errors   []string `json:"errors,omitempty"`
		Host     string   `json:"host"`
	}{
		Type:     se.Type,
		Status:   int(se.Status),
		Title:    se.Title,
		Detail:   se.Detail,
		Instance: se.Instance,
		Host:     se.Host,
	}
	for _, err := range se.Errors {
		output.Errors = append(output.Errors, err.Error())
	}
	return json.Marshal(output)
}

// Equals checks if the current WISdoMError object is equal to the provided
// ServiceError object. It compares the values of the Type, Status, Title, and
// Detail fields between the two objects. If any of these fields differ, Equals
// returns false. Otherwise, it returns true, indicating that the two objects
// are equal.
//
// Example usage:
//
//	err1 := &ServiceError{
//	    Type:   "error",
//	    Status: 500,
//	    Title:  "Internal Server Error",
//	    Detail: "An unknown error occurred",
//	}
//	err2 := &ServiceError{
//	    Type:   "error",
//	    Status: 500,
//	    Title:  "Internal Server Error",
//	    Detail: "An unknown error occurred",
//	}
//	equal := err1.Equals(*err2)
//	fmt.Println(equal) // Output: true
func (se *ServiceError) Equals(other ServiceError) bool {
	equals := true
	if se.Type != other.Type {
		equals = false
	}
	if se.Status != other.Status {
		equals = false
	}
	if se.Title != other.Title {
		equals = false
	}
	if se.Detail != other.Detail {
		equals = false
	}
	return equals
}
