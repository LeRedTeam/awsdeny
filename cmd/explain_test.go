package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/leredteam/awsdeny/internal"
	"github.com/leredteam/awsdeny/parse"
	"github.com/spf13/cobra"
)

func TestRunExplain_WithErrorFlag(t *testing.T) {
	errorMsg = "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key because no identity-based policy allows the s3:GetObject action"
	useStdin = false
	cloudtrailPath = ""
	doEnrich = false
	formatFlag = "json"

	err := runExplain(&cobra.Command{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunExplain_WithPositionalArgs(t *testing.T) {
	errorMsg = ""
	useStdin = false
	cloudtrailPath = ""
	doEnrich = false
	formatFlag = "json"

	args := []string{"User:", "arn:aws:iam::123:role/MyRole", "is", "not", "authorized"}

	err := runExplain(&cobra.Command{}, args)
	// Will parse what it can from the joined text
	if err != nil {
		// An ExitError for unparseable format is acceptable
		if !isExitError(err) {
			t.Fatalf("unexpected error type: %v", err)
		}
	}
}

func TestRunExplain_NoInput(t *testing.T) {
	errorMsg = ""
	useStdin = false
	cloudtrailPath = ""

	err := runExplain(&cobra.Command{}, nil)
	if err == nil {
		t.Error("expected error when no input provided")
	}
	if !strings.Contains(err.Error(), "provide an error message") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGetErrorMessage_ErrorFlag(t *testing.T) {
	errorMsg = "test error"
	useStdin = false

	msg, err := getErrorMessage(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg != "test error" {
		t.Errorf("expected 'test error', got %q", msg)
	}
}

func TestGetErrorMessage_PositionalArgs(t *testing.T) {
	errorMsg = ""
	useStdin = false

	msg, err := getErrorMessage([]string{"some", "error", "text"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg != "some error text" {
		t.Errorf("expected 'some error text', got %q", msg)
	}
}

func TestGetErrorMessage_NoInput(t *testing.T) {
	errorMsg = ""
	useStdin = false

	_, err := getErrorMessage(nil)
	if err == nil {
		t.Error("expected error when no input")
	}
}

func TestWriteOutput_JSON(t *testing.T) {
	var buf bytes.Buffer
	parsed := parse.Parse("User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key")
	result := analyzeError(context.TODO(), parsed, false)

	if err := writeOutput(&buf, result, "json"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), `"status": "denied"`) {
		t.Error("JSON output should contain status field")
	}
}

func TestWriteOutput_Human(t *testing.T) {
	var buf bytes.Buffer
	parsed := parse.Parse("User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key")
	result := analyzeError(context.TODO(), parsed, false)

	if err := writeOutput(&buf, result, "human"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "Access Denied") {
		t.Error("human output should contain 'Access Denied'")
	}
}

func TestWriteOutput_GitHub(t *testing.T) {
	var buf bytes.Buffer
	parsed := parse.Parse("User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key")
	result := analyzeError(context.TODO(), parsed, false)

	if err := writeOutput(&buf, result, "github"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "## AWS AccessDenied") {
		t.Error("github output should contain markdown header")
	}
}

func isExitError(err error) bool {
	_, ok := err.(*internal.ExitError)
	return ok
}
