// Command github-sts-bundle exposes policy-bundle checks for release and
// deployment automation.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/depthmark/github-sts/internal/bundle"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "check-promotion" {
		_, _ = fmt.Fprintln(stderr, "usage: github-sts-bundle check-promotion [flags]")
		return 2
	}

	flags := flag.NewFlagSet("check-promotion", flag.ContinueOnError)
	flags.SetOutput(stderr)
	mode := flags.String("mode", "", "promotion mode: release or deployment")
	currentRevision := flags.String("current-revision", "", "trusted current policy revision")
	currentDigest := flags.String("current-digest", "", "trusted current OCI digest")
	candidateRevision := flags.String("candidate-revision", "", "candidate policy revision")
	candidateDigest := flags.String("candidate-digest", "", "candidate OCI digest")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "check-promotion does not accept positional arguments")
		return 2
	}

	current := bundle.PolicyArtifactVersion{Digest: *currentDigest, PolicyRevision: *currentRevision}
	candidate := bundle.PolicyArtifactVersion{Digest: *candidateDigest, PolicyRevision: *candidateRevision}
	if err := bundle.ValidatePolicyPromotion(bundle.PolicyPromotionMode(*mode), current, candidate); err != nil {
		_, _ = fmt.Fprintf(stderr, "policy promotion rejected: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(struct {
		Allowed   bool                         `json:"allowed"`
		Mode      bundle.PolicyPromotionMode   `json:"mode"`
		Current   bundle.PolicyArtifactVersion `json:"current"`
		Candidate bundle.PolicyArtifactVersion `json:"candidate"`
	}{Allowed: true, Mode: bundle.PolicyPromotionMode(*mode), Current: current, Candidate: candidate}); err != nil {
		_, _ = fmt.Fprintf(stderr, "writing result: %v\n", err)
		return 1
	}
	return 0
}
