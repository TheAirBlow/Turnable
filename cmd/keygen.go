package main

import (
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

// keygenOptions holds CLI flags for the keygen subcommand
type keygenOptions struct {
	asJSON bool
}

// newKeygenCommand creates the keygen cobra command
func newKeygenCommand() *cobra.Command {
	opts := &keygenOptions{}

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate ML-KEM-768 keys for config",
		RunE: func(cmd *cobra.Command, args []string) error {
			return keygenMain(opts)
		},
	}

	cmd.Flags().BoolVar(&opts.asJSON, "json", false, "print keys as a JSON object")
	return cmd
}

// serverMain runs the keygen command
func keygenMain(opts *keygenOptions) error {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return err
	}

	priv := base64.StdEncoding.EncodeToString(dk.Bytes())
	pub := base64.StdEncoding.EncodeToString(dk.EncapsulationKey().Bytes())

	if opts.asJSON {
		payload := map[string]string{
			"priv_key": priv,
			"pub_key":  pub,
		}
		out, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}

	fmt.Printf("priv_key=%s\n", priv)
	fmt.Printf("pub_key=%s\n", pub)
	return nil
}
