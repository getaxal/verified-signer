package enclave

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"

	"github.com/getaxal/verified-signer/common/aws"
	log "github.com/sirupsen/logrus"
)

// kmsToolEnclaveCLIPath is the location of the AWS Nitro Enclaves kmstool CLI
// baked into the enclave image. See the Dockerfile build stage.
const kmsToolEnclaveCLIPath = "/kmstool_enclave_cli"

// MaybeUnwrap returns the plaintext bytes of a secret value fetched from Secrets
// Manager.
//
// For the "local" environment (developer machine, no NSM device) the stored
// value is plaintext JSON and is returned as-is.
//
// For every other environment the stored value is a base64-encoded KMS
// ciphertext. It is decrypted with an attestation-bound kms:Decrypt performed
// inside the enclave (see KmsDecryptAttested). This is what actually closes the
// host/enclave trust gap: the parent host can fetch the same ciphertext and
// holds the same instance-role credentials, but the KMS key policy only
// releases the plaintext to a request carrying a valid enclave attestation
// matching the expected PCR measurement, which the host cannot produce.
func MaybeUnwrap(env, secretValue, region string, kmsProxyPort uint32, creds aws.AWSCredentials) ([]byte, error) {
	if env == "local" {
		return []byte(secretValue), nil
	}
	return KmsDecryptAttested(secretValue, region, kmsProxyPort, creds)
}

// KmsDecryptAttested decrypts a base64 KMS ciphertext inside the enclave using
// kmstool_enclave_cli.
//
// The CLI generates an ephemeral RSA keypair, requests an NSM attestation
// document binding that public key, and calls kms:Decrypt with the attestation
// as the Recipient. KMS validates the attestation against the key policy's
// kms:RecipientAttestation conditions, then returns the plaintext encrypted to
// the enclave's ephemeral key, which the CLI unwraps with the matching private
// key. The KMS request is routed to the host's vsock->TCP proxy on kmsProxyPort.
func KmsDecryptAttested(ciphertextB64, region string, kmsProxyPort uint32, creds aws.AWSCredentials) ([]byte, error) {
	if kmsProxyPort == 0 {
		return nil, fmt.Errorf("kms vsock proxy port is not configured")
	}
	if creds.AccessKey == "" || creds.AccessSecret == "" {
		return nil, fmt.Errorf("missing AWS credentials for attested KMS decrypt")
	}

	args := []string{
		"decrypt",
		"--region", region,
		"--proxy-port", fmt.Sprintf("%d", kmsProxyPort),
		"--aws-access-key-id", creds.AccessKey,
		"--aws-secret-access-key", creds.AccessSecret,
		"--ciphertext", ciphertextB64,
	}
	if creds.SessionToken != "" {
		args = append(args, "--aws-session-token", creds.SessionToken)
	}

	// Note: stdout carries the decrypted plaintext, so it is never logged.
	out, err := exec.Command(kmsToolEnclaveCLIPath, args...).Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			log.Errorf("kmstool_enclave_cli failed with exit code %d", exitErr.ExitCode())
		}
		return nil, fmt.Errorf("attested KMS decrypt failed: %w", err)
	}

	// kmstool_enclave_cli prints "PLAINTEXT: <base64>".
	const prefix = "PLAINTEXT: "
	line := strings.TrimSpace(string(out))
	idx := strings.LastIndex(line, prefix)
	if idx < 0 {
		return nil, fmt.Errorf("unexpected kmstool_enclave_cli output format")
	}

	plaintext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line[idx+len(prefix):]))
	if err != nil {
		return nil, fmt.Errorf("failed to decode kmstool_enclave_cli plaintext: %w", err)
	}

	return plaintext, nil
}
