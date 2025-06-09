package secretmananger

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/getaxal/verified-signer/common/aws"
	"github.com/getaxal/verified-signer/common/network"
	log "github.com/sirupsen/logrus"
)

const (
	algorithm       = "AWS4-HMAC-SHA256"
	service         = "secretsmanager"
	terminationChar = "aws4_request"
	// EC2 metadata endpoints for IAM role credentials
	ec2MetadataTokenURL = "http://169.254.169.254/latest/api/token"
	ec2MetadataRoleURL  = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
)

type SecretManager struct {
	SmClient             *http.Client
	EC2CredentialsClient *http.Client
	Config               *SecretManagerConfig
	Environment          string // "local", "dev", or "prod"
}

// GetSecretValueRequest represents the request payload
type GetSecretValueRequest struct {
	SecretId string `json:"SecretId"`
}

// GetSecretValueResponse represents the API response
type GetSecretValueResponse struct {
	ARN           string   `json:"ARN"`
	Name          string   `json:"Name"`
	SecretString  string   `json:"SecretString"`
	VersionId     string   `json:"VersionId"`
	VersionStages []string `json:"VersionStages"`
}

// EC2Credentials represents temporary credentials from EC2 metadata
type EC2Credentials struct {
	AccessKeyId     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	Token           string    `json:"Token"`
	Expiration      time.Time `json:"Expiration"`
}

// Creates a new Secret Manager instance with specified environment
// environment should be "dev", "prod", or "local"
func NewSecretManager(cfgPath string, environment string, smPort uint32, ec2Port uint32) (*SecretManager, error) {
	sm := &SecretManager{
		SmClient:             network.InitHttpsClientWithTLSVsockTransport(smPort, fmt.Sprintf("secretsmanager.%s.amazonaws.com", aws.USEast2)),
		EC2CredentialsClient: network.InitHttpClientWithVsockTransport(ec2Port),
		Environment:          environment,
	}

	creds, err := sm.getCredentials(cfgPath)
	if err != nil {
		log.Errorf("Unable to create a SM manager with err: %v", err)
		return nil, fmt.Errorf("Unable to create a New Secrets Manager Client")
	}

	sm.Config = &SecretManagerConfig{
		Credentials: *creds,
		Region:      creds.Region,
	}

	return sm, nil

}

// getEC2Credentials fetches temporary credentials from EC2 instance metadata
func (sm *SecretManager) getEC2Credentials() (*aws.AWSCredentials, error) {
	// Get IMDSv2 token for secure access
	tokenReq, err := http.NewRequest("PUT", ec2MetadataTokenURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	tokenResp, err := sm.EC2CredentialsClient.Do(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata token: %w", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get metadata token, status: %d", tokenResp.StatusCode)
	}

	token, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata token: %w", err)
	}

	// Get IAM role name
	roleReq, err := http.NewRequest("GET", ec2MetadataRoleURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create role request: %w", err)
	}
	roleReq.Header.Set("X-aws-ec2-metadata-token", string(token))

	roleResp, err := sm.EC2CredentialsClient.Do(roleReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM role: %w", err)
	}
	defer roleResp.Body.Close()

	if roleResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get IAM role, status: %d", roleResp.StatusCode)
	}

	roleName, err := io.ReadAll(roleResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read IAM role name: %w", err)
	}

	// Get temporary credentials for the role
	credReq, err := http.NewRequest("GET", ec2MetadataRoleURL+string(roleName), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create credentials request: %w", err)
	}
	credReq.Header.Set("X-aws-ec2-metadata-token", string(token))

	credResp, err := sm.EC2CredentialsClient.Do(credReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}
	defer credResp.Body.Close()

	if credResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get credentials, status: %d", credResp.StatusCode)
	}

	var ec2Creds EC2Credentials
	if err := json.NewDecoder(credResp.Body).Decode(&ec2Creds); err != nil {
		return nil, fmt.Errorf("failed to decode credentials: %w", err)
	}

	return &aws.AWSCredentials{
		AccessKey:    ec2Creds.AccessKeyId,
		AccessSecret: ec2Creds.SecretAccessKey,
		SessionToken: ec2Creds.Token,
	}, nil
}

// getCredentials returns the appropriate credentials based on environment
func (sm *SecretManager) getCredentials(cfgPath string) (*aws.AWSCredentials, error) {
	switch sm.Environment {
	case "dev", "prod":
		// Use IAM role credentials from EC2 metadata
		log.Info("Fetching ec2 credentials")
		return sm.getEC2Credentials()
	case "local":
		creds, err := aws.NewAWSConfigFromYAML(cfgPath)
		if err != nil {
			return nil, fmt.Errorf("Unable to fetch local credentials")
		}

		return &creds.AWSCredentials, nil
	default:
		creds, err := aws.NewAWSConfigFromYAML(cfgPath)
		if err != nil {
			return nil, fmt.Errorf("Unable to fetch local credentials")
		}

		return &creds.AWSCredentials, nil
	}
}

// Use this function to sign the HTTP request to AWS. Uses AWS sig4 found here https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html.
func (sm *SecretManager) signRequest(req *http.Request, payload string) error {
	creds := sm.Config.Credentials

	t := time.Now().UTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	// Get host from URL
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}

	// Set required headers BEFORE creating canonical headers
	req.Header.Set("Host", host)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")

	// Add session token if present (for IAM role credentials)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	// Create canonical request
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQueryString := req.URL.RawQuery

	// Create canonical headers - MUST include Host
	var headerNames []string
	headerMap := make(map[string]string)
	for name, values := range req.Header {
		lowerName := strings.ToLower(name)
		headerNames = append(headerNames, lowerName)
		headerMap[lowerName] = strings.TrimSpace(strings.Join(values, ","))
	}
	sort.Strings(headerNames)

	var canonicalHeaders strings.Builder
	for _, name := range headerNames {
		canonicalHeaders.WriteString(fmt.Sprintf("%s:%s\n", name, headerMap[name]))
	}

	signedHeaders := strings.Join(headerNames, ";")
	payloadHash := sha256Hash(payload)

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method, canonicalURI, canonicalQueryString,
		canonicalHeaders.String(), signedHeaders, payloadHash)

	// Create string to sign
	credentialScope := fmt.Sprintf("%s/%s/%s/%s", dateStamp, sm.Config.Region, service, terminationChar)
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
		algorithm, amzDate, credentialScope, sha256Hash(canonicalRequest))

	// Create signature using the obtained credentials
	signingKey := createSignatureKey(creds.AccessSecret, dateStamp, sm.Config.Region.String(), service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	// Create authorization header
	authorizationHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm, creds.AccessKey, credentialScope, signedHeaders, signature)

	req.Header.Set("Authorization", authorizationHeader)
	return nil
}

// GetSecret retrieves a secret from AWS Secrets Manager with a given secretName by directly sending a request to the AWS HTTPS APIs.
// We sign the request with AWS sig4.
func (sm *SecretManager) GetSecret(ctx context.Context, secretName string) (*GetSecretValueResponse, error) {
	// Prepare request payload
	reqPayload := GetSecretValueRequest{
		SecretId: secretName,
	}
	payloadBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	endpoint := sm.Config.GetSecretManagerEndpoint()
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Sign the request (automatically uses appropriate credentials based on environment)
	if err := sm.signRequest(req, string(payloadBytes)); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	// Make the request
	resp, err := sm.SmClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	var secretResp GetSecretValueResponse
	if err := json.Unmarshal(respBody, &secretResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &secretResp, nil
}
