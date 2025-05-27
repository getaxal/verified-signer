package privysigner

// Config for privy access
type PrivyConfig struct {
	AppID               string `json:"app_id" yaml:"app_id"`
	DelegatedActionsKey string `json:"delegated_actions_key" yaml:"delegated_actions_key"`
	AppSecret           string `json:"app_secret" yaml:"app_secret"`
	JWTVerificationKey  string `json:"jwt_verification_key" yaml:"jwt_verification_key"`
}
