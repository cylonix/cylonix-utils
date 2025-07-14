// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/cylonix/utils/oauth"

	gviper "github.com/spf13/viper"
)

type APIServerConfig struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Scheme string `json:"scheme,omitempty"` // http/https/tcp, optional, default to https
}

func (c APIServerConfig) IsZero() bool {
	return c.Port <= 0 || c.Host == ""
}
func (c APIServerConfig) URL(includeScheme bool) string {
	if c.IsZero() {
		return ""
	}
	if !includeScheme {
		return c.Host + ":" + strconv.Itoa(c.Port)
	}
	proto := c.Scheme
	if proto == "" {
		proto = "http"
	}
	if (c.Port == 443 && proto == "https") || (c.Port == 80 && proto == "http") {
		return proto + "://" + c.Host
	}
	return proto + "://" + c.Host + ":" + strconv.Itoa(c.Port)
}
func newAPIServerConfig(v *gviper.Viper) APIServerConfig {
	if v == nil {
		return APIServerConfig{}
	}
	return APIServerConfig{
		Scheme: v.GetString("scheme"),
		Host:   v.GetString("host"),
		Port:   v.GetInt("port"),
	}
}

type NatTraversalRegionNode struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	HostName string `json:"hostname"`
	StunPort int    `json:"stun_port"`
	DerpPort int    `json:"derp_port"`
	StunOnly bool   `json:"stun_only"`
}

type NatTraversalRegion struct {
	ID    int                      `json:"id"`
	Code  string                   `json:"code"`
	Name  string                   `json:"name"`
	Nodes []NatTraversalRegionNode `json:"nodes"`
}

func loadPacFile(file string) (string, error) {
	contents, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	if len(contents) == 0 {
		return "", fmt.Errorf("empty pac file for %v", file)
	}
	return string(contents), nil
}

type PacFile struct {
	Name       string `json:"name"`
	FileName   string `json:"file"`
	PacContent string // Read from file.
	IsValid    bool
}

type PostgresDBConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	Username string `json:"username"`
	DBName   string `json:"db_name"`
	SslMode  string `json:"ssl_mode"`
	TimeZone string `json:"time_zone"`
}

type OauthLoginConfig struct {
	Provider     string `mapstructure:"provider"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	TeamID       string `mapstructure:"team_id,omitempty"` // For Apple login.
	KeyID        string `mapstructure:"key_id,omitempty"`  // For Apple login.
}

type SendSMSConfig struct {
	Provider        string `mapstructure:"provider"`
	RegionID        string `mapstructure:"region_id"`
	AccessKeyID     string `mapstructure:"access_key_id"`
	AccessKeySecret string `mapstructure:"access_key_secret"`
	RequestSignName string `mapstructure:"request_sign_name"`
}
type SendSMSInterface interface {
	Send(phoneNum, code string) error
}
type SendEmailConfig struct {
	Provider           string `mapstructure:"provider"`
	FromAddress        string `mapstructure:"from_address"`
	LocalName          string `mapstructure:"local_name"`
	ServiceAccountFile string `mapstructure:"service_account_file"`
}

type Configuration struct {
	BaseURL       string           `json:"base_url"`
	ListeningAddr string           `json:"listening_addr"`
	IPDrawer      APIServerConfig  `json:"ip_drawer"`
	ETCDEndpoints []string         `json:"etcd_endpoints"`
	ETCDPrefix    string           `json:"etcd_prefix"`
	Redis         APIServerConfig  `json:"redis"`
	RedisPrefix   string           `json:"redis_prefix"`
	Postgres      PostgresDBConfig `json:"postgres"`

	// Optional configs.
	Supervisor    APIServerConfig `json:"supervisor,omitempty"`
	Elasticsearch APIServerConfig `json:"elastic_search,omitempty"`
	Prometheus    APIServerConfig `json:"prometheus,omitempty"`

	// SMS code provider config.
	SendSMSConfig   SendSMSConfig   `json:"send_sms_config,omitempty"`
	SendEmailConfig SendEmailConfig `json:"send_email_config,omitempty"`

	// Oauth configs.
	OauthLogins []OauthLoginConfig `json:"oauth_logins"`

	// To be refactored.
	DomainName          string               `json:"domain_name"`
	MeetingBaseURL      string               `json:"meeting_base_url,omitempty"`
	DefaultWgServerName string               `json:"default_wg_server_name,omitempty"`
	NatTraversal        []NatTraversalRegion `json:"nat_regions"`
	PacFiles            []PacFile            `json:"internal_pac_files"`
}

func (c Configuration) OauthCallbackURL() string {
	base := os.Getenv("CYLONIX_UI_BASE_URL")
	if base == "" {
		base = c.BaseURL
	}
	log.Printf("oauth callback base url: %v\n", base)
	return base + "/manager/v2/login/oauth/callback"
}

func LoginURL(sessionID string) string {
	base := os.Getenv("CYLONIX_UI_BASE_URL")
	if base == "" {
		base = gConfig.BaseURL
	}
	log.Printf("Login base url: %v\n", base)
	return base + "/login/" + sessionID
}

func LoginURLToSessionID(loginURL string) (string, error) {
	parts := strings.Split(loginURL, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid login URL %v", loginURL)
	}
	sessionID := parts[len(parts)-1]
	if sessionID == "" {
		return "", fmt.Errorf("invalid login URL %v", loginURL)
	}
	return sessionID, nil
}

var (
	gConfig          Configuration
	sendSmsInterface SendSMSInterface

	oauthProviderMap = make(map[string]oauth.Provider)
	ErrInvalidConfig = errors.New("invalid config")
)

type ConfigCheckSetting struct {
	IPDrawer      bool
	Supervisor    bool
	ETCD          bool
	Redis         bool
	Postgres      bool
	Elasticsearch bool
	Prometheus    bool
}

func getConfigFromViper() (*Configuration, error) {
	c := Configuration{
		BaseURL:       viper.GetString("base_url"),
		ListeningAddr: viper.GetString("listening_addr"),
		ETCDPrefix:    viper.GetString("etcd_prefix"),
		ETCDEndpoints: strings.Split(viper.GetString("etcd_endpoints"), ","),
		RedisPrefix:   viper.GetString("redis_prefix"),
		IPDrawer:      newAPIServerConfig(viper.Sub("ip_drawer")),
		Redis:         newAPIServerConfig(viper.Sub("redis")),
		Supervisor:    newAPIServerConfig(viper.Sub("supervisor")),
		Elasticsearch: newAPIServerConfig(viper.Sub("elastic_search")),
		Prometheus:    newAPIServerConfig(viper.Sub("prometheus")),
	}
	if v := viper.Sub("postgres"); v != nil {
		c.Postgres = PostgresDBConfig{
			Host:     v.GetString("host"),
			Port:     v.GetInt("port"),
			Username: v.GetString("username"),
			Password: v.GetString("password"),
			DBName:   v.GetString("db_name"),
			SslMode:  "disable",
		}
	}

	logins := []OauthLoginConfig{}
	if err := viper.UnmarshalKey("oauth_logins", &logins); err == nil {
		for _, l := range logins {
			if l.ClientID != "" && l.ClientSecret != "" {
				log.Printf("added %v oauth login", l.Provider)
				c.OauthLogins = append(c.OauthLogins, l)
			}
		}
	} else {
		log.Printf("failed to parse oauth login configs: %v", err)
	}
	if v := viper.Sub("send_sms_config"); v != nil {
		if err := v.Unmarshal(&c.SendSMSConfig); err != nil {
			return nil, fmt.Errorf("failed to parse send sms config: %v", v)
		}
		log.Printf("added send sms config from %v", c.SendSMSConfig.Provider)
	}
	if v := viper.Sub("send_email_config"); v != nil {
		if err := v.Unmarshal(&c.SendEmailConfig); err != nil {
			return nil, fmt.Errorf("failed to parse send email config: %v", v)
		}
		log.Printf("added send email config from %v", c.SendEmailConfig.Provider)
	}
	if v := viper.Sub("supervisor"); v != nil {
		if err := v.Unmarshal(&c.Supervisor); err != nil {
			return nil, fmt.Errorf("failed to parse supervisor config: %v", v)
		}
		log.Printf("added supervisor config from %v", c.Supervisor.Host)
	}
	return &c, nil
}

func InitCfgFromViper(viperIn *gviper.Viper, setting ConfigCheckSetting) (*Configuration, error) {
	if viper == nil {
		Init(viperIn)
	}

	cfg, err := getConfigFromViper()
	if err != nil {
		return nil, err
	}
	gConfig = *cfg

	if setting.IPDrawer {
		if gConfig.IPDrawer.IsZero() {
			return nil, errors.New("invalid ip drawer config")
		}
	}
	if setting.Postgres {
		cfg := &gConfig.Postgres
		if cfg.DBName == "" ||
			cfg.Host == "" || cfg.Port == 0 ||
			cfg.Username == "" || cfg.Password == "" {
			return nil, errors.New("invalid postgres config")
		}
	}
	if setting.ETCD {
		if len(gConfig.ETCDEndpoints) <= 0 {
			return nil, errors.New("invalid etcd config")
		}
	}
	if setting.Redis {
		if gConfig.Redis.IsZero() {
			return nil, errors.New("invalid redis")
		}
	}
	if err = checkOidcConfig(setting); err != nil {
		return nil, err
	}

	for i, pac := range gConfig.PacFiles {
		content, err := loadPacFile(pac.FileName)
		if err != nil {
			return nil, err
		}
		gConfig.PacFiles[i].PacContent = content
		gConfig.PacFiles[i].IsValid = true
	}


	if gConfig.BaseURL == "" {
		return nil, errors.New("daemon base URL is not set")
	}
	return &gConfig, nil
}

func ETCDEndpoints() ([]string, error) {
	return gConfig.ETCDEndpoints, nil
}
func ETCDPrefix() string {
	return gConfig.ETCDPrefix
}

func PostgresConfig() (dsn, dbName string, err error) {
	cfg := gConfig.Postgres
	dsn = fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%d sslmode=%s %s",
		cfg.Host, cfg.Username, cfg.Password, cfg.DBName, cfg.Port, cfg.SslMode,
		cfg.TimeZone,
	)
	dbName = cfg.DBName
	if cfg.Host == "" || cfg.Username == "" || cfg.Password == "" || cfg.DBName == "" {
		err = fmt.Errorf("invalid dsn: %v", dsn)
	}
	return
}
func RedisConfig() (url string, prefix string, err error) {
	if gConfig.Redis.IsZero() {
		return "", "", fmt.Errorf("invalid redis config %v", gConfig.Redis)
	}
	return gConfig.Redis.URL(false), gConfig.RedisPrefix, nil
}

func GetIPDrawerConfig() (string, string, int, error) {
	host := gConfig.IPDrawer.Host
	port := gConfig.IPDrawer.Port
	schema := gConfig.IPDrawer.Scheme
	return schema, host, port, nil
}

func checkOidcConfig(setting ConfigCheckSetting) error {
	for _, v := range gConfig.OauthLogins {
		log.Printf("checking %v login...", v.Provider)
		// Skip entries with empty client ID or secret.
		if v.ClientID == "" || v.ClientSecret == "" {
			log.Printf("skipping %v login with empty client ID or secret", v.Provider)
			continue
		}
		provider, err := oauth.NewOAuth(oauth.Config{
			Provider:     v.Provider,
			ClientID:     v.ClientID,
			ClientSecret: v.ClientSecret,
			RedirectURI:  gConfig.OauthCallbackURL(),
			TeamID:       v.TeamID,
			KeyID:        v.KeyID,
		})
		if err != nil {
			return err
		}
		oauthProviderMap[v.Provider] = provider
	}
	return nil
}

func UserApprovalStateSeeOtherURL(state string) string {
	return gConfig.BaseURL + "/303/" + state
}

func UserLoginErrorURL(err string) string {
	return gConfig.BaseURL + "/303/" + err
}

func GetAuthProvider(namespace, provider string) (oauth.Provider, error) {
	if auth, ok := oauthProviderMap[provider]; ok {
		return auth, nil
	}
	return nil, ErrInvalidAuthProvider
}

func AuthProviders() []string {
	var list []string
	for _, v := range gConfig.OauthLogins {
		list = append(list, v.Provider)
	}
	return list
}

func GetElasticsearchURL() string {
	return gConfig.Elasticsearch.URL(true)
}

func GetPrometheusURL() string {
	return gConfig.Prometheus.URL(true)
}

func GetSupervisorConfig(useDefault bool) (proto string, host string, port int, err error) {
	proto, host, port = gConfig.Supervisor.Scheme, gConfig.Supervisor.Host, gConfig.Supervisor.Port

	if gConfig.Supervisor.IsZero() {
		// Check default configure allowed or not.
		if !useDefault {
			err = ErrInvalidConfig
			return
		}
		if proto == "" {
			proto = "http"
		}
		if host == "" {
			host = "localhost"
		}
		if port <= 0 {
			port = 8989
		}
	}
	return
}

func GetNatRegions() []NatTraversalRegion {
	return gConfig.NatTraversal
}

func GetPacFileList() []PacFile {
	return gConfig.PacFiles
}

func DefaultWgServerName() string {
	return gConfig.DefaultWgServerName
}

func DefaultMeetingServer(namespace string) string {
	return strings.ReplaceAll(namespace, ".", "-") + "-meet" + gConfig.MeetingBaseURL
}

func SendSmsCode(phone, code string) error {
	if sendSmsInterface == nil {
		return errors.New("send sms is not provisioned")
	}
	return sendSmsInterface.Send(phone, code)
}
func GetCylonixAdminInfo() (namespace, username, password, email, firstName, lastName string) {
	namespace = SysAdminNamespace
	username = viper.GetString("sys_admin.username")
	password = viper.GetString("sys_admin.password")
	email = viper.GetString("sys_admin.email")
	firstName = viper.GetString("sys_admin.first_name")
	lastName = viper.GetString("sys_admin.last_name")
	if username == "" {
		username = "admin"
	}
	return
}

// TODO: make this per config.
func DefaultPermitCIDRList() []string {
	return []string{"8.8.8.8/32", "8.8.4.4/32", "9.9.9.9/32"}
}

// TODO: add controller FQDN.
func DefaultPermitFQDNList() []string {
	return []string{}
}
