// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package keycloak

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/cylonix/utils/namehash"
	pw "github.com/cylonix/utils/password"
	"github.com/google/uuid"
)

const (
	AdminRolePrefix = "sase-admin-"
	SysadminRole    = "sase-master-admin"
)

// Key cloak user has many details that it probably wouldn't work if
// tenant has their own IDP and they will only export limited information to us
// Let's kept the user detail agnostic to the IDP and the must haves only.
// Or we can directly use the open api user model so that we don't have to
// fill-in the information multiple times.
type UserDetail struct {
	ID            *string             `json:"id,omitempty"`
	Username      *string             `json:"username,omitempty"`
	Enabled       *bool               `json:"enabled,omitempty"`
	EmailVerified *bool               `json:"emailVerified,omitempty"`
	FirstName     *string             `json:"firstName,omitempty"`
	LastName      *string             `json:"lastName,omitempty"`
	Email         *string             `json:"email,omitempty"`
	Department    string              `json:"department,omitempty"`
	Namespace     string              `json:"namespace,omitempty"`
	Phone         string              `json:"phone,omitempty"`
	HeadImgUrl    string              `json:"head_img_url,omitempty"`
	Attributes    map[string][]string `json:"attributes,omitempty"`
	ClientRoles   map[string][]string `json:"clientRoles,omitempty"`
}
type KeyCloakInterface interface {
	NamespaceList() ([]string, error)
	Range(namespace string, callback func(user *UserDetail) error) error
	UserList(realm string, includeClientRoles bool) ([]*gocloak.User, error)
	CreateUser(userDetail *UserDetail, secret string, attributes map[string][]string) (string, error)
	UserLogin(username, password string) (string, error)
	SetPassword(namespace, userID, password string) error
	GetUserByID(realm, userID string) (*gocloak.User, error)
	GetUserByUsername(realm, username string) (*gocloak.User, error)
	RealmExists(realm string) bool
	UpdateUser(realm string, user *gocloak.User) error
	GetUserAttribute(realm, userID, attr string) ([]string, bool)
	GetUserAttributes(realm, userID, attr string) (map[string][]string, bool)
	NewRealm(namespace string, companyName string) error
	DeleteRealm(namespace string) error
	AddClientRolesToUser(namespace, userID string, roleNameList []string) error
	CreateClientRole(namespace, roleName string) error
	GetClientRole(namespace, roleName string) (*gocloak.Role, error)
	GetClientRoles(namespace string, params gocloak.GetRoleParams) ([]*gocloak.Role, error)
	DeleteClientRole(namespace, roleName string) error
	DeleteUser(namespace, userID string) error
	CheckPassword(namespace, username, password string) (bool, error)
}

var (
	instance            KeyCloakInterface
	ErrInstanceInvalid  = errors.New("instance invalid")
	ErrUserNotExists    = errors.New("user does not exist")
	ErrUserExists       = errors.New("user exists")
	kcRequestExpireTime = 5 // seconds
)

type Config struct {
	url           string
	clientID      string
	token         string
	realm         string
	adminUsername string
	adminPassword string
	redirectURLs  []string
}

func SetInstance(i KeyCloakInterface) {
	instance = i
}
func GetInstance() KeyCloakInterface {
	return instance
}
func NewConfig(url, clientID, clientRealm, adminUsername, adminPassword string, redirectURLs []string) *Config {
	return &Config{
		url:           url,
		clientID:      clientID,
		realm:         clientRealm,
		adminUsername: adminUsername,
		adminPassword: adminPassword,
		redirectURLs:  redirectURLs,
	}
}

type Emulator struct {
	userMap map[string]interface{}
}

func NewEmulator() (*Emulator, error) {
	return &Emulator{
		userMap: make(map[string]interface{}),
	}, nil
}

type Impl struct {
	config         *Config
	client         *gocloak.GoCloak
	token          *gocloak.JWT
	tokenExpiresAt time.Time
}

func NewImpl(config *Config) *Impl {
	return &Impl{config: config}
}

func UpdateUser(realm string, user *gocloak.User) error {
	if instance != nil {
		return instance.UpdateUser(realm, user)
	}
	return ErrInstanceInvalid
}
func GetNamespaceListFromKC() ([]string, error) {
	if instance != nil {
		return instance.NamespaceList()
	}
	return nil, ErrInstanceInvalid
}
func Range(namespace string, callback func(user *UserDetail) error) error {
	if instance != nil {
		return instance.Range(namespace, callback)
	}
	return ErrInstanceInvalid
}
func NamespaceExists(namespace string) bool {
	if instance != nil {
		return instance.RealmExists(namespace)
	}
	return false
}
func CheckPassword(namespace, username, password string) (bool, error) {
	if instance != nil {
		return instance.CheckPassword(namespace, username, password)
	}
	return false, ErrInstanceInvalid
}
func UserList(realm string, includeClientRoles bool) ([]*gocloak.User, error) {
	if instance != nil {
		return instance.UserList(realm, includeClientRoles)
	}
	return nil, ErrInstanceInvalid
}
func CreateUser(userDetail *UserDetail, secret string, attributes map[string][]string) (string, error) {
	if instance != nil {
		return instance.CreateUser(userDetail, secret, attributes)
	}
	return "", ErrInstanceInvalid
}
func GetUserAttribute(realm string, userID string, attr string) ([]string, bool) {
	if instance != nil {
		return instance.GetUserAttribute(realm, userID, attr)
	}
	return nil, false
}
func GetUserAttributes(realm string, userID string, attr string) (map[string][]string, bool) {
	if instance != nil {
		return instance.GetUserAttributes(realm, userID, attr)
	}
	return nil, false
}
func UserLogin(username string, password string) (string, error) {
	if instance != nil {
		return instance.UserLogin(username, password)
	}
	return "", ErrInstanceInvalid
}
func SetPassword(namespace string, userID string, password string) error {
	if instance != nil {
		return instance.SetPassword(namespace, userID, password)
	}
	return ErrInstanceInvalid
}
func SetUsername(namespace string, userID string, username string) error {
	if instance != nil {
		user := gocloak.User{
			ID:       &userID,
			Username: &username,
		}
		return instance.UpdateUser(namespace, &user)
	}
	return ErrInstanceInvalid
}
func GetUserByID(realm, userID string) (*gocloak.User, error) {
	if instance != nil {
		return instance.GetUserByID(realm, userID)
	}
	return nil, ErrInstanceInvalid
}
func GetUserByUsername(realm, username string) (*gocloak.User, error) {
	if instance != nil {
		return instance.GetUserByUsername(realm, username)
	}
	return nil, ErrInstanceInvalid
}
func NewRealm(namespace string, companyName string) error {
	if instance != nil {
		return instance.NewRealm(namespace, companyName)
	}
	return ErrInstanceInvalid
}
func DeleteRealm(namespace string) error {
	if instance != nil {
		return instance.DeleteRealm(namespace)
	}
	return ErrInstanceInvalid
}
func AddClientRolesToUser(namespace, userID string, roleNameList []string) error {
	if instance != nil {
		return instance.AddClientRolesToUser(namespace, userID, roleNameList)
	}
	return ErrInstanceInvalid
}
func CreateClientRole(namespace, roleName string) error {
	if instance != nil {
		return instance.CreateClientRole(namespace, roleName)
	}
	return ErrInstanceInvalid
}
func GetClientRole(namespace, roleName string) (*gocloak.Role, error) {
	if instance != nil {
		return instance.GetClientRole(namespace, roleName)
	}
	return nil, ErrInstanceInvalid
}
func GetClientRoles(namespace string, params gocloak.GetRoleParams) ([]*gocloak.Role, error) {
	if instance != nil {
		return instance.GetClientRoles(namespace, params)
	}
	return nil, ErrInstanceInvalid
}
func DeleteClientRole(namespace, roleName string) error {
	if instance != nil {
		return instance.DeleteClientRole(namespace, roleName)
	}
	return ErrInstanceInvalid
}
func DeleteUser(namespace, userID string) error {
	if instance != nil {
		return instance.DeleteUser(namespace, userID)
	}
	return ErrInstanceInvalid
}

func RealmClientID(namespace string) string {
	return namespace + "-auth"
}
func getContextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.TODO(), time.Second*time.Duration(kcRequestExpireTime))
}

// Real client.
func (impl *Impl) InitAdminRealm(namespace, username, password, email, firstName, lastName string) error {
	if namespace == "" || username == "" {
		return fmt.Errorf(
			"init admin realm failed: namespace=[%s] username=[%s]",
			namespace, username,
		)
	}
	if impl == nil {
		return ErrInstanceInvalid
	}
	if !impl.RealmExists(namespace) {
		if err := impl.NewRealm(namespace, namespace); err != nil {
			return fmt.Errorf("create realm failed: %w", err)
		}
	}
	adminRoleName := AdminRolePrefix + namespace
	masterRoleName := SysadminRole
	if _, err := impl.GetClientRole(namespace, adminRoleName); err != nil {
		if err := impl.CreateClientRole(namespace, adminRoleName); err != nil {
			return fmt.Errorf("create admin client role failed: %w", err)
		}
	}
	if _, err := impl.GetClientRole(namespace, masterRoleName); err != nil {
		if err := impl.CreateClientRole(namespace, masterRoleName); err != nil {
			return fmt.Errorf("create master client role failed: %w", err)
		}
	}
	_, err := impl.GetUserByUsername(namespace, username)
	if err != nil && errors.Is(err, ErrUserNotExists) {
		if !pw.IsValid(password) {
			return errors.New("invalid password to create the sys admin user")
		}
		if email == "" {
			email = username + "@cylonix.io"
		}
		if firstName == "" {
			firstName = username
		}
		if lastName == "" {
			lastName = "empty"
		}
		userDetail := UserDetail{
			Username:    gocloak.StringP(username),
			Enabled:     gocloak.BoolP(true),
			Namespace:   namespace,
			Email:       gocloak.StringP(email),
			FirstName:   gocloak.StringP(firstName),
			LastName:    gocloak.StringP(lastName),
			ClientRoles: map[string][]string{RealmClientID(namespace): {adminRoleName, masterRoleName}},
		}
		if _, err := impl.CreateUser(&userDetail, password, nil); err != nil {
			return fmt.Errorf("create admin user failed: %w", err)
		}
	}

	return nil
}
func (impl *Impl) DeleteRealm(namespace string) error {
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return err
	}
	return client.DeleteRealm(ctx, token.AccessToken, namespace)
}

func (impl *Impl) NewRealm(namespace, companyName string) error {
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return err
	}
	ckClient := gocloak.Client{
		ID: gocloak.StringP(RealmClientID(namespace)),
		ProtocolMappers: &[]gocloak.ProtocolMapperRepresentation{
			{
				ID:             gocloak.StringP(uuid.New().String()),
				Name:           gocloak.StringP("user-attribute"),
				Protocol:       gocloak.StringP("openid-connect"),
				ProtocolMapper: gocloak.StringP("oidc-usermodel-attribute-mapper"),
				Config: &map[string]string{
					"user.attribute":       "department",
					"claim.name":           "department",
					"multivalued":          "true",
					"jsonType.label":       "String",
					"id.token.claim":       "true",
					"access.token.claim":   "true",
					"userinfo.token.claim": "true",
				},
			},
			{
				ID:             gocloak.StringP(uuid.New().String()),
				Name:           gocloak.StringP("client-role-map"),
				Protocol:       gocloak.StringP("openid-connect"),
				ProtocolMapper: gocloak.StringP("oidc-usermodel-client-role-mapper"),
				Config: &map[string]string{
					"claim.name":           "client_role_map",
					"multivalued":          "true",
					"jsonType.label":       "String",
					"id.token.claim":       "true",
					"access.token.claim":   "true",
					"userinfo.token.claim": "true",
				},
			},
		},
		// DefaultClientScopes:       &[]string{RealmClientID(namespace)},
		DirectAccessGrantsEnabled: gocloak.BoolP(true),
		ServiceAccountsEnabled:    gocloak.BoolP(true),
		RedirectURIs:              &impl.config.redirectURLs,
		PublicClient:              gocloak.BoolP(true),
	}
	defaultRole := "sase-user-" + namespace
	realm := gocloak.RealmRepresentation{
		Realm: gocloak.StringP(namespace),
		Clients: &[]gocloak.Client{
			ckClient,
		},
		Roles: &gocloak.RolesRepresentation{
			Realm: &[]gocloak.Role{
				{Name: gocloak.StringP(defaultRole)},
			},
		},
		DefaultRoles:    &[]string{defaultRole},
		Enabled:         gocloak.BoolP(true),
		VerifyEmail:     gocloak.BoolP(true),
		SslRequired:     gocloak.StringP("none"),
		DisplayName:     gocloak.StringP(companyName),
		DisplayNameHTML: gocloak.StringP(companyName),
	}
	_, err = client.CreateRealm(ctx, token.AccessToken, realm)
	if err != nil {
		return err
	}
	return nil
}
func (impl *Impl) GetClient(namespace string) (*gocloak.Client, error) {
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return nil, err
	}
	clientID := RealmClientID(namespace)
	return impl.getClient(ctx, client, token, namespace, clientID)
}

func (impl *Impl) GetClientRole(namespace, roleName string) (*gocloak.Role, error) {
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return nil, err
	}
	clientID := RealmClientID(namespace)
	id, err := impl.GetIDOfClient(ctx, client, token, namespace, clientID)
	if err != nil {
		return nil, err
	}
	role, err := client.GetClientRole(ctx, token.AccessToken, namespace, id, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to get client role for %v/%v: %w", namespace, clientID, err)
	}
	return role, nil
}
func (impl *Impl) GetClientRoles(namespace string, params gocloak.GetRoleParams) ([]*gocloak.Role, error) {
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return nil, err
	}
	clientID := RealmClientID(namespace)
	id, err := impl.GetIDOfClient(ctx, client, token, namespace, clientID)
	if err != nil {
		return nil, err
	}
	roles, err := client.GetClientRoles(ctx, token.AccessToken, namespace, id, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get client roles for %v/%v: %w", namespace, clientID, err)
	}
	return roles, nil
}
func (impl *Impl) CreateClientRole(namespace, roleName string) error {
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return err
	}
	role := gocloak.Role{
		Name: &roleName,
	}
	clientID := RealmClientID(namespace)
	id, err := impl.GetIDOfClient(ctx, client, token, namespace, RealmClientID(namespace))
	if err != nil {
		return err
	}
	_, err = client.CreateClientRole(ctx, token.AccessToken, namespace, id, role)
	if err != nil {
		return fmt.Errorf("failed to create client role for %v/%v: %w", namespace, clientID, err)
	}
	return nil
}
func (impl *Impl) DeleteClientRole(namespace, roleName string) error {
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return err
	}
	clientID := RealmClientID(namespace)
	id, err := impl.GetIDOfClient(ctx, client, token, namespace, clientID)
	if err != nil {
		return err
	}
	err = client.DeleteClientRole(ctx, token.AccessToken, namespace, id, roleName)
	if err != nil {
		return fmt.Errorf("failed to delete client role for %v/%v: %w", namespace, clientID, err)
	}
	return nil
}
func (impl *Impl) AddClientRolesToUser(namespace, userID string, roleNameList []string) error {
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return err
	}

	clientID := RealmClientID(namespace)
	id, err := impl.GetIDOfClient(ctx, client, token, namespace, clientID)
	if err != nil {
		return err
	}
	return impl.addClientRolesToUser(ctx, client, token, namespace, id, userID, roleNameList)
}

func (impl *Impl) addClientRolesToUser(ctx context.Context, client *gocloak.GoCloak, token *gocloak.JWT, realm, idOfClient, userID string, roleNameList []string) error {
	roleList := []gocloak.Role{}
	for _, roleName := range roleNameList {
		r, err := client.GetClientRole(ctx, token.AccessToken, realm, idOfClient, roleName)
		if err != nil {
			// Only add roles that exists.
			continue
		}
		roleList = append(roleList, *r)
	}
	err := client.AddClientRolesToUser(ctx, token.AccessToken, realm, idOfClient, userID, roleList)
	if err != nil {
		return fmt.Errorf("failed to add client roles to user %v/%v/%v: %w", realm, idOfClient, userID, err)
	}
	return nil
}
func (impl *Impl) newAdminLogin(ctx context.Context) (*gocloak.GoCloak, *gocloak.JWT, error) {
	c := impl.config
	client := gocloak.NewClient(c.url)
	token, err := client.LoginAdmin(ctx, c.adminUsername, c.adminPassword, "master")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to login as admin: %w", err)
	}
	return client, token, nil
}

func (impl *Impl) adminLogin(ctx context.Context) (*gocloak.GoCloak, *gocloak.JWT, error) {
	if impl.token != nil && impl.tokenExpiresAt.After(time.Now()) {
		return impl.client, impl.token, nil
	}
	client, token, err := impl.newAdminLogin(ctx)
	if err != nil {
		return nil, nil, err
	}
	impl.client = client
	impl.token = token
	impl.tokenExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	return client, token, nil
}

func (impl *Impl) UpdateUser(realm string, user *gocloak.User) error {
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return err
	}
	err = client.UpdateUser(ctx, token.AccessToken, realm, *user)
	if err != nil {
		return fmt.Errorf("failed to update user %s, %w", *user.Username, err)
	}
	return nil
}

func (impl *Impl) GetUserAttribute(realm, userID, attr string) ([]string, bool) {
	kcUser, err := GetUserByID(realm, userID)
	if err != nil {
		return nil, false
	}
	if kcUser.Attributes != nil {
		for k, v := range *kcUser.Attributes {
			if k == attr {
				return v, true
			}
		}
	}
	return nil, false
}

func (impl *Impl) GetUserAttributes(realm, userID, attr string) (map[string][]string, bool) {
	kcUser, err := GetUserByID(realm, userID)
	if err != nil {
		return nil, false
	}
	if kcUser.Attributes != nil {
		return *kcUser.Attributes, true
	}
	return nil, false
}
func (impl *Impl) NamespaceList() ([]string, error) {
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return nil, err
	}

	realms, err := client.GetRealms(ctx, token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get list of realms: %w", err)
	}
	namespaceList := make([]string, 0, len(realms))
	for _, realm := range realms {
		if realm.Realm == nil {
			return nil, fmt.Errorf("missing real name")
		}
		namespaceList = append(namespaceList, *realm.Realm)
	}
	return namespaceList, nil
}
func (impl *Impl) RealmExists(namespace string) bool {
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return false
	}
	_, err = client.GetRealm(ctx, token.AccessToken, namespace)
	return err == nil

}
func (impl *Impl) Range(namespace string, callback func(user *UserDetail) error) error {
	kcUserList, err := UserList(namespace, false)
	if err != nil {
		return err
	}

	for _, user := range kcUserList {
		// Must have an ID
		department := ""
		phone := ""
		if user.ID == nil {
			return fmt.Errorf("missing user ID, namespace %v", namespace)
		}
		if user.Attributes != nil {
			for key, value := range *user.Attributes {
				switch key {
				case "department":
					department = value[0]
				case "phone":
					phone = value[0]
				}
			}
		}
		u := &UserDetail{
			ID:            user.ID,
			Username:      user.Username,
			Enabled:       user.Enabled,
			FirstName:     user.FirstName,
			LastName:      user.LastName,
			EmailVerified: user.EmailVerified,
			Email:         user.Email,
			Department:    department,
			Phone:         phone,
		}
		if err = callback(u); err != nil {
			return err
		}
	}
	return nil
}

// This potentially going to fetch a lot of users. Use with caution.
func (impl *Impl) UserList(realm string, includeClientRoles bool) ([]*gocloak.User, error) {
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return nil, err
	}
	usersParams := gocloak.GetUsersParams{}
	// Get the count first.
	// TODO: what if the users are quite a lot will it be an issue?
	count, err := client.GetUserCount(ctx, token.AccessToken, realm, usersParams)
	if err != nil {
		return nil, fmt.Errorf("failed to get user count for realm %v: %w", realm, err)
	}
	usersParams.Max = &count
	userList, err := client.GetUsers(ctx, token.AccessToken, realm, usersParams)
	if err != nil {
		return nil, fmt.Errorf("failed to get users for realm %v: %w", realm, err)
	}
	if includeClientRoles {
		// For each of the user. Get the client roles.
		// This should only be done for small set of users e.g. admin users.
		clientID := RealmClientID(realm)
		idOfClient, err := impl.GetIDOfClient(ctx, client, token, realm, clientID)
		if err != nil {
			return nil, err
		}
		for _, u := range userList {
			if u.ID == nil {
				continue
			}
			roles, err := impl.getUserClientRoles(ctx, client, token, realm, idOfClient, *u.ID)
			if err != nil {
				username := ""
				if u.Username != nil {
					username = *u.Username
				}
				return nil, fmt.Errorf("failed to get user %v roles", username)
			}
			clientRoles := map[string][]string{clientID: roles}
			u.ClientRoles = &clientRoles
		}
	}
	return userList, nil
}

func (impl *Impl) CreateUser(userDetail *UserDetail, secret string, attributes map[string][]string) (string, error) {
	namespace := userDetail.Namespace
	if namespace == "" {
		namespace = "cylonix"
	}
	credentials := []gocloak.CredentialRepresentation{
		{
			Type:  gocloak.StringP("secret"),
			Value: gocloak.StringP(secret),
		},
	}
	emailVerified, enabled := gocloak.BoolP(true), gocloak.BoolP(true)
	if userDetail.EmailVerified != nil {
		emailVerified = userDetail.EmailVerified
	}
	if userDetail.Enabled != nil {
		enabled = userDetail.Enabled
	}
	if attributes == nil {
		attributes = make(map[string][]string)
	}
	clientRoles := userDetail.ClientRoles
	if clientRoles == nil {
		clientRoles = make(map[string][]string)
	}
	if userDetail.Phone != "" {
		if v, ok := attributes["phone"]; !ok || len(v) <= 0 {
			attributes["phone"] = []string{userDetail.Phone}
		}
	}
	if userDetail.Department != "" {
		if v, ok := attributes["department"]; !ok || len(v) <= 0 {
			attributes["department"] = []string{userDetail.Department}
		}
	}
	attributes["namespace"] = []string{namespace}
	user := gocloak.User{
		FirstName:     userDetail.FirstName,
		LastName:      userDetail.LastName,
		Email:         userDetail.Email,
		EmailVerified: emailVerified,
		Enabled:       enabled,
		Username:      userDetail.Username,
		Attributes:    &attributes,
		Credentials:   &credentials,
		ClientRoles:   &clientRoles,
	}
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return "", err
	}
	kcID, err := client.CreateUser(ctx, token.AccessToken, namespace, user)
	if err != nil {
		return "", err
	}

	if len(clientRoles) <= 0 {
		return kcID, nil
	}

	// Delete user if failed to add client roles.
	defer func() {
		if err != nil {
			client.DeleteUser(ctx, token.AccessToken, namespace, kcID)
		}
	}()

	// Add client roles one by one since the create user API does not really
	// add the roles to the user.
	for k, v := range clientRoles {
		idOfClient, newErr := impl.GetIDOfClient(ctx, client, token, namespace, k)
		if err != nil {
			err = newErr
			return "", fmt.Errorf("failed to get id for client %v: %w", k, err)
		}
		if err = impl.addClientRolesToUser(ctx, client, token, namespace, idOfClient, kcID, v); err != nil {
			return "", fmt.Errorf("failed to add roles to user for client %v: %w", k, err)
		}
	}
	return kcID, nil
}

func (impl *Impl) DeleteUser(namespace string, userID string) error {
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return err
	}
	return client.DeleteUser(ctx, token.AccessToken, namespace, userID)
}
func (impl *Impl) UserLogin(username string, password string) (string, error) {
	c := impl.config
	client := gocloak.NewClient(c.url)
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	jwt, err := client.Login(ctx, c.clientID, c.token, c.realm, username, password)
	if err != nil {
		return "", fmt.Errorf("failed to login user %v: %w", username, err)
	}
	token := jwt.RefreshToken
	return token, nil
}

// Get the ID generated by keycloak for a client.
func (impl *Impl) GetIDOfClient(ctx context.Context, client *gocloak.GoCloak, token *gocloak.JWT, realm, clientID string) (string, error) {
	c, err := impl.getClient(ctx, client, token, realm, clientID)
	if err != nil {
		return "", err
	}
	if c != nil && c.ID != nil {
		return *c.ID, nil
	}
	return "", nil
}

// Get the ID generated by keycloak for a client.
func (impl *Impl) getClient(ctx context.Context, client *gocloak.GoCloak, token *gocloak.JWT, realm, clientID string) (*gocloak.Client, error) {
	clients, err := client.GetClients(ctx, token.AccessToken, realm, gocloak.GetClientsParams{ClientID: &clientID})
	if err != nil {
		return nil, fmt.Errorf("failed to get clients of %v/%v: %w", realm, clientID, err)
	}
	for _, client := range clients {
		if client.ClientID != nil && *client.ClientID == clientID {
			return client, nil
		}
	}
	return nil, nil
}

func (impl *Impl) CheckPassword(namespace, username, password string) (bool, error) {
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return false, err
	}
	credentials, err := client.GetCredentials(ctx, token.AccessToken, namespace, username)
	if err != nil {
		return false, fmt.Errorf("failed to get user credentials %v: %w", username, err)
	}
	for _, credential := range credentials {
		if credential.Value != nil && *credential.Value == password {
			return true, nil
		}
	}
	return false, nil
}
func (impl *Impl) SetPassword(namespace, userID, password string) error {
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return err
	}
	err = client.SetPassword(ctx, token.AccessToken, userID, namespace, password, false)
	if err != nil {
		return fmt.Errorf("failed to set password for user ID %v: %w", userID, err)
	}
	return nil
}

func (impl *Impl) getUserClientRoles(ctx context.Context, client *gocloak.GoCloak, token *gocloak.JWT, realm, idOfClient, userID string) ([]string, error) {
	roles, err := client.GetClientRolesByUserID(ctx, token.AccessToken, realm, idOfClient, userID)
	if err != nil {
		return nil, err
	}
	var roleNames []string
	for _, r := range roles {
		n := ""
		if r.Name != nil {
			n = *r.Name
		}
		roleNames = append(roleNames, n)
	}
	return roleNames, nil
}

func (impl *Impl) GetUserByID(realm, userID string) (*gocloak.User, error) {
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return nil, err
	}
	kcUser, err := client.GetUserByID(ctx, token.AccessToken, realm, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user for user ID %v: %w", userID, err)
	}
	clientID := RealmClientID(realm)
	idOfClient, err := impl.GetIDOfClient(ctx, client, token, realm, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to get realm client id: %w", err)
	}

	roles, err := impl.getUserClientRoles(ctx, client, token, realm, idOfClient, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get client roles: %w", err)
	}
	clientRoles := map[string][]string{clientID: roles}
	kcUser.ClientRoles = &clientRoles
	return kcUser, nil
}
func (impl *Impl) GetUserByUsername(realm, username string) (*gocloak.User, error) {
	ctx, cancel := getContextWithTimeout()
	defer cancel()
	client, token, err := impl.adminLogin(ctx)
	if err != nil {
		return nil, err
	}
	userParam := gocloak.GetUsersParams{
		Username: &username,
		Exact:    gocloak.BoolP(false),
	}
	kcUsers, err := client.GetUsers(ctx, token.AccessToken, realm, userParam)
	if err == nil {
		if len(kcUsers) > 0 {
			for _, kcUser := range kcUsers {
				if *kcUser.Username == username {
					clientID := RealmClientID(realm)
					idOfClient, err := impl.GetIDOfClient(ctx, client, token, realm, clientID)
					if err != nil {
						return nil, fmt.Errorf("failed to get realm client id: %w", err)
					}
					roles, err := impl.getUserClientRoles(ctx, client, token, realm, idOfClient, *kcUser.ID)
					if err != nil {
						return nil, fmt.Errorf("failed to get client roles: %w", err)
					}
					clientRoles := map[string][]string{clientID: roles}
					kcUser.ClientRoles = &clientRoles
					return kcUser, nil
				}
			}
		}
		err = ErrUserNotExists
	}
	return nil, fmt.Errorf("failed to get user for %v: %w", username, err)
}

// Emulator for testing.
func (em *Emulator) CreateClientRole(namespace, roleName string) error {
	return nil
}
func (em *Emulator) CheckPassword(namespace, username, password string) (bool, error) {
	if em.userMap[username] == password {
		return true, nil
	}
	return false, nil
}
func (em *Emulator) GetClientRole(namespace, roleName string) (*gocloak.Role, error) {
	return nil, nil
}
func (em *Emulator) GetClientRoles(namespace string, params gocloak.GetRoleParams) ([]*gocloak.Role, error) {
	return nil, nil
}
func (em *Emulator) AddClientRolesToUser(namespace, userID string, roleNameList []string) error {
	return nil
}
func (em *Emulator) DeleteClientRole(namespace, roleName string) error {
	return nil
}
func (em *Emulator) DeleteUser(namespace, userID string) error {
	return nil
}
func (em *Emulator) DeleteRealm(namespace string) error {
	return nil
}
func (em *Emulator) NewRealm(namespace, realmName string) error {
	return nil
}
func (em *Emulator) UpdateUser(realm string, user *gocloak.User) error {
	return nil
}
func (em *Emulator) GetUserAttribute(realm, userID, attr string) ([]string, bool) {
	return nil, false
}
func (em *Emulator) GetUserAttributes(realm, userID, attr string) (map[string][]string, bool) {
	return nil, false
}
func (em *Emulator) GetUserByID(realm, userID string) (*gocloak.User, error) {
	return nil, nil
}
func (em *Emulator) RealmExists(namespace string) bool {
	return true
}
func (em *Emulator) GetUserByUsername(realm, username string) (*gocloak.User, error) {
	userID := namehash.New(realm + username)
	_, ok := em.userMap[userID]
	if ok {
		return &gocloak.User{
			ID: &userID,
		}, nil
	}
	return nil, ErrUserNotExists
}
func (em *Emulator) NamespaceList() ([]string, error) {
	return nil, nil
}
func (em *Emulator) Range(namespace string, callback func(user *UserDetail) error) error {
	return nil
}
func (em *Emulator) UserList(realm string, includeClientRoles bool) ([]*gocloak.User, error) {
	return nil, nil
}
func (em *Emulator) CreateUser(userDetail *UserDetail, secret string, attributes map[string][]string) (string, error) {
	namespace := userDetail.Namespace
	username := userDetail.Username
	userID := namehash.New(namespace + *username)
	if _, ok := em.userMap[userID]; ok {
		return "", ErrUserExists
	}
	kcId, _ := uuid.NewUUID()
	em.userMap[userID] = userDetail
	em.userMap[*username] = secret
	em.userMap[kcId.String()] = userDetail
	return kcId.String(), nil
}
func (em *Emulator) UserLogin(username, password string) (string, error) {
	pwd, ok := em.userMap[username]
	if ok {
		pwdStr, ok := pwd.(string)
		if ok && pwdStr == password {
			return "", nil
		}
	}
	return "", ErrUserNotExists
}
func (em *Emulator) SetPassword(namespace, userID, password string) error {
	user, ok := em.userMap[userID]
	if !ok {
		return ErrUserNotExists
	}
	userDetail, ok := user.(*UserDetail)
	if !ok || userDetail.Username == nil {
		return ErrUserNotExists
	}
	username := *userDetail.Username
	em.userMap[username] = password
	return nil
}
