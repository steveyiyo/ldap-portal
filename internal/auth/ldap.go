package auth

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-ldap/ldap"
	"github.com/joho/godotenv"
)

var ldapConn *ldap.Conn

func resetInit() {
	godotenv.Load()

	ldapUser := os.Getenv("LDAP_USER")
	ldapPwd := os.Getenv("LDAP_PASSWORD")

	var err error
	err = ldapConn.Bind(ldapUser, ldapPwd)
	if err != nil {
		log.Fatalf("Authorization Failed: %v", err)
	}
}

func init() {
	godotenv.Load()

	ldapServer := os.Getenv("LDAP_SERVER")
	ldapUser := os.Getenv("LDAP_USER")
	ldapPwd := os.Getenv("LDAP_PASSWORD")

	var err error
	ldapConn, err = ldap.Dial("tcp", ldapServer)
	if err != nil {
		log.Fatalf("Connection Failed: %v", err)
	}
	err = ldapConn.Bind(ldapUser, ldapPwd)
	if err != nil {
		log.Fatalf("Authorization Failed: %v", err)
	}

	log.Println("LDAP connection established and user bound successfully.")
}

type UserProfile struct {
	Uid          string
	HashPassword string
	Email        string
	FirstName    string
	LastName     string
}

func LeapCreateUser(userInfo UserProfile) error {
	resetInit()

	baseDN := fmt.Sprintf("ou=users,%s", os.Getenv("LDAP_SEARCH_BASE_DN"))
	if baseDN == "" {
		return fmt.Errorf("LDAP_SEARCH_BASE_DN not set")
	}
	if ldapConn == nil {
		return fmt.Errorf("ldap connection is nil")
	}

	dn := fmt.Sprintf("uid=%s,%s", userInfo.Uid, baseDN)
	addReq := ldap.NewAddRequest(dn, nil)
	addReq.Attribute("objectClass", []string{"top", "posixAccount", "person", "inetOrgPerson"})
	addReq.Attribute("uid", []string{userInfo.Uid})
	addReq.Attribute("sn", []string{userInfo.LastName})
	addReq.Attribute("givenName", []string{userInfo.FirstName})
	addReq.Attribute("cn", []string{userInfo.FirstName + " " + userInfo.LastName})
	addReq.Attribute("mail", []string{userInfo.Email})
	addReq.Attribute("userPassword", []string{userInfo.HashPassword})

	return ldapConn.Add(addReq)
}

func LdapAuthUser(username, password string) (bool, error) {
	resetInit()
	// Filter
	searchRequest := ldap.NewSearchRequest(
		fmt.Sprintf("ou=users,%s", os.Getenv("LDAP_SEARCH_BASE_DN")),
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(uid=%s)", username),
		[]string{"dn"},
		nil,
	)

	sr, err := ldapConn.Search(searchRequest)
	if err != nil {
		return false, fmt.Errorf("search failed: %v", err)
	}

	if len(sr.Entries) == 0 {
		return false, errors.New("user not found")
	}

	// If the user exists, attempt to bind (authenticate) using the user's DN and password
	userDN := sr.Entries[0].DN
	err = ldapConn.Bind(userDN, password)
	if err != nil {
		return false, fmt.Errorf("password verification failed: %v", err)
	}

	return true, nil // User authenticated successfully
}

func LdapGetUserInfo(username string) (map[string]string, error) {
	searchRequest := ldap.NewSearchRequest(
		fmt.Sprintf("ou=users,%s", os.Getenv("LDAP_SEARCH_BASE_DN")),
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(uid=%s)", username),
		[]string{"dn", "mail", "cn", "memberOf"},
		nil,
	)

	sr, err := ldapConn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("search failed: %v", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	userInfo := make(map[string]string)
	userInfo["dn"] = sr.Entries[0].DN
	userInfo["mail"] = sr.Entries[0].GetAttributeValue("mail")
	userInfo["cn"] = sr.Entries[0].GetAttributeValue("cn")
	userInfo["memberOf"] = sr.Entries[0].GetAttributeValue("memberOf")

	// jsonData, err := json.Marshal(userInfo)
	// if err != nil {
	// 	fmt.Println("Error marshaling user info:", err)
	// } else {
	// 	fmt.Println(string(jsonData))
	// }

	return userInfo, nil
}

func LdapChangePassword(username, oldPassword, newPassword string) error {
	resetInit()

	// Change password
	changeRequest := ldap.NewModifyRequest(
		fmt.Sprintf("uid=%s,%s", username, fmt.Sprintf("ou=users,%s", os.Getenv("LDAP_SEARCH_BASE_DN"))),
		nil,
	)
	changeRequest.Replace("userPassword", []string{hashPassword(newPassword)})

	err := ldapConn.Modify(changeRequest)
	if err != nil {
		return fmt.Errorf("password change failed: %v", err)
	}

	return nil
}

// SHA-1 Password
func hashPassword(password string) string {
	hash := sha1.New()
	hash.Write([]byte(password))
	return "{SHA}" + base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func CreateServiceAccount(serviceDN, servicePassword string) error {
	resetInit()

	dnParsed, err := ldap.ParseDN(serviceDN)
	if err != nil {
		return fmt.Errorf("invalid serviceDN: %v", err)
	}

	var cn, uid string
	for _, rdn := range dnParsed.RDNs {
		for _, attr := range rdn.Attributes {
			switch strings.ToLower(attr.Type) {
			case "cn":
				cn = attr.Value
			case "uid":
				uid = attr.Value
			}
		}
	}
	if cn == "" {
		return fmt.Errorf("cn not found in serviceDN")
	}

	addSvc := ldap.NewAddRequest(serviceDN, nil)
	addSvc.Attribute("objectClass", []string{
		"top",
		"organizationalRole",   // structural objectClass
		"simpleSecurityObject", // auxiliary objectClass for userPassword
	})
	addSvc.Attribute("cn", []string{cn})
	if uid != "" {
		addSvc.Attribute("uid", []string{uid})
	}
	addSvc.Attribute("userPassword", []string{servicePassword})

	if err := ldapConn.Add(addSvc); err != nil {
		return fmt.Errorf("create service account error: %v", err)
	}

	return nil
}
