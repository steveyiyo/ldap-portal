package auth

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"

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

func LdapAuthUser(username, password string) (bool, error) {
	// Filter
	searchRequest := ldap.NewSearchRequest(
		os.Getenv("LDAP_SEARCH_BASE_DN"),
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
		os.Getenv("LDAP_SEARCH_BASE_DN"),
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
		fmt.Sprintf("uid=%s,%s", username, os.Getenv("LDAP_SEARCH_BASE_DN")),
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
