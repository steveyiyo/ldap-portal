package auth

import (
	"fmt"
	"os"

	"github.com/go-ldap/ldap"
)

func LdapListUsers() ([]string, error) {
	resetInit()
	baseDN := fmt.Sprintf("ou=users,%s", os.Getenv("LDAP_SEARCH_BASE_DN"))
	sr, err := ldapConn.Search(ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=inetOrgPerson)",
		[]string{"uid"},
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("search users failed: %v", err)
	}
	var uids []string
	for _, entry := range sr.Entries {
		if uid := entry.GetAttributeValue("uid"); uid != "" {
			uids = append(uids, uid)
		}
	}
	return uids, nil
}

func LdapGetUserDetails(username string) (map[string]string, error) {
	resetInit()
	baseDN := fmt.Sprintf("ou=users,%s", os.Getenv("LDAP_SEARCH_BASE_DN"))
	filter := fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(username))
	sr, err := ldapConn.Search(ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"dn", "uid", "cn", "sn", "givenName", "mail", "memberOf"},
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("search user %s failed: %v", username, err)
	}
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user %s not found", username)
	}
	e := sr.Entries[0]
	info := map[string]string{
		"dn":        e.DN,
		"uid":       e.GetAttributeValue("uid"),
		"cn":        e.GetAttributeValue("cn"),
		"sn":        e.GetAttributeValue("sn"),
		"givenName": e.GetAttributeValue("givenName"),
		"mail":      e.GetAttributeValue("mail"),
		"memberOf":  e.GetAttributeValue("memberOf"),
	}
	return info, nil
}
