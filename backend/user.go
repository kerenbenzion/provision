package backend

import (
	"strings"
	"time"

	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
	sc "github.com/elithrar/simple-scrypt"
)

// User is an API user of DigitalRebar Provision
// swagger:model
type User struct {
	*models.User
	validate
	activeTenant string
}

func (obj *User) SetReadOnly(b bool) {
	obj.ReadOnly = b
}

func (u *User) Tenant() string {
	return u.activeTenant
}

func (obj *User) SaveClean() store.KeySaver {
	mod := *obj.User
	mod.ClearValidation()
	return toBackend(&mod, obj.rt)
}

func (p *User) Indexes() map[string]index.Maker {
	fix := AsUser
	res := index.MakeBaseIndexes(p)
	res["Name"] = index.Make(
		true,
		"string",
		func(i, j models.Model) bool { return fix(i).Name < fix(j).Name },
		func(ref models.Model) (gte, gt index.Test) {
			refName := fix(ref).Name
			return func(s models.Model) bool {
					return fix(s).Name >= refName
				},
				func(s models.Model) bool {
					return fix(s).Name > refName
				}
		},
		func(s string) (models.Model, error) {
			u := fix(p.New())
			u.Name = s
			return u, nil
		})
	return res
}

func (u *User) New() store.KeySaver {
	res := &User{User: &models.User{}}
	if u.User != nil && u.ChangeForced() {
		res.ForceChange()
	}
	res.rt = u.rt
	return res
}

func AsUser(o models.Model) *User {
	return o.(*User)
}

func AsUsers(o []models.Model) []*User {
	res := make([]*User, len(o))
	for i := range o {
		res[i] = AsUser(o[i])
	}
	return res
}

func (u *User) ChangePassword(rt *RequestTracker, newPass string) error {
	ph, err := sc.GenerateFromPassword([]byte(newPass), sc.DefaultParams)
	if err != nil {
		return err
	}
	u.PasswordHash = ph
	_, err = rt.Save(u)
	// When a user changes their password, invalidate any previous cached auth tokens.
	u.Secret = randString(16)
	return err
}

func (u *User) Validate() {
	u.User.Validate()
	u.AddError(index.CheckUnique(u, u.rt.stores("users").Items()))
	u.SetValid()
	for _, rName := range u.Roles {
		r := u.rt.find("roles", rName)
		if r == nil {
			u.Errorf("Role %s does not exist", rName)
		} else {
			role := AsRole(r)
			if !role.Available {
				u.Errorf("Role %s is not available", rName)
			}
		}
	}
	u.SetAvailable()
}

func (u *User) GenClaim(grantor string, ttl time.Duration, wantedRoles ...string) *DrpCustomClaims {
	claim := NewClaim(u.Name, grantor, ttl)
	// Users always have the right to get a token and change their password.
	claim.AddRawClaim("users", "token,password,get", u.Name)
	claim.AddRawClaim("info", "get", "")
	if len(wantedRoles) == 0 {
		claim.AddRoles(u.Roles...)
		return claim
	}
	haveRoles := []*Role{}
	for _, r := range u.Roles {
		if robj := u.rt.find("roles", r); robj != nil {
			haveRoles = append(haveRoles, robj.(*Role))
		} else {
			u.rt.Errorf("User %s has missing role %s", u.Name, r)
		}
	}
	for i := range wantedRoles {
		r := strings.TrimSpace(wantedRoles[i])
		if robj := u.rt.find("roles", r); robj != nil {
			for _, test := range haveRoles {
				role := AsRole(robj)
				if test.Role.Contains(role.Role) {
					claim.AddRoles(r)
					break
				}
			}
		}
	}
	return claim
}

func (u *User) BeforeSave() error {
	if u.Secret == "" {
		u.Secret = randString(16)
	}
	u.Validate()
	if !u.Useable() {
		return u.MakeError(422, ValidationError, u)
	}
	return nil
}

func (u *User) OnLoad() error {
	defer func() { u.rt = nil }()
	u.Fill()

	// This mustSave part is just to keep us from resaving all the users on startup.
	mustSave := false
	if u.Secret == "" {
		mustSave = true
	}
	err := u.BeforeSave()
	if err == nil && mustSave {
		v := u.SaveValidation()
		u.ClearValidation()
		err = u.rt.stores("users").backingStore.Save(u.Key(), u)
		u.RestoreValidation(v)
	}
	return err
}

func (u *User) AfterDelete() {
	if u.activeTenant == "" {
		return
	}
	if obj := u.rt.find("tenants", u.activeTenant); obj != nil {
		t := AsTenant(obj)
		newUserList := []string{}
		for _, name := range t.Users {
			if name == u.Name {
				continue
			}
			newUserList = append(newUserList, name)
		}
		t.Users = newUserList
		u.rt.Save(t)
	}
}

var userLockMap = map[string][]string{
	"get":     []string{"users", "roles"},
	"create":  []string{"users", "roles"},
	"update":  []string{"users", "roles"},
	"patch":   []string{"users", "roles"},
	"delete":  []string{"users", "tenants"},
	"actions": []string{"users", "roles", "profiles", "params"},
}

func (u *User) Locks(action string) []string {
	return userLockMap[action]
}
