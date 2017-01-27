package jwt

import "fmt"
import "reflect"

type (
	// SingleKeystore is a Keystore that trusts exactly one key regardless of
	// the token's issuer.
	//
	// Trust() and RevokeTrust() have no effect, although Trust() returns an
	// error if called with a key other than the one-and-only trusted key.
	SingleKeystore struct {
		Key
	}
)

func (sk *SingleKeystore) Trust(issuer string, key Key) error {
	if !reflect.DeepEqual(key, sk.Key) {
		return fmt.Errorf("SingleKeystore cannot trust additional keys")
	}
	return nil
}

func (sk *SingleKeystore) RevokeTrust(issuer string) {
}

func (sk *SingleKeystore) Get(issuer string) Key {
	return sk.Key
}
