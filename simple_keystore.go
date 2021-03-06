package jwtauth

import "fmt"
import "reflect"

type (
	// SimpleKeystore is a Keystore that trusts exactly one key regardless of
	// the token's issuer.
	//
	// Trust() and RevokeTrust() have no effect, although Trust() returns an
	// error if called with a key other than the one-and-only trusted key.
	SimpleKeystore struct {
		Key interface{}
	}
)

func (sk *SimpleKeystore) Trust(issuer string, key interface{}) error {
	if !reflect.DeepEqual(key, sk.Key) {
		return fmt.Errorf("cannot trust additional keys; call RevokeTrust first")
	}
	return nil
}

func (sk *SimpleKeystore) RevokeTrust(issuer string) {
}

func (sk *SimpleKeystore) Get(issuer string) interface{} {
	return sk.Key
}
