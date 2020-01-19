package owasp

import (
	"fmt"
	"math"
)

// enforce a minimum length
func minimumLength(owasp *Owasp, password string, params []interface{}) (err error) {
	if len(password) < owasp.PasswordConfig.MinLength {
		return fmt.Errorf("the password must be at least %d characters long", owasp.PasswordConfig.MinLength)
	}
	return nil
}

// enforce a maximum length
func maximumLength(owasp *Owasp, password string, params []interface{}) (err error) {
	if len(password) > owasp.PasswordConfig.MaxLength {
		return fmt.Errorf("the password must be fewer than %d characters", owasp.PasswordConfig.MaxLength)
	}
	return nil
}

// forbid repeating characters
func preventRepeating(owasp *Owasp, password string, params []interface{}) (err error) {
	ans, temp := 1, 1
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			temp++
			if temp > 2 {
				return fmt.Errorf("the password may not contain sequences of three or more repeated characters")
			}
		} else {
			ans = int(math.Max(float64(ans), float64(temp)))
			temp = 1
		}
	}
	ans = int(math.Max(float64(ans), float64(temp)))
	if ans > 2 {
		return fmt.Errorf("the password may not contain sequences of three or more repeated characters")
	}
	return nil
}
