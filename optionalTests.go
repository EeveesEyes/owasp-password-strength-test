package owasp

import (
	"fmt"
	"log"
	"regexp"
)

func atLeastOneOf(owasp *Owasp, password string, params []interface{}) (err error) {
	regex, errorDescription := fmt.Sprintf("%v", params[0]), fmt.Sprintf("%v", params[1])
	match, err := regexp.Match(regex, []byte(password))
	if !match {
		return fmt.Errorf("the password must contain at least one %s", errorDescription)
	} else if err != nil {
		log.Println("LowercaseLetter", err)
		return err
	}
	return nil
}
