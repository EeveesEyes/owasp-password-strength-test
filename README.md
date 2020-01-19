# OWASP Password Strength Test

This is a go port of the unofficial [node.js OWASP strength test](https://github.com/nowsecure/owasp-password-strength-test)

### Usage:
-
    import (
    	"github.com/EeveesEyes/owasp" 
    )
    func main() {
        password := "weakpassword"
        owasp.DefaultPasswordConfig()
        owasp.TestPassword(password)
    }
