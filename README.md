# OWASP Password Strength Test

This is a go port of the unofficial [node.js OWASP strength test](https://github.com/nowsecure/owasp-password-strength-test)

### Usage:
-

    import (
    	"github.com/EeveesEyes/owasp" 
    )
    func main() {
        password := "weakpassword"
        passwordConfig := owasp.DefaultPasswordConfig()
        passwordConfig.TestPassword(password)
    }

### Password Config:
You can either modify the existing `Owasp.PasswordConfig` attribute or add your own password config by assigning a new instance of `owasp.PasswordConfig{}` to the `Owasp.PasswordConfig` attribute.
This way you can adjust i.e. the required password length and other settings. Default settings are:

   - AllowPassPhrases          (true)       
   - MaxLength                 (128)        
   - MinLength                 (10)         
   - MinPhraseLength           (20)         
   - MinOptionalTestsToPass    (4)          

### TestConfig
You can add your own password tests functions of the signature 
`testMethod(owasp *Owasp, password string, parameters []interface{}) (err error)`
by appending instances of `Owasp.PasswordTest{}` to either `Owasp.TestConfig.requiredTests` or `Owasp.TestConfig.optionalTests`. 

The slice `parameters` can be set by setting `Owasp.PasswordTest{}.parameters` which is of type `[]interface{}`  

### Result
Like the node.js implementation `Owasp.TestPassword()` returns a json object of the form:

    {
      errors              : [],
      failedTests         : [],
      requiredTestErrors  : [],
      optionalTestErrors  : [],
      passedTests         : [ 0, 1, 2, 3, 4, 5, 6 ],
      isPassphrase        : false,
      strong              : true,
      optionalTestsPassed : 4
    } 

which is valid or:

    {
      "errors": [
        "the password must be at least 10 characters long",
        "the password may not contain sequences of three or more repeated characters",
        "the password must contain at least one lowercase letter",
        "the password must contain at least one uppercase letter",
        "the password must contain at least one special character"
      ],
      "failedTests": [
        0,
        2,
        3,
        4,
        6
      ],
      "passedTests": [
        1,
        5
      ],
      "requiredTestErrors": [
        "the password must be at least 10 characters long",
        "the password may not contain sequences of three or more repeated characters"
      ],
      "optionalTestErrors": [
        "the password must contain at least one lowercase letter",
        "the password must contain at least one uppercase letter",
        "the password must contain at least one special character"
      ],
      "isPassphrase": false,
      "strong": false,
      "optionalTestsPassed": 1
    }
    
which contains errors of an invalid password ("111"). 