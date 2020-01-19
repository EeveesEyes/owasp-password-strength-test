package owasp

import "encoding/json"

type Owasp struct {
	PasswordConfig PasswordConfig
	TestConfig     TestConfig
	TestResult     TestResult
}

type PasswordConfig struct {
	AllowPassPhrases       bool
	MaxLength              int
	MinLength              int
	MinPhraseLength        int
	MinOptionalTestsToPass int
}

type TestConfig struct {
	RequiredTests []*PasswordTest
	OptionalTests []*PasswordTest
}

// These are configuration settings that should
// be used when testing password strength
func DefaultPasswordConfig() *Owasp {
	return &Owasp{
		PasswordConfig: PasswordConfig{
			AllowPassPhrases:       true,
			MaxLength:              128,
			MinLength:              10,
			MinPhraseLength:        20,
			MinOptionalTestsToPass: 4,
		},
		TestConfig: TestConfig{
			RequiredTests: defaultRequiredTests(),
			OptionalTests: defaultOptionalTests(),
		},
		TestResult: TestResult{
			Errors:              []string{},
			FailedTests:         []interface{}{},
			PassedTests:         []interface{}{},
			RequiredTestErrors:  []interface{}{},
			OptionalTestErrors:  []interface{}{},
			IsPassphrase:        false,
			Strong:              true,
			OptionalTestsPassed: 0,
		},
	}
}

type TestResult struct {
	Errors              []string      `json:"errors"`
	FailedTests         []interface{} `json:"failedTests"`
	PassedTests         []interface{} `json:"passedTests"`
	RequiredTestErrors  []interface{} `json:"requiredTestErrors"`
	OptionalTestErrors  []interface{} `json:"optionalTestErrors"`
	IsPassphrase        bool          `json:"isPassphrase"`
	Strong              bool          `json:"strong"`
	OptionalTestsPassed int           `json:"optionalTestsPassed"`
}

type PasswordTest struct {
	testMethod func(owasp *Owasp, password string, parameters []interface{}) (err error)
	params     []interface{}
}

// An array of required tests. A password *must* pass these test s in order
// to be considered strong.
func defaultRequiredTests() []*PasswordTest {
	return []*PasswordTest{
		{testMethod: minimumLength},
		{testMethod: maximumLength},
		{testMethod: preventRepeating},
	}
}

// An array of optional tests. These tests are "optional" in two senses:
//
// 1. Passphrases (passwords whose length exceeds
//    this.configs.minPhraseLength) are not obligated to pass these tests
//    provided that this.configs.allowPassphrases is set to Boolean true
//    (which it is by default).
//
// 2. A password need only to pass this.configs.minOptionalTestsToPass
//    number of these optional tests in order to be considered strong.
func defaultOptionalTests() []*PasswordTest {
	return []*PasswordTest{
		// require at least one lowercase letter
		{
			testMethod: atLeastOneOf,
			params:     []interface{}{"[a-z]", "lowercase letter"},
		},
		// require at least one uppercase letter
		{
			testMethod: atLeastOneOf,
			params:     []interface{}{"[A-Z]", "uppercase letter"},
		},
		// require at least one number
		{
			testMethod: atLeastOneOf,
			params:     []interface{}{"[0-9]", "number"},
		},
		// require at least one special character
		{
			testMethod: atLeastOneOf,
			params:     []interface{}{"[^A-Za-z0-9]", "special character"},
		},
	}
}

func (owasp *Owasp) runTests(password string, requiredTests []*PasswordTest,
	optionalTests []*PasswordTest) {

	// Always submit the password/passphrase to the required tests
	for k, v := range requiredTests {
		err := v.testMethod(owasp, password, v.params)
		if err != nil {
			owasp.TestResult.Strong = false
			owasp.TestResult.Errors = append(owasp.TestResult.Errors, err.Error())
			owasp.TestResult.RequiredTestErrors = append(owasp.TestResult.RequiredTestErrors, err.Error())
			owasp.TestResult.FailedTests = append(owasp.TestResult.FailedTests, k)
		} else {
			owasp.TestResult.PassedTests = append(owasp.TestResult.PassedTests, k)
		}
	}
	// OPTIONAL TESTS:
	for k, v := range optionalTests {
		err := v.testMethod(owasp, password, v.params)
		if err != nil {
			owasp.TestResult.Errors = append(owasp.TestResult.Errors, err.Error())
			owasp.TestResult.OptionalTestErrors = append(owasp.TestResult.OptionalTestErrors, err.Error())
			owasp.TestResult.FailedTests = append(owasp.TestResult.FailedTests, len(requiredTests)+k)
		} else {
			owasp.TestResult.OptionalTestsPassed++
			owasp.TestResult.PassedTests = append(owasp.TestResult.PassedTests, len(requiredTests)+k)
		}
	}
}

// This method tests password strength
func (owasp *Owasp) TestPassword(password string) ([]byte, error) {
	owasp.runTests(password, owasp.TestConfig.RequiredTests, owasp.TestConfig.OptionalTests)

	// If configured to allow passphrases, and if the password is of a
	// sufficient length to consider it a passphrase, exempt it from the
	// optional tests.
	if owasp.PasswordConfig.AllowPassPhrases == true &&
		len(password) >= owasp.PasswordConfig.MinPhraseLength {
		owasp.TestResult.IsPassphrase = true
	}

	// If the password is not a passphrase, assert that it has passed a
	// sufficient number of the optional tests, per the configuration
	if !owasp.TestResult.IsPassphrase &&
		owasp.TestResult.OptionalTestsPassed < owasp.PasswordConfig.MinOptionalTestsToPass {
		owasp.TestResult.Strong = false
	}

	return json.Marshal(owasp.TestResult)
}
