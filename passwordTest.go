package owasp

type Owasp struct {
	PasswordConfig PasswordConfig
	TestConfig     TestConfig
	TestResult     TestResult
}

type PasswordConfig struct {
	allowPassPhrases       bool
	maxLength              int
	minLength              int
	minPhraseLength        int
	minOptionalTestsToPass int
}

type TestConfig struct {
	requiredTests []*requiredTest
	optionalTests []*optionalTest
}

// These are configuration settings that should
// be used when testing password strength
func DefaultPasswordConfig() *Owasp {
	return &Owasp{
		PasswordConfig: PasswordConfig{
			allowPassPhrases:       true,
			maxLength:              128,
			minLength:              10,
			minPhraseLength:        20,
			minOptionalTestsToPass: 4,
		},
		TestConfig: TestConfig{
			requiredTests: nil,
			optionalTests: defaultOptionalTests(),
		},
		TestResult: TestResult{
			errors:              []error{},
			failedTests:         []interface{}{},
			passedTests:         []interface{}{},
			requiredTestErrors:  []interface{}{},
			optionalTestErrors:  []interface{}{},
			isPassphrase:        false,
			strong:              true,
			optionalTestsPassed: 0,
		},
	}
}

type TestResult struct {
	errors              []error `json:"errors"`
	failedTests         []interface{}
	passedTests         []interface{}
	requiredTestErrors  []interface{}
	optionalTestErrors  []interface{}
	isPassphrase        bool
	strong              bool
	optionalTestsPassed int
}

type requiredTest struct {
	testMethod func(owasp *Owasp, password string, parameters []interface{}) (err error)
	params     []interface{}
}

// An array of required tests. A password *must* pass these test s in order
// to be considered strong.
func defaultRequiredTests() []*requiredTest {
	return []*requiredTest{
		{testMethod: minimumLength},
		{testMethod: maximumLength},
		{testMethod: preventRepeating},
	}
}

type optionalTest struct {
	testMethod func(owasp *Owasp, password string, parameters []interface{}) (err error)
	params     []interface{}
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
func defaultOptionalTests() []*optionalTest {
	return []*optionalTest{
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

func (owasp *Owasp) runTests(password string, requiredTests []*requiredTest,
	optionalTests []*optionalTest) {

	// Always submit the password/passphrase to the required tests
	for k, v := range requiredTests {
		err := v.testMethod(owasp, password, v.params)
		if err != nil {
			owasp.TestResult.strong = false
			owasp.TestResult.errors = append(owasp.TestResult.errors, err)
			owasp.TestResult.requiredTestErrors = append(owasp.TestResult.requiredTestErrors, err)
			owasp.TestResult.failedTests = append(owasp.TestResult.failedTests, k)
		} else {
			owasp.TestResult.passedTests = append(owasp.TestResult.passedTests, k)
		}
	}
	// OPTIONAL TESTS:
	for k, v := range optionalTests {
		err := v.testMethod(owasp, password, v.params)
		if err != nil {
			owasp.TestResult.errors = append(owasp.TestResult.errors, err)
			owasp.TestResult.optionalTestErrors = append(owasp.TestResult.optionalTestErrors, err)
			owasp.TestResult.failedTests = append(owasp.TestResult.failedTests, len(requiredTests)+k)
		} else {
			owasp.TestResult.optionalTestsPassed++
			owasp.TestResult.passedTests = append(owasp.TestResult.passedTests, len(requiredTests)+k)
		}
	}
}

// This method tests password strength
func (owasp *Owasp) TestPassword(password string) TestResult {
	requiredTests := defaultRequiredTests()
	optionalTests := defaultOptionalTests()

	owasp.runTests(password, requiredTests, optionalTests)

	// If configured to allow passphrases, and if the password is of a
	// sufficient length to consider it a passphrase, exempt it from the
	// optional tests.
	if owasp.PasswordConfig.allowPassPhrases == true &&
		len(password) >= owasp.PasswordConfig.minPhraseLength {
		owasp.TestResult.isPassphrase = true
	}

	// If the password is not a passphrase, assert that it has passed a
	// sufficient number of the optional tests, per the configuration
	if !owasp.TestResult.isPassphrase &&
		owasp.TestResult.optionalTestsPassed < owasp.PasswordConfig.minOptionalTestsToPass {
		owasp.TestResult.strong = false
	}

	return owasp.TestResult
}
