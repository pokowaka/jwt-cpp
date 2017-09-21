// This is a wee bit of a hack..
// We combine all the individual test cpp's
// mainly so we can execute the code coverage target with
// some meaningful numbers
#include "base64/base64_test.cpp"
#include "token/token_test.cpp"
#include "validators/claim_validators_factory_test.cpp"
#include "validators/claim_validators_test.cpp"
#include "validators/validators_factory_test.cpp"
#include "validators/validators_test.cpp"
