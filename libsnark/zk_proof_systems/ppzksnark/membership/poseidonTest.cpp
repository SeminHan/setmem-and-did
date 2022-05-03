#include <iostream>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <flint/fmpz.h>
#include <vector> 
#include <map>
#include <math.h>
#include <time.h>
#include <string.h>
#include <string>
#include <cstdlib>
#include <ctime>
#include <cassert>
#include <cstdio>
#include <complex>
#include <stdexcept>
#include <cstddef>

#include "poseidon.hpp"

using namespace Hashes;

const string _FIELD_PRIME = "21888242871839275222246405745257275088548364400416034343698204186575808495617";

int main(int argc, char* argv[]) {
    
    BIGNUM* bn_rnd = BN_new();
    BIGNUM* bn_prime = BN_new();
    
    BN_rand(bn_rnd, 256, 1, 0);
    BN_hex2bn(&bn_prime, _FIELD_PRIME.c_str());

    cout << BN_bn2hex(bn_prime) << endl << endl;

    vector<BIGNUM*> bn_rnd_vec;
    bn_rnd_vec.push_back(bn_rnd);

    BIGNUM* pos_output = Poseidon::hash(bn_rnd_vec, bn_prime);

    cout << "The result of rnd pos is : " << BN_bn2hex(pos_output) << endl;

    return 0;
}