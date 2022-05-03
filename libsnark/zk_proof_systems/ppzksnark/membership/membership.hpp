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


#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>   
#include <libsnark/zk_proof_systems/ppzksnark/membership/membership_snark.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>



using namespace std;

namespace membership {
    using def_pp = libsnark::default_r1cs_gg_ppzksnark_pp;

    typedef struct {
        fmpz_t N;
        fmpz_t V;
        vector<BIGNUM*> vec_prime;
    }public_param;

    typedef struct {
        BIGNUM* W;
        BIGNUM* C_x;
        BIGNUM* C_y;
        BIGNUM* k;
        BIGNUM* opt_k;
        BIGNUM* h;
        BIGNUM* Q;
        BIGNUM* l;
    }mem_proof;

    const string FIELD_PRIME = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";  

    int pp_init(public_param* pp);
    
    int pp_clear(public_param* pp);

    int groupGen(public_param* pp);
    
    void print_debug(const char* msg);

    void print_BN(BIGNUM* p, string s);

    void proof_size(mem_proof* proof, bool is_opt);

    void Hash1(BIGNUM* res, BIGNUM* sk);

    void Hash2(BIGNUM* ret, BIGNUM* W, BIGNUM* C_x, BIGNUM* C_y, BIGNUM* R);

    void Hash3(BIGNUM* ret, BIGNUM* h);

    void hashPos1(BIGNUM* ret, BIGNUM* sk);

    void hashPos2(BIGNUM* ret, BIGNUM* W, BIGNUM* C_x, BIGNUM* C_y, BIGNUM* R);

    void hashToPrimePos(BIGNUM* ret, BIGNUM* h);

    void setup(public_param* pp);

    void add(vector<BIGNUM*> &S, vector<BIGNUM*> u);

    void accumulate(public_param* pp, vector<BIGNUM*> S, BIGNUM* &ACC);

    void compute(libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark_ex, 
    const libsnark::r1cs_gg_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> snark_key,
    libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> &snark_proof,
    public_param* pp, libff::G1_vector<def_pp> &commit_base, vector<BIGNUM*> S, vector<BIGNUM*> u, mem_proof* proof, int hash_type);

    void optCompute(libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark_ex,
    const libsnark::r1cs_gg_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> snark_key,
    libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> &snark_proof,
    public_param* pp, libff::G1_vector<def_pp> &commit_base, vector<BIGNUM*> S, vector<BIGNUM*> u, mem_proof* proof, int hash_type);

    bool verify(libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark_ex, 
    libsnark::r1cs_gg_ppzksnark_verification_key<libsnark::default_r1cs_gg_ppzksnark_pp> snark_vk,
    libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> snark_proof,
    public_param* pp, BIGNUM* &ACC, vector<BIGNUM*> S, mem_proof* proof, int hash_type);

    bool optVerify(libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark_ex, 
    libsnark::r1cs_gg_ppzksnark_verification_key<libsnark::default_r1cs_gg_ppzksnark_pp> snark_vk, 
    libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> snark_proof,
    public_param* pp, BIGNUM* &ACC, vector<BIGNUM*> S, mem_proof* proof, int hash_type);
}