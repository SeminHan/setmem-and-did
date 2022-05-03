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

#include "membership_did.hpp"

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libff/algebra/fields/field_utils.hpp>
#include "poseidon.hpp"

#include <complex>
#include <stdexcept>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/public_params.hpp>


using namespace std;
using namespace membership;
using namespace libsnark;
using namespace memDID;
using namespace Hashes;

const string USAGE = 
    "Set membership for DID computing car insurance premiums\n\n\tUSAGE:\n\t\t./MembershipDID [Version] <batching_size> <set_size> <hash:poseidon/sha>\n\n\tVersion:\n\t\tnonopt: Non-optimized version; Membership proof: (W, C, k, h)\n\n\t\topt: Optimized version(with using PoKE); Membership proof: (W, C, k', h, Q, l)\n";

typedef libff::Fr<libff::default_ec_pp> FieldT;

typedef struct {
    string version;
    int batching_size;
    int set_size;
    string hash;
}input_args;


// Example attribute generation function for holder those who wants to buy a car insurance
// In the current state, attributes are fixed. To be modified these can be from user input. 
void attrGen(holders* holder) {
    holder->id = BN_new();

    srand((unsigned int)time(NULL));
    int rand_num = rand();
    int rand_range = rand();
    
    // map<string, int> tmp_info = {{"driving history", 20}, {"marriage", 1}, {"child", 1}, 
    //     {"safety training", 1}, {"age", 49}, {"engineer diploma", 1}, 
    //     {"residence", 0}, {"income", 70000}, {"credit score", 0}, {"driving habit", 3},
    //     {"1 year accident record", 1}, {"1~5 year accident record", 1}, {"penalty record", 0}, {"job", 0}, 
    //     {"property", 300000}, {"health record", 0}};

    map<string, int> tmp_info = {{"driving history", rand_num % 40}, {"marriage", rand() % 2}, {"child", rand() % 2}, 
        {"safety training", rand() % 2}, {"age", (rand_num % 40) + (rand_range % 10 + 20)}, {"engineer diploma", rand() % 2}, 
        {"residence", rand() % 3}, {"income", 10000 + (rand() % 190001)}, {"credit score", rand() % 3}, {"driving habit", rand() % 7},
        {"1 year accident record", rand() % 4}, {"1~5 year accident record", rand() % 6}, {"penalty record", rand() % 41}, {"job", rand() % 2}, 
        {"property", 30000 + (rand() % 570001)}, {"health record", rand() % 2}};
        

    holder->info = tmp_info;
}




int main(int argc, char* argv[]) {
    input_args* args = new input_args;

    membership::public_param* pp = new membership::public_param();
    membership::mem_proof* memProof = new membership::mem_proof();
    
    // vector<attr_info*> tmp_info;
    map<string, int> tmp_info; 
    vector<credentials*> tmp_credential;
    holders* test_holder = new holders;
    test_holder->info = tmp_info;
    test_holder->holderCred = tmp_credential;

    bool is_opt, pass_vfy;
    int hash_type = 0;

    if(argc != 4 && argc != 5) {
        cout << "Invalid argument error!" << endl << endl;
        cout << USAGE << endl;
        return 0;
    }

    args->version = argv[1];
    args->batching_size = atoi(argv[2]);
    args->set_size = atoi(argv[3]);
    args->hash = argv[4];

    if(argc == 4) {
        args->hash = "sha";
    }

    if(args->version == "nonopt") {
        is_opt = false;
    }
    else if(args->version == "opt") {
        is_opt = true;
    }

    if(args->hash == "sha") {
        hash_type = 0;
    }
    else if(args->hash == "poseidon" || args->hash == "pos") {
        cout << "POSEIDON HASH" << endl;
        hash_type = 1;
    } 
    else {
        cout << "Invalid argument error! Hash = [sha/poseidon]" << endl << endl;
        cout << USAGE << endl;
        return 0;
    }

    
    vector<BIGNUM*> S; //element set S
    vector<holders*> holder_set;
    BIGNUM* ACC = BN_new(); // Accumulator initialization with value "1"
    BN_copy(ACC, BN_value_one());
    
     // Assume that there have been some existing elements 
    for(int i = 0; i < args->set_size; i++) {
        BN_CTX* bn_ctx = BN_CTX_new();
        memDID::holders* old_holder = new holders;
        old_holder->id = BN_new();
        memDID::credentials* tmp_cred = new credentials;
        tmp_cred->addrIssuer = BN_new();
        tmp_cred->c = BN_new();

        BIGNUM* bn_ik = BN_new();
        BN_rand(bn_ik, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        
        BN_rand(old_holder->id, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        
       if(hash_type == 0) {
           memDID::addrGen(tmp_cred->addrIssuer, bn_ik);
       }
       else if(hash_type == 1) {
           vector<BIGNUM*> bn_ik_vec;
           bn_ik_vec.push_back(bn_ik);
           BIGNUM* bn_prime = BN_new();
           BN_hex2bn(&bn_prime, membership::FIELD_PRIME.c_str());
           tmp_cred->addrIssuer = Poseidon::hash(bn_ik_vec, bn_prime);
       }

        
        

        // Existing holder generation
        memDID::userGen(old_holder);

        for(auto x: old_holder->info) {
            int rand = 0;
            BIGNUM* bn_h = BN_new();

            if(hash_type == 0) {
                do{
                    memDID::attrHash(bn_h, old_holder->id, x.first, x.second, rand);
                    memDID::credGen(tmp_cred->c, tmp_cred->addrIssuer, bn_h);
                    rand += 1;
                }while(!BN_is_prime(tmp_cred->c, 5, NULL, bn_ctx, NULL));
            }
            else if(hash_type == 1) {
                string str_key = string_to_hex(x.first);
                string str_val = to_string(x.second);
                string _mid = BN_bn2hex(old_holder->id) + str_key + str_val;

                do{
                    string _input = _mid + to_string(rand);
                    memDID::attrHashPos(bn_h, _input);
                    memDID::credGenPos(tmp_cred->c, tmp_cred->addrIssuer, bn_h);
                    rand += 1;
                }while(!BN_is_prime(tmp_cred->c, 5, NULL, bn_ctx, NULL));
            }

            
            tmp_cred->attrCred_key = x.first;
            tmp_cred->attrCred_val = x.second;
            tmp_cred->rand = rand;

            old_holder->holderCred.push_back(tmp_cred);
            S.push_back(tmp_cred->c);

            BN_free(bn_h);
        }
        holder_set.push_back(old_holder);
        BN_CTX_free(bn_ctx);
    }

    libsnark::default_r1cs_gg_ppzksnark_pp::init_public_params();
    libff::start_profiling();

    libff::G1_vector<libsnark::default_r1cs_gg_ppzksnark_pp> commit_base; 
    libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark;

    r1cs_gg_ppzksnark_keygen(snark, 13100, (args->batching_size)*16);

    r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> snark_key = r1cs_gg_ppzksnark_generator<libsnark::default_r1cs_gg_ppzksnark_pp>(snark.constraint_system);
    snark_key.pk = libff::reserialize<r1cs_gg_ppzksnark_proving_key<default_r1cs_gg_ppzksnark_pp>>(snark_key.pk);
    snark_key.vk = libff::reserialize<r1cs_gg_ppzksnark_verification_key<default_r1cs_gg_ppzksnark_pp>>(snark_key.vk);

    r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> snark_proof; 

    for(int i = 0; i < (args->batching_size)*16; i++) {
        commit_base.push_back(snark_key.pk.A_query[i+1]);
    }

    vector<holders*> test_holder_set; 

    for(int i = 0; i < args->batching_size; i++) {
        holders* tmp_holder = new holders;
        attrGen(tmp_holder);
        test_holder_set.push_back(tmp_holder);
    }

    cout << "===============WELL DONE!=============" << endl << endl;

    vector<BIGNUM*> _credentials;

    membership::setup(pp);
    membership::accumulate(pp, S, ACC);
    for(auto x: test_holder_set) {
        issue(pp, x, S, ACC, hash_type);
        for(auto y: x->holderCred) {
            _credentials.push_back(y->c);
        }
    }

    for(auto x: test_holder_set) {
        x->premiums = computePremiums(x);
    }

    proof(snark, snark_key, snark_proof, pp, commit_base, S, _credentials, memProof, is_opt, hash_type);
    pass_vfy = verify(snark, snark_key.vk, snark_proof, pp, ACC, S, memProof, is_opt, hash_type);

    if(pass_vfy) {
        membership::print_debug("Verification Pass");
    }
    else {
        membership::print_debug("Verification Failed");
    }

    cout << "========== Holder ==========" << endl;
    for(auto x: test_holder_set) {
        for(auto y: x->info) {
            cout << y.first << " : " << y.second << endl;
        }
        
    }

    return 0;
}