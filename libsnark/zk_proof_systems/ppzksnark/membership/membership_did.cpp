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
#include <iomanip>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libff/algebra/fields/field_utils.hpp>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/public_params.hpp>

#include <complex>
#include <stdexcept>

#include "membership.hpp"
#include "poseidon.hpp"


#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/examples/run_r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>


using namespace std;
using namespace Hashes;
using def_pp = libsnark::default_r1cs_gg_ppzksnark_pp;

namespace memDID {
    const int userID_len = 256;
    const string FACTORS[] = {"driving history", "marriage", "child", "safety training", "age", "engineer diploma", "residence", "income", 
        "credit score", "driving habit", "1 year accident record", "1~5 year accident record", "penalty record", "job", "property", "health record"};
    const int BASIC_FEE = 1800;
    

// Actually, this struct include key, value, type. 
// However, we just fix the attribute type to be integer since this is very simple example.
// This will be modified in near future. 
    typedef struct {
        string attr_key;
        int attr_val;
    }attr_info;

    typedef struct {
        BIGNUM* addrIssuer;
        int* rand;
        string attrCred_key;
        int attrCred_val;
        BIGNUM* c;    
    }credentials;

    typedef struct {
        vector<credentials*> holderCred;
        // vector<attr_info*> info;
        map<string, int> info;
        BIGNUM* id;
        double premiums;
    }holders;

// The signature is omitted for now. Since we just show the flow of credential with membership. 
    typedef struct {
        BIGNUM* addr_issuer;
        BIGNUM* h;
        BIGNUM* c;
    }transactions;


    
    void r1cs_gg_ppzksnark_keygen(libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> &snark_ex, int num_constraints, int input_size) {
        const bool test_serialization = true;
        snark_ex = libsnark::generate_r1cs_example_with_binary_input<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>>(num_constraints, input_size);

        assert(bit);    
    }

    string string_to_hex(string s) {
        ostringstream ret;
        
        for(string::size_type i = 0; i < s.length(); ++i) {
            ret << std::hex << std::setfill('0') << std::setw(2) << (int)s[i];
        }

        return ret.str();
    }
    
    // Is randomness is essential in this function?
    void attrHash(BIGNUM* ret, BIGNUM* userID, string attrKey, int attrVal, int rand_num) {
        unsigned char hash_digest[SHA256_DIGEST_LENGTH];
        unsigned char temp[2048];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);

        BN_bn2bin(userID, temp);
        SHA256_Update(&sha256, temp, BN_num_bytes(userID));
        memcpy(temp, &attrKey, sizeof(string));
        SHA256_Update(&sha256, temp, sizeof(string));
        memcpy(temp, &attrVal, sizeof(int));
        SHA256_Update(&sha256, temp, sizeof(int));
        memcpy(temp, &rand_num, sizeof(int));
        SHA256_Update(&sha256, temp, sizeof(int));

        SHA256_Final(hash_digest, &sha256);   

        BN_bin2bn(hash_digest, 32, ret);
    }

    void attrHashPos(BIGNUM* &ret, string _attr) {
        BIGNUM* bn_attr = BN_new();
        BN_hex2bn(&bn_attr, _attr.c_str());

        vector<BIGNUM*> pos_inp_vec = {bn_attr};

        BIGNUM* bn_prime = BN_new();
        BN_hex2bn(&bn_prime, membership::FIELD_PRIME.c_str());
        
        // cout << BN_bn2hex(bn_prime) << endl << endl;
        ret = Poseidon::hash(pos_inp_vec, bn_prime);
        // cout << BN_bn2hex(ret) << endl << endl;
    }

    // Isn't randomness needed in this function? randomness "r"
    void credGen(BIGNUM* ret, BIGNUM* addrIssuer, BIGNUM* h) {
        unsigned char hash_digest[SHA256_DIGEST_LENGTH];
        unsigned char temp[2048];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);

        BN_bn2bin(addrIssuer, temp);
        SHA256_Update(&sha256, temp, BN_num_bytes(addrIssuer));
        BN_bn2bin(h, temp);
        SHA256_Update(&sha256, temp, BN_num_bytes(h));

        SHA256_Final(hash_digest, &sha256);   

        BN_bin2bn(hash_digest, 32, ret);
    }

    void credGenPos(BIGNUM* &ret, BIGNUM* addrIssuer, BIGNUM* h) {
        BIGNUM* bn_input = BN_new();
        BN_add(bn_input, addrIssuer, h);
        vector<BIGNUM*> pos_inp_vec = {bn_input};
        // vector<BIGNUM*> pos_inp_vec = {addrIssuer, h};
        BIGNUM* bn_prime = BN_new();
        BN_hex2bn(&bn_prime, membership::FIELD_PRIME.c_str());
        ret = Poseidon::hash(pos_inp_vec, bn_prime);
    }

    // Arbitrary holder generation
    // holder has some ID, which is generated randomly in bignum form. 
    // This ID can be replaced as it needs. 
    void userGen(holders* holder) {
        // holder ID generation
        holder->id = BN_new();
        BN_rand(holder->id, userID_len, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);

        // Attribution information sample for one person. 
        
        
        srand((unsigned int)time(NULL));
        int rand_num = rand(); 
        int rand_range = rand();
        
        holder->info = {{"driving history", rand_num % 40}, {"marriage", rand() % 2}, {"child", rand() % 2}, 
        {"safety training", rand() % 2}, {"age", (rand_num % 40) + (rand_range % 10 + 20)}, {"engineer diploma", rand() % 2}, 
        {"residence", rand() % 3}, {"income", 10000 + (rand() % 190001)}, {"credit score", rand() % 3}, {"driving habit", rand() % 7},
        {"1 year accident record", rand() % 4}, {"1~5 year accident record", rand() % 6}, {"penalty record", rand() % 41}, {"job", rand() % 2}, 
        {"property", 30000 + (rand() % 570001)}, {"health record", rand() % 2}};
    }

    void addrGen(BIGNUM* ret, BIGNUM* issuer_key) {
        unsigned char hash_digest[SHA256_DIGEST_LENGTH];
        unsigned char temp[2048];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);

        BN_bn2bin(issuer_key, temp);
        SHA256_Update(&sha256, temp, BN_num_bytes(issuer_key));

        SHA256_Final(hash_digest, &sha256);   

        BN_bin2bn(hash_digest, 32, ret);
    }

    // User generation + Membership Setup
    // void setup(membership::public_param*) {
    //     libff::start_profiling();
    //     libff::enter_block("Call to setup membership");

    //     membership::setup(pp);
    //     // userGen(holder);

    //     libff::leave_block("Call to setup for membership");
    // }

    void addCred(vector<BIGNUM*> &S, BIGNUM* elem) {
        S.push_back(elem);
    }

    // Issuer checks that holder satisfies some requirements for approval.
    // In current state, we only deal with about age requirement.
    bool is_satisfied(holders* holder) {
        bool pass = false;
        for(auto x: holder->info) {
            if(x.first == "age") {
                if(x.second > 19) {
                    pass = true; 
                }
            }
        }
        return pass;
    }    

    void computeFactors(holders* holder, map<string, float> &factors_set, map<string, int> indexed_factors, map<int, int> indexed_attr) {
        for(auto x: indexed_attr) {
            string _key = "";
            float _val = 0;

            for(auto y: indexed_factors) {
                if(y.second == x.first) {
                    _key = y.first;
                }
            }

            if(x.second < 0) {
                cout << "Invalid values! Attributes value cannot be negative." << endl;
                exit(-1);
            }

            switch (x.first)
            {
                case 0:
                    if(x.second == 0) {
                        _val = -150;
                    }
                    else {
                        _val = (1 + (x.second * 0.01));
                    }
                    break;
                
                case 1:
                    _val = x.second * 100;
                    break;
                
                case 2:
                    if((x.second >= 20 && x.second < 30) || (x.second >= 50 && x.second < 60)) {
                        _val = 1.02;
                    }
                    else if(x.second >=30 && x.second < 50) {
                        _val = 1;
                    }
                    else {
                        _val = 1.05;
                    }
                    break;
                
                case 3:
                    if(x.second == 1) {
                        _val = -120;
                    }
                    break;
                
                case 4:
                    if(x.second == 0) {
                        _val = 150;
                    }
                    else if(x.second == 1) {
                        _val = 100;
                    }
                    break;
                
                case 5:
                    if(x.second < 2) {
                        _val = -200;
                    }
                    else if(x.second >= 4) {
                        _val = 150;
                    }
                    break;
                
                case 6:
                    if(x.second < 3) {
                        _val = 600;
                    }
                    else if(x.second >= 3 && x.second < 10) {
                        _val = 300;
                    }
                    else {
                        _val = -200;
                    }
                    break;

                case 7:
                    if(x.second == 1) {
                        _val = -150;
                    }
                    break;
                
                case 8:
                    _val = x.second * 500;
                    break;
                
                case 9:
                    if(x.second < 35000) {
                        _val = 350;
                    }
                    else if(x.second >= 35000 && x.second < 65000) {
                        _val = 200;
                    }
                    else if(x.second >= 65000 && x.second < 100000) {
                        _val = 100;
                    }
                    break;
                
                case 10:
                    if(x.second == 1) {
                        _val = -200;
                    }
                    break;
                
                case 11:
                    if(x.second == 1) {
                        _val = -120;
                    }
                    break;

                case 12:
                    _val = x.second * 10;
                    break;
                
                case 13:
                    if(x.second < 50000) {
                        _val = 500;
                    }
                    else if(x.second >= 50000 && x.second < 100000) {
                        _val = 300;
                    }
                    else if(x.second >= 100000 && x.second < 300000) {
                        _val = 200;
                    }
                    else if(x.second >= 300000 && x.second < 500000) {
                        _val = 100;
                    }
                    break;
                
                case 14:
                    if(x.second == 0) {
                        _val = -200;
                    }
                    else if(x.second == 2) {
                        _val = 200;
                    }
                    break;

                case 15:
                    if(x.second == 1) {
                        _val = -200;
                    }
                
                default:
                    break;
            }

            factors_set.insert({_key, _val});
        }
       
    }

    int computePremiums(holders* holder) {
        int premiums = BASIC_FEE;
        int cnt = 0;
        map<string, int> indexed_factors; 
        map<string, float> computed_factors;
        map<int, int> indexed_attr;
      
        for(auto x: holder->info) {
            indexed_factors.insert({x.first, cnt});
            cnt++;
        }
      
        for(auto x: indexed_factors) {
            for(auto y: holder->info) {
                if(x.first == y.first) {
                    indexed_attr.insert({x.second, y.second});
                }
            }
        }

        computeFactors(holder, computed_factors, indexed_factors, indexed_attr);

        float extra_charge = 0;
        for(auto x: computed_factors) {
            if(abs(x.second) > 5 || x.second == 0) {
                premiums += x.second;    
            }
            else if(x.second > 1 && x.second <5){
                extra_charge += x.second;
            }
            
            // cout << x.first << " : " << x.second << endl;
        }
        premiums *= extra_charge;
        cout << "Temporary insurance premiums is : " << premiums << endl;

        return premiums;
    }


    // Issuer generates credential(which is accumulated as a set element) only if holder satisfies some attributes that issuer requires
    // This would be changed according to which attribute is used.
    // In fact, we pass more parameter for considering which credential the holder wants to issue realted to attributes.
    // In current state, we omit this parameter and assume that all of the attributes that holder has 
    // are isssued with credential since we only consider the car insurance scenario for now.
    void issue(membership::public_param* pp, holders* &holder, vector<BIGNUM*> &S, BIGNUM* &ACC, int hash_type) {
        libff::start_profiling();
        libff::enter_block("Call to issuer");

        BIGNUM* bn_issuer_key = BN_new();
        BIGNUM* addr = BN_new();
        BN_CTX* bn_ctx = BN_CTX_new();
        BN_rand(bn_issuer_key, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        addrGen(addr, bn_issuer_key);

        bool _satisfied = true;

        int rand_num = 0;
        string ACC_val;
        
        if(!_satisfied) {
            membership::print_debug("This holder does not satisfy the requirement.");
            abort();
        }

        // cout << "The number of attributes that holder has : " <<  holder->info.size() << endl;

        for(auto x: holder->info) {
            credentials* tmp_cred = new credentials;
            tmp_cred->addrIssuer = BN_new();
            tmp_cred->c = BN_new();
            BN_copy(tmp_cred->addrIssuer, addr);

            transactions* tx = new transactions;
            tx->addr_issuer = BN_new();
            BN_copy(tx->addr_issuer, addr);
            tx->h = BN_new();
            tx->c = BN_new();

            if(hash_type == 0) {
                do{
                    attrHash(tx->h, holder->id, x.first, x.second, rand_num);
                    credGen(tx->c, addr, tx->h);
                    rand_num += 1;
                }while(tx->c, 5, NULL, bn_ctx, NULL);
            }
            else if(hash_type == 1) {
                string str_key = string_to_hex(x.first);
                string str_val = to_string(x.second);
                string _mid = BN_bn2hex(holder->id) + str_key + str_val;
                
                do{
                    string _input = to_string(rand_num) + _mid;                    
                    attrHashPos(tx->h, _input);
                    credGenPos(tx->c, addr, tx->h);
                    rand_num += 1;
                }while(tx->c, 5, NULL ,bn_ctx, NULL);
            }
            
            
            tmp_cred->rand = &rand_num;
            tmp_cred->c = tx->c;            
            tmp_cred->attrCred_key = x.first;
            tmp_cred->attrCred_val = x.second;

            addCred(S, tx->c);
            ACC_val = BN_bn2dec(ACC);

            if(ACC_val == "1") {
                membership::print_debug("DEBUG ACCUMULATE");
                membership::accumulate(pp, S, ACC);
                cout << BN_bn2dec(ACC) << endl;
            }
            else {
                BIGNUM* modN = BN_new();
                BN_hex2bn(&modN, fmpz_get_str(NULL, 16, pp->N));
                BN_mod_exp(ACC, ACC, tx->c, modN, bn_ctx);
            }

            holder->holderCred.push_back(tmp_cred);
        }

        BN_CTX_free(bn_ctx);
        libff::leave_block("Call to issuer");
    }

    void proof(libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> _snark, 
        const libsnark::r1cs_gg_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> snark_key,
    libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> &snark_proof,
    membership::public_param* pp, libff::G1_vector<def_pp> &com_base, vector<BIGNUM*> S, 
    vector<BIGNUM*> _credentials, membership::mem_proof* memProof, bool is_opt, int hash_type) {
        if(!is_opt) {
            membership::compute(_snark, snark_key, snark_proof, pp, com_base, S, _credentials, memProof, hash_type);
        }
        else {
            membership::optCompute(_snark, snark_key, snark_proof, pp, com_base, S, _credentials, memProof, hash_type);
        }
    }

    bool verify(libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> _snark, 
    libsnark::r1cs_gg_ppzksnark_verification_key<libsnark::default_r1cs_gg_ppzksnark_pp> snark_vk, 
    libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> snark_proof,
    membership::public_param* pp, BIGNUM* &ACC, vector<BIGNUM*> S, membership::mem_proof* memProof, bool is_opt, int hash_type) {
        if(!is_opt) {
            return membership::verify(_snark, snark_vk, snark_proof, pp, ACC, S, memProof, hash_type);
        }
        else {
            return membership::optVerify(_snark, snark_vk, snark_proof, pp, ACC, S, memProof, hash_type);
        }
    }
}
