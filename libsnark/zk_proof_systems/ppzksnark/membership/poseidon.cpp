#include <iostream>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <stdexcept>

#include "poseidon.hpp"
#include "poseidon_constant.hpp"


using namespace std;


namespace Hashes {
    BIGNUM* Poseidon::hash( const vector<BIGNUM*> & inputs , BIGNUM* __FIELD_PRIME ){
        
        FIELD_PRIME = __FIELD_PRIME ;

        if (!constants_loaded) {

            NUM_ROUNDS_P.insert(NUM_ROUNDS_P.end(), { 56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68 } );
            NUM_ROUNDS_F = 8;

            load_opt_constants();

            constants_loaded = true ;
        }
        
        if (inputs.size() == 0 || inputs.size() > NUM_ROUNDS_P.size())
        {
            throw invalid_argument("invalid inputs length");
        }

        return _poseidon(inputs) ;

    }

    BIGNUM* Poseidon::_poseidon(const vector<BIGNUM*> & inputs)
    {
        int t = inputs.size() + 1 ;
        int nRoundsP = NUM_ROUNDS_P[t - 2];
        int nRoundsF = NUM_ROUNDS_F ;  

        vector<BIGNUM*> c = C[t-2]; // C.size() = 3
        vector<BIGNUM*> s = S[t-2]; 
        vector<vector<BIGNUM*>> m = M[t-2];
        vector<vector<BIGNUM*>> p = P[t-2];
        

        BIGNUM* bn_zero = BN_new();
        BN_CTX* bn_ctx = BN_CTX_new();
        BN_zero(bn_zero);

        vector<BIGNUM*> state { bn_zero };
        state.insert(state.end(), inputs.begin(), inputs.end()) ;

        ark(state, c, 0);

        for (int i = 0; i < nRoundsF / 2 - 1; i++) {
            exp5state(state);
            ark(state, c, (i + 1) * t);
            mix(state, m);
        }     

        
        exp5state(state);
        ark(state, c, (nRoundsF / 2) * t);
        mix(state, p);

        for (int i = 0; i < nRoundsP; i++) {
            state[0] = exp5(state[0]);
            // state[0] = state[0].add(c[(nRoundsF / 2 + 1) * t + i]).mod(FIELD_PRIME);
            BN_mod_add(state[0], state[0], c[(nRoundsF / 2 + 1) * t + i], FIELD_PRIME, bn_ctx);

            BIGNUM* newState0 = BN_new();
            BN_zero(newState0);

            for (int j = 0; j < t; j++) {
                BIGNUM* bn_tmp = BN_new();
                BN_mul(bn_tmp, state[j], s[(t * 2 - 1) * i + j], bn_ctx);
                BN_mod_add(newState0, newState0, bn_tmp, FIELD_PRIME, bn_ctx);
                // newState0 = newState0.add(state[j].multiply(s[(t * 2 - 1) * i + j])).mod(FIELD_PRIME);
            }

            for (int k = 1; k < t; k++) {
                BIGNUM* bn_tmp = BN_new();

                BN_mul(bn_tmp, state[0], s[(t * 2 - 1) * i + t + k - 1], bn_ctx);
                BN_mod_add(state[k], state[k], bn_tmp, FIELD_PRIME, bn_ctx);
                // state[k] = state[k].add(state[0].multiply(s[(t * 2 - 1) * i + t + k - 1]).mod(FIELD_PRIME)).mod(FIELD_PRIME);
            }
            state[0] = newState0;
        }

        for (int i = 0; i < nRoundsF / 2 - 1; i++) {
            exp5state(state);
            ark(state, c, (nRoundsF / 2 + 1) * t + nRoundsP + i * t);
            mix(state, m);
        }

        exp5state(state);
        mix(state, m);
       
        BN_CTX_free(bn_ctx);
    
        return state[0] ;
    }

    BIGNUM* Poseidon::exp5(BIGNUM* & a)
    {
        BIGNUM* bn_five = BN_new();
        BIGNUM* a5 = BN_new();
        BN_CTX* bn_ctx = BN_CTX_new();

        BN_dec2bn(&bn_five, "5");
        BN_mod_exp(a5, a, bn_five, FIELD_PRIME, bn_ctx);

        // BIGNUM* a2 = a.multiply(a).mod(FIELD_PRIME);
        // BIGNUM* a4 = a2.multiply(a2).mod(FIELD_PRIME);

        BN_CTX_free(bn_ctx);
        return a5;
    }

    void Poseidon::exp5state(vector<BIGNUM*> & _state)
    {
        for (size_t i = 0; i < _state.size(); i++)
        {
            _state[i] = exp5(_state[i]);
        }
    }

    void Poseidon::ark(vector<BIGNUM*> & _state, vector<BIGNUM*> & _c, int r)
    {
        BN_CTX* bn_ctx = BN_CTX_new();
        for (size_t i = 0; i < _state.size(); i++)
        {
            BN_mod_add(_state[i], _state[i], _c[r + i], FIELD_PRIME, bn_ctx);
            // _state[i] = _state[i].add(_c[r + i]).mod(FIELD_PRIME);
        }
        BN_CTX_free(bn_ctx);
    }

    void Poseidon::mix(vector<BIGNUM*> & _state, vector<vector<BIGNUM*>> & _m)
    {
        BN_CTX* bn_ctx = BN_CTX_new();
        vector<BIGNUM*> newState(_state.size()) ;
        for (size_t i = 0; i < _state.size(); i++)
        {
            BIGNUM* bn_zero = BN_new();
            BN_zero(bn_zero);
            newState[i] = bn_zero;
    
            for (size_t j = 0; j < _state.size(); j++)
            {                
                BIGNUM* bn_tmp = BN_new();
                BN_mod_mul(bn_tmp, _state[j], _m[j][i], FIELD_PRIME, bn_ctx);
                BN_mod_add(newState[i], newState[i], bn_tmp, FIELD_PRIME, bn_ctx);
            }
        }
        _state = newState;
    }

    int Poseidon::NUM_ROUNDS_F;
    vector<uint8_t> Poseidon::NUM_ROUNDS_P;
    vector<vector<vector<BIGNUM*>>> Poseidon::M;
    vector<vector<vector<BIGNUM*>>> Poseidon::P;
    vector<vector<BIGNUM*>> Poseidon::C;
    vector<vector<BIGNUM*>> Poseidon::S;
    BIGNUM* Poseidon::FIELD_PRIME = BN_new();
    bool Poseidon::constants_loaded = false;
    

    void Poseidon::load_opt_constants()
    {   

        vector<vector<string>> _C = PoseidonConstants::C ;
        vector<vector<string>> _S = PoseidonConstants::S ;
        vector<vector<vector<string>>> _M = PoseidonConstants::M ;
        vector<vector<vector<string>>> _P = PoseidonConstants::P ;
        
        C = vector<vector<BIGNUM*>>(_C.size());
        S = vector<vector<BIGNUM*>>(_S.size());
        M = vector<vector<vector<BIGNUM*>>>(_M.size());
        P = vector<vector<vector<BIGNUM*>>>(_P.size());

        for (size_t i=0; i<_C.size(); i++) {
            vector<string> _ith = _C[i];
            vector<BIGNUM*> temp(_ith.size());
            for (size_t j=0; j < _ith.size(); j++) {
                BN_hex2bn(&temp[j], _ith[j].c_str());
                // temp[j] = Bigint(_ith[j], 16) ;
            }
            C[i] = temp ;
        }

       

        for (size_t i=0; i<_S.size(); i++) {
            vector<string> _ith = _S[i];
            vector<BIGNUM*> temp(_ith.size());
            for (size_t j=0; j< _ith.size(); j++) {
                BN_hex2bn(&temp[j], _ith[j].c_str());
                // temp[j] = BIGNUM*(_ith[j], 16) ;
            }
            S[i] = temp ;
        }

        for (size_t i=0; i<_M.size(); i++) {
            vector<vector<string>> _ith = _M[i];
            vector<vector<BIGNUM*>> temp(_ith.size());
            for (size_t j=0; j< _ith.size(); j++) {
                vector<string> _ijth = _ith[j];
                vector<BIGNUM*> temp2(_ijth.size());
                for (size_t k=0; k < _ijth.size(); k++) {
                    BN_hex2bn(&temp2[k], _ijth[k].c_str());
                    // temp2[k] = BIGNUM*(_ijth[k], 16) ;
                }
                temp[j] = temp2;
            }
            M[i] = temp ;
        }

        for (size_t i=0; i<_P.size(); i++) {
            vector<vector<string>> _ith = _P[i];
            vector< vector<BIGNUM*> > temp(_ith.size());
            for (size_t j=0; j< _ith.size(); j++) {
                vector<string> _ijth = _ith[j];
                vector<BIGNUM*> temp2(_ijth.size());
                for (size_t k=0; k < _ijth.size(); k++) {
                    BN_hex2bn(&temp2[k], _ijth[k].c_str());
                    // temp2[k] = BIGNUM*(_ijth[k], 16) ;
                }
                temp[j] = temp2;
            }
            P[i] = temp ;
        }

    }

}




#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif   