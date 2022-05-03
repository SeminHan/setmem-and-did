#pragma once

#include <string>
#include <vector>
#include <openssl/bn.h>


using namespace std;

namespace Hashes {

	class Poseidon {
    
    private :
        
        static const size_t numRounds ;
        static vector<BIGNUM*> roundConstants;
        static BIGNUM* FIELD_PRIME ;

        static int NUM_ROUNDS_F ;
        static vector<uint8_t> NUM_ROUNDS_P ;
        static vector<vector<vector<BIGNUM*>>> M ;
        static vector<vector<vector<BIGNUM*>>> P ;
        static vector<vector<BIGNUM*>> C ;
        static vector<vector<BIGNUM*>> S ;
        static bool constants_loaded ;

        

	public :
        
		static BIGNUM* hash(const vector<BIGNUM*> & inputs , BIGNUM* __FIELD_PRIME ) ;

	private :

        static BIGNUM* _poseidon(const vector<BIGNUM*> & inputs) ;
        static BIGNUM* exp5(BIGNUM* & a) ;
        static void exp5state(vector<BIGNUM*> & state) ;
        static void ark(vector<BIGNUM*> & state, vector<BIGNUM*> & c, int it) ;
        static void mix(vector<BIGNUM*> & state, vector<vector<BIGNUM*>> & m) ;
        static void load_opt_constants();

    };


}