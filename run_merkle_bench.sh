#!/bin/sh

#build/libsnark/jsnark_lego_interface/bench_setmem_lego merkle poseidon 16 |  tee log_merkle_pos16
#build/libsnark/jsnark_lego_interface/bench_setmem_lego merkle poseidon 32 |  tee log_merkle_pos32

#build/libsnark/jsnark_lego_interface/bench_setmem_lego merkle sha 16 |  tee log_merkle_sha16
build/libsnark/jsnark_lego_interface/bench_setmem_lego merkle sha 32 | tee log_merkle_sha32
