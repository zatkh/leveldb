#!/bin/bash
export TEST_TMPDIR=./test
NUM=1000000
# some engines appear to ignore the cache_size and just grab as much RAM as they want
CACHE=34359738368
# some engines honor the cache_size, give them more.
CACHE2=137438953472
WRATE=0
STATS=1048576
DUR=600
TIME="/usr/bin/time -v"


rm -rf $TEST_TMPDIR

mkdir -p $TEST_TMPDIR
$TIME ./db_bench --num=$NUM --benchmarks=fillseq #--benchmarks=readwhilewriting 
for THREADS in 1 2 4 8 16 32 64; do
echo THREADS=$THREADS
$TIME ./db_bench --num=$NUM --use_existing_db=1 --benchmarks=readwhilewriting --threads=$THREADS
du $TEST_TMPDIR
done

