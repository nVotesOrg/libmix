#!/bin/bash

# you must have run the assembly command from sbt for this to work
CLASSPATH=../target/scala-2.12/libmix-assembly-0.2-SNAPSHOT.jar:../target/scala-2.12/scala-library-2.12.1-assembly.jar

MAINCLASS=org.nvotes.libmix.benchmark.Benchmark

# the first options to test
OPTIONS_ONE="-Dlibmix.gmp=true -Dlibmix.extractor=true -Dlibmix.parallel-generators=true"

# the second  options to test
OPTIONS_TWO="-Dlibmix.gmp=true -Dlibmix.extractor=false -Dlibmix.parallel-generators=false"

# space sperated list of vote counts to run
RUNS="100 200"

# note that previous runs are not deleted, this allows incrementally adding data to the file
# but you must manually delete it if you want to overwrite
cp ./times.dat ./times.dat.bak 2>/dev/null || :

# run it
for votes in $RUNS
do
  echo running votes = $votes
  time1=`java $OPTIONS_ONE -classpath $CLASSPATH $MAINCLASS $votes | grep -Po '(?<=time: )[^\] ]*'`
  time2=`java $OPTIONS_TWO -classpath $CLASSPATH $MAINCLASS $votes | grep -Po '(?<=time: )[^\] ]*'`
  echo $votes $time1 $time2
  echo $votes $time1 $time2  >> times.dat
done
