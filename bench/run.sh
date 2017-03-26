#!/bin/bash

# you must have run the assembly command from sbt for this to work
CLASSPATH=../target/scala-2.12/libmix-assembly-0.2-SNAPSHOT.jar:../target/scala-2.12/scala-library-2.12.1-assembly.jar

MAINCLASS=org.nvotes.libmix.benchmark.Benchmark

# the first options to test
OPTIONS_ONE="-Dlibmix.gmp=true -Dlibmix.extractor=true -Dlibmix.parallel-generators=true"

java $OPTIONS_ONE -classpath $CLASSPATH $MAINCLASS $*
