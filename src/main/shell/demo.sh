#!/bin/sh

#
# this script must be run from the home directory, so first copy it there
#

USE_GMP=true
USE_EXTRACTOR=false
BYPASS_MEMBERSHIP_CHECK=false
USE_GENERATORS_PARALLEL=false
GENERATORS_PARALLELISM_LEVEL=16
CLUSTER_SEED=localhost:2555

# you must have run assemblyPacakgeDependency and package from sbt for this to work
CPATH=target/scala-2.12/libmix_2.12-0.1-SNAPSHOT.jar:target/scala-2.12/libmix-assembly-0.1-SNAPSHOT-deps.jar

# GC_LOGGING="XX:+PrintGCDetails -XX:+PrintGCDateStamps -Xloggc:gc.log"
OPTIONS="-Dmpservice.use-gmp=$USE_GMP -Dmpservice.use-extractor=$USE_EXTRACTOR -Dbypass-membership-check=$BYPASS_MEMBERSHIP_CHECK -Duse-generators-parallel=$USE_GENERATORS_PARALLEL -Dgenerators-parallelism-level=$GENERATORS_PARALLELISM_LEVEL"

java $OPTIONS -d64 -Xms1G -Xmx1G -Djava.library.path=. -classpath $CPATH org.nvotes.mix.demo.ElectionTest $*
