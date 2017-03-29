# libmix

A mixnet library built on top of [unicrypt](https://github.com/bfh-evg/univote2) and the [univote](https://github.com/bfh-evg/univote2) design. Provides

* A Scala interface to mixnet-based voting system building blocks
* An automatic parallelization mechanism for modPow operations
* A bridge to native gmp implementations for modPow and Legendre
* Patches to the unicrypt library for optimisation (parallelism, native code)
* A benchmark simulating the crypto for a full election cycle

See [here](https://nvotes.com/parallelizing-a-mixnet-prototype/) for performance numbers.

### Running the benchmark

First make sure the project has been packaged, the benchmark script also needs the scala dependency:

```sbt assembly
sbt assemblyPackageScala```

In the bench directory you will find two scripts, 'run.sh' and 'bench.sh' Use run.sh to
execute one run of the benchmark. You need to pass in the number of votes, for example:

```./run.sh 1000```

To execute the benchmark simulating parallel execution of the offline phase of the shuffle,
pass in a second parameter to the script:

```./run.sh 1000 true```

Once the benchmark completes it will print out a time in seconds. You can adjust the optimization
settings (see below) editing the run.sh script.

The 'bench.sh' script can be used to carry out several runs comparing
different optimization settings. It also includes a simple gplot script
to plot results. Please refer to that file for details.

### Packaging the library

Use the

```sbt assembly```

command to generate the project jar, in the target directory.

This includes the nMixlib classes, the patched unicrypt classes and the original unicrypt
library classes. It also includes the jna-gmp classes, needed for native gmp code.

### Optimization switches

The following environment variables may be set

* libmix.gmp=true/false

Activates native implementation of modular exponentiation and legendre symbol via
[jna-gmp](https://github.com/square/jna-gmp) and gmp, if available on the system.

* libmix.extractor=true/false

Activates automatic extraction and parallelization of modular exponentiation calls.

* libmix.parallel-generators=true/false

Activates parallel computation of generators used in Terelius-Wikstrom proofs (experimental)

### Randomness

To speed up HybridRandomByteSequence under linux install rng-tools.

### Latest changes

* Updated to unicrypt 2.2-release (commit c6d3502100e4950e123326dcc5278265432f5a33)
* Updated to Scala 2.12
* Removed Akka clustering and akka dependencies
* Removed shapeless dependency
* Removed bypass-membership-checks code
* Added gmp modpows to unicrypt (jnagmp)
* Added gmp legendre for membership checks to unicrypt (jnagmp kronecker)
* Converted CryptoTest to ScalaTest format (sbt test)
* Rearranged packages
* Added benchmark/demo
* Readded unicrypt parallelism optimizations
* Added support for offline + online phase split
* Added sl4j tracing

### Work to do

* Revise configuration mechanism
* MPBridge clean up