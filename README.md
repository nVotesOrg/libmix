# nMixlib

A mixnet library built on top of [unicrypt](https://github.com/bfh-evg/univote2) and the [univote](https://github.com/bfh-evg/univote2) design. Provides

* A Scala interface to mixnet-based voting system building blocks
* An automatic parallelization mechanism for modPow operations
* A bridge to native gmp implementations for modPow and Legendre
* Patches to the unicrypt library for optimisation (parallelism, native code)
* A benchmark simulating the crypto for a full election cycle

See [here](https://nvotes.com/parallelizing-a-mixnet-prototype/) for performance numbers.

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

### Packaging

Use the

```sbt assembly```

command to generate the project jar, in the target directory.

This includes the nMixlib classes, the patched unicrypt classes and the original unicrypt
library classes. It also includes the jna-gmp classes, needed for native gmp code.

### Optimization switches

The following environment variables may be set

* USE_GMP=true/false

Activates native implementation of modular exponentiation and legendre symbol via
[jna-gmp](https://github.com/square/jna-gmp) and gmp, if available on the system.

* USE_EXTRACTOR=true/false

Activates automatic extraction and parallelization of modular exponentiation calls.

* USE_PARALLEL_GENERATORS=true/false

Activates parallel computation of generators used in Terelius-Wikstrom proofs (experimental)

### Randomness

To speed up HybridRandomByteSequence under linux install rng-tools.

### Work to do

* Revise configuration mechanism
* Proper tracing
* MPBridge clean up