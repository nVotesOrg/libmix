# nMixlib

A mixnet library built on top of [unicrypt](https://github.com/bfh-evg/univote2) and the [univote](https://github.com/bfh-evg/univote2) design. Provides

* A Scala interface to mixnet-based voting system building blocks
* An automatic parallelization mechanism for modPow operations
* A bridge to native Gmp operations for modPow and Legendre
* Patches to the unicrypt library for optimisation (parallelism, native code)

See [here](https://nvotes.com/parallelizing-a-mixnet-prototype/) for performance numbers.

## Latest changes

* Removed fiware
* ~~Updated to unicrypt version 1c1dc26 (https://github.com/bfh-evg/unicrypt/commit/1c1dc260e000e4d868e929456d1c7703fd8a691a)~~
* Removed bypass-membership-checks code
* Added gmp modpows to unicrypt (jnagmp)
* Added gmp legendre for membership checks to unicrypt (jnagmp kronecker)
* Converted CryptoTest to proper ScalaTest format (sbt test)
* Rearranged packages
* Removed Akka clustering and akka dependencies
* Removed demo code and shapeless dependency
* Updated to unicrypt to 2.2-release (commit c6d3502100e4950e123326dcc5278265432f5a33)
* Added benchmark/demo

### Work to do

* Re add unicrypt parallelism optimizations (this is the big part)