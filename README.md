# nMixlib

A mixnet library built on top of [unicrypt](https://github.com/bfh-evg/univote2) and the [univote](https://github.com/bfh-evg/univote2) design. Provides

* A Scala interface to mixnet-based voting system building blocks
* An automatic parallelization mechanism for modPow operations
* A bridge to native Gmp operations for modPow and Legendre
* Patches to the unicrypt library for optimisation (parallelism, native code)

See [here](https://nvotes.com/parallelizing-a-mixnet-prototype/) for performance numbers.

## Latest changes

* Updated to unicrypt 2.2-release (commit c6d3502100e4950e123326dcc5278265432f5a33)
* Removed Akka clustering and akka dependencies
* Removed shapeless dependency
* Removed bypass-membership-checks code
* Added gmp modpows to unicrypt (jnagmp)
* Added gmp legendre for membership checks to unicrypt (jnagmp kronecker)
* Converted CryptoTest to ScalaTest format (sbt test)
* Rearranged packages
* Added benchmark/demo

### Work to do

* Re add unicrypt parallelism optimizations (this is the big part)