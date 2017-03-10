# nMix

Fork of agora-mixnet, the following changes have been made

* Removed fiware trash
* Updated to unicrypt version 1c1dc26 (https://github.com/bfh-evg/unicrypt/commit/1c1dc260e000e4d868e929456d1c7703fd8a691a)
* Removed bypass-membership-checks code
* Added gmp modpows to unicrypt (jnagmp)
* Added gmp legendre for membership checks to unicrypt (jnagmp kronecker)
* Converted CryptoTest to proper ScalaTest format (sbt test)
* Rearranged packages
* Separated demo code into its own package (some trustee code in Demo.scala)
* Renamed Util.getE
* Removed Akka clustering and akka dependencies
* Removed demo code and shapeless dependency into other project

### Work to do

* Re add unicrypt parallelism optimizations (this is the big part)
* Re add benchmarking scripts
* Add demo following reactive protocol using local bb
* Update to unicrypt latest version (Currently Nov 15)