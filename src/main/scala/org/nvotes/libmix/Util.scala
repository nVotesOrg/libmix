package org.nvotes.libmix

import ch.bfh.unicrypt.math.algebra.general.abstracts.AbstractSet
import ch.bfh.unicrypt.math.algebra.general.interfaces.Element
import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModElement
import ch.bfh.unicrypt.crypto.schemes.encryption.classes.ElGamalEncryptionScheme
import ch.bfh.unicrypt.math.algebra.general.interfaces.Element
import ch.bfh.unicrypt.math.algebra.general.classes.Pair
import ch.bfh.unicrypt.math.algebra.general.classes.Tuple
import ch.bfh.unicrypt.crypto.encoder.classes.ZModPrimeToGStarModSafePrime
import ch.bfh.unicrypt.math.algebra.general.classes.ProductSet
import ch.bfh.unicrypt.helper.converter.classes.biginteger.ByteArrayToBigInteger
import ch.bfh.unicrypt.helper.converter.classes.bytearray.BigIntegerToByteArray
import ch.bfh.unicrypt.helper.converter.classes.bytearray.StringToByteArray
import ch.bfh.unicrypt.helper.converter.classes.biginteger.BigIntegerToBigInteger
import ch.bfh.unicrypt.math.algebra.general.abstracts.AbstractCyclicGroup
import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarMod
import ch.bfh.unicrypt.helper.random.deterministic.CTR_DRBG
import ch.bfh.unicrypt.helper.random.deterministic.DeterministicRandomByteSequence
import ch.bfh.unicrypt.helper.math.MathUtil
import ch.bfh.unicrypt.helper.array.classes.ByteArray
import ch.bfh.unicrypt.helper.tree.Tree
import ch.bfh.unicrypt.helper.hash.HashMethod

import java.util.List
import java.math.BigInteger
import scala.collection.JavaConverters._

/**
 *  Some utilities
 */
object Util {

  val useGmp = getEnvBoolean("libmix.gmp")
  // obsolete, remove
  val generatorParallelism = 10

  /** Returns a boolean system property, specified with -Dname=true|false */
  def getEnvBoolean(variable: String) = {
    sys.props.get(variable).getOrElse("false").toBoolean
  }

  /** Converts a Seq of unicrypt Elements to a unicrypt Tuple */
  def tupleFromSeq(items: Seq[Element[_]]) = {
    Tuple.getInstance(items:_*)
  }

  /** Converts unicrypt Tuples of Elements to a
    Seq of Strings, using parallelism */
  def stringsFromTuple(tuple: Tuple): Seq[String] = {
    tuple.asScala.par.map{ x => x.convertToString }.seq.toSeq
  }

  /** Returns random elements from the encryption space, useful to generate
    random encryptions faster than encrypting known plaintexts */
  def getRandomVotes(size: Int, generator: GStarModElement, publicKey: GStarModElement) = {
    val elGamal = ElGamalEncryptionScheme.getInstance(generator)

    (1 to size).par.map { _ =>
      elGamal.getEncryptionSpace().getRandomElement()
    }
  }

  /** Returns random elements from the encryption space as Strings, useful to generate
    random encryptions faster than encrypting known plaintexts */
  def getRandomVotesStr(size: Int, generator: GStarModElement, publicKey: GStarModElement) = {
    val elGamal = ElGamalEncryptionScheme.getInstance(generator)

    (1 to size).par.map { _ =>
      elGamal.getEncryptionSpace().getRandomElement().convertToString
    }
  }

  /** Encodes and encrypts the given plaintexts, using parallelism */
  def encryptVotes(plaintexts: Seq[Int], cSettings: CryptoSettings, publicKey: GStarModElement) = {
    val elGamal = ElGamalEncryptionScheme.getInstance(cSettings.generator)
    val encoder = ZModPrimeToGStarModSafePrime.getInstance(cSettings.group)

    plaintexts.par.map { p =>
      val message = encoder.getDomain().getElementFrom(p)
      val encodedMessage = encoder.encode(message)
      elGamal.encrypt(publicKey, encodedMessage)
    }.seq
  }

  /** Returns the the public key corresponding to the input string */
  def getPublicKeyFromString(publicKey: String, generator: GStarModElement): GStarModElement = {
    val elGamal = ElGamalEncryptionScheme.getInstance(generator)
    val keyPairGen = elGamal.getKeyPairGenerator()
    keyPairGen.getPublicKeySpace().getElementFrom(publicKey).asInstanceOf[GStarModElement]
  }

  /** Get an element from its string representation
   *
   *  This function exists because the scala compiler reports an ambiguity
   *  when using the getElementFrom method without casting to AbstractSet,
   *  since ProductSet contains an ellipsis overload which accepts one argument
   *  as a particular case.
   *
   *  Calling this function can be avoided by using casts like:
   *
   *  .asInstanceOf[AbstractSet[_,_]].getElementFrom(string)
   *
   */
  def fromString[A <: Element[B],B](set: AbstractSet[A, B], value: String): Element[B] = {
    set.getElementFrom(value)
  }

  /** Get an element from its byte array representation
   *
   *  This function exists because the scala compiler reports an ambiguity
   *  when using the getElementFrom method without casting to AbstractSet,
   *  since ProductSet contains an ellipsis overload which accepts one argument
   *  as a particular case.
   *
   *  We can either rename this function or get rid of it, using casts like:
   *
   *  .asInstanceOf[AbstractSet[_,_]].getElementFrom
   *
   *  This is method is unused, but will be useful for byte serialization
   */
  def fromBytes[A <: Element[B],B](set: AbstractSet[A, B], value: Array[Byte]): Element[B] = {
    val bytes = ByteArray.getInstance(value :_*)
    set.getElementFrom(bytes)
  }

  /** Returns independent generators for a cyclic group, using parallelism
   *
   *  Independent generators are necessary for TW proofs of shuffle.
   */
  def parGetIndependentGenerators[E <: Element[_]](group: AbstractCyclicGroup[E, _], skip: Int, size: Int): java.util.List[E] = {
    val split = generatorParallelism
    val total = size + skip

    val a = Array.fill(total % split)((total / split) + 1)
    val b = Array.fill(split - (total % split))(total / split)
    val c = a ++ b

    val seedLength = CTR_DRBG.getFactory().getSeedByteLength()
    val converter = ByteArrayToBigInteger.getInstance(seedLength)

    val rds = c.zipWithIndex.map{ case (value, index) =>
      // 1000: we want to leave room for generators not to overlap
      val seed = java.math.BigInteger.valueOf(index * (total / split) * 1000).mod(MathUtil.powerOfTwo(CTR_DRBG.getFactory().getSeedByteLength()))

      val r = DeterministicRandomByteSequence.getInstance(CTR_DRBG.getFactory(), converter.reconvert(seed))
      (r, value)
    }

    val items = rds.par.flatMap { case (d, i) =>
      val sequence = group.getIndependentGenerators(d).limit(i)
      sequence.asScala.toList
    }

    items.drop(skip).toList.asJava
  }

  /** Returns independent generators for safe prime cyclic group, using parallelism
   *  The implementation follows the NIST standard FIPS PUB
   *  186-4 (Appendix A.2.3)
   *
   *  Independent generators are necessary for TW proofs of shuffle.
   */
  def parGetIndependentGeneratorsFIPS(group: GStarMod, skip: Int, size: Int): List[GStarModElement] = {
    val domainParameterSeed = "FIXME"
    val stringConverter = StringToByteArray.getInstance()
    val indexCountConverter = BigIntegerToByteArray.getInstance()
    val hashMethod = HashMethod.getInstance()
    val converter = ByteArrayToBigInteger.getInstance(hashMethod.getHashAlgorithm().getByteLength())

    val total = size + skip

    val generators = (1 to total).par.map { index =>
      var count = 0
      var g = BigInteger.ONE
      do {
        count = count + 1
        val u: Tree[ByteArray] = Tree.getInstance(stringConverter.convert(domainParameterSeed), stringConverter.convert("ggen"), indexCountConverter.convert(BigInteger.valueOf(index)), indexCountConverter.convert(BigInteger.valueOf(count)));
        val w = hashMethod.getHashValue(u)
        g = org.nvotes.libmix.mpservice.MPBridge.modPow(
            converter.convert(w), group.getCoFactor(), group.getModulus())

      } while(g.compareTo(MathUtil.ONE) <= 0)

      group.getElement(g)
    }

    generators.drop(skip).toList.asJava
  }

  /*

  return Sequence.getInstance(1, index -> index + 1).map(index -> {
      int count = 0;
      BigInteger g;
      do {
        count++;
        Tree<ByteArray> u = Tree.getInstance(stringConverter.convert(domainParameterSeed), stringConverter.convert("ggen"), indexCountConverter.convert(BigInteger.valueOf(index)), indexCountConverter.convert(BigInteger.valueOf(count)));
        ByteArray w = hashMethod.getHashValue(u);
        g = MathUtil.modExp(converter.convert(w), this.getCoFactor(), this.getModulus());
      } while (g.compareTo(MathUtil.ONE) <= 0);
      return this.abstractGetElement(g);

  */

  /** Returns the legendre symbol, optionally using native gmp code */
  def legendreSymbol(a: BigInteger, p: BigInteger): Int = {
    if(useGmp) {
      com.squareup.jnagmp.Gmp.kronecker(a, p)
    }
    else {
      MathUtil.legendreSymbol(a, p)
    }
  }

  def time[R](tag: String)(block: => R): R = {
    val t0 = System.nanoTime()
    val result = block
    val t1 = System.nanoTime()
    println(s"Elapsed time '$tag': " + ((t1 - t0) / 1000000000.0) + " s")
    result
  }
}