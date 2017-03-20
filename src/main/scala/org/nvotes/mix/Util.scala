package org.nvotes.mix

import ch.bfh.unicrypt.math.algebra.general.abstracts.AbstractSet
import ch.bfh.unicrypt.math.algebra.general.interfaces.Element
import ch.bfh.unicrypt.crypto.schemes.encryption.classes.ElGamalEncryptionScheme
import ch.bfh.unicrypt.math.algebra.general.interfaces.Element
import ch.bfh.unicrypt.math.algebra.general.classes.Pair
import ch.bfh.unicrypt.math.algebra.general.classes.Tuple
import ch.bfh.unicrypt.crypto.encoder.classes.ZModPrimeToGStarModSafePrime
import ch.bfh.unicrypt.math.algebra.general.classes.ProductSet
import ch.bfh.unicrypt.helper.converter.classes.biginteger.ByteArrayToBigInteger
import ch.bfh.unicrypt.math.algebra.general.abstracts.AbstractCyclicGroup
import ch.bfh.unicrypt.helper.random.deterministic.CTR_DRBG
import ch.bfh.unicrypt.helper.random.deterministic.DeterministicRandomByteSequence
import ch.bfh.unicrypt.helper.math.MathUtil
import java.math.BigInteger
import scala.collection.JavaConverters._

/** Some utilities
 *
 */
object Util {

  val useGmp = getEnvBoolean("nmixlib.gmp")
  val generatorParallelism = 10

  def getEnvBoolean(variable: String) = {
    sys.props.get(variable).getOrElse("false").toBoolean
  }

  def tupleFromSeq(items: Seq[Element[_]]) = {
    Tuple.getInstance(items:_*)
  }

  def stringsFromTuple(tuple: Tuple): Seq[String] = {
    tuple.asScala.par.map{ x => x.convertToString }.seq.toSeq
  }

  def getRandomVotes(size: Int, generator: Element[_], publicKey: Element[_]) = {
    val elGamal = ElGamalEncryptionScheme.getInstance(generator)

    (1 to size).map { _ =>
      val element = elGamal.getMessageSpace().getRandomElement()
      println(s"* plaintext $element")
      elGamal.encrypt(publicKey, element)
    }
  }

  def encryptVotes(plaintexts: Seq[Int], cSettings: CryptoSettings, publicKey: Element[_]) = {
    val elGamal = ElGamalEncryptionScheme.getInstance(cSettings.generator)
    val encoder = ZModPrimeToGStarModSafePrime.getInstance(cSettings.group)

    plaintexts.par.map { p =>
      val message = encoder.getDomain().getElementFrom(p)
      val encodedMessage = encoder.encode(message)
      elGamal.encrypt(publicKey, encodedMessage)
    }.seq
  }

  def getPublicKeyFromString(publicKey: String, generator: Element[_]) = {
    val elGamal = ElGamalEncryptionScheme.getInstance(generator)
    val keyPairGen = elGamal.getKeyPairGenerator()
    keyPairGen.getPublicKeySpace().getElementFrom(publicKey)
  }

  /** Get an element from its string representation
   *
   *  This function exists because the scala compiler reports an ambiguity
   *  when using the getElementFrom method without casting to AbstractSet,
   *  since ProductSet contains an ellipsis overload which accepts one argument
   *  as a particular case.
   *
   *  We can either rename this function or get rid of it, using casts like:
   *
   *  .asInstanceOf[AbstractSet[_,_]].getElementFrom(string)
   *
   */
  def fromString[A <: Element[B],B](set: AbstractSet[A, B], value: String): Element[B] = {
    set.getElementFrom(value)
  }

  def getIndependentGenerators[E <: Element[_]](group: AbstractCyclicGroup[E, _], skip: Int, size: Int): java.util.List[E] = {
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
      // println("*** index " + index + " seed " + seed + " value " + value)
      val r = DeterministicRandomByteSequence.getInstance(CTR_DRBG.getFactory(), converter.reconvert(seed))
      (r, value)
    }
    // rds.foreach(println)

    val items = rds.par.flatMap { case (d, i) =>
      val sequence = group.getIndependentGenerators(d).limit(i)
      sequence.asScala.toList
    }
    println("getIndependentGenerators " + total + " " + items.size)

    // DenseArray.getInstance(items.drop(skip).toList.toArray)
    items.drop(skip).toList.asJava
  }

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