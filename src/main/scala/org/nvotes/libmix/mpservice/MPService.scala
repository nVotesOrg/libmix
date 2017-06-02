package org.nvotes.libmix.mpservice

import scala.concurrent.duration.DurationInt
import java.math.BigInteger
import scala.collection._
import scala.util.Try
import scala.util.Success
import com.squareup.jnagmp.Gmp

import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Represents a modular exponentiation operation
 */
case class ModPow(base: BigInteger, pow: BigInteger, mod: BigInteger)

/**
 * Represents a modular exponentiation operation with common modulus (see below)
 */
case class ModPow2(base: BigInteger, pow: BigInteger)

/**
 * Represents a modpow result, together with the request parameters
 */
case class ModPowResult(base: BigInteger, pow: BigInteger, mod: BigInteger, result: BigInteger)

/**
 * The mpservice public api
 */
trait ModPowService {
  /** Compute modular exponentiation for a list of inputs */
  def compute(work: Array[ModPow]): Array[BigInteger]

  /** Compute modular exponentiation for a list of inputs with common modulus */
  def compute(work: Array[ModPow2], mod: BigInteger): Array[BigInteger]

  /** Compute modular exponentiation for a list of inputs
   *
   *  Returns (also) the inputs to the computation to allow checking for consistency.
   */
  def computeDebug(work: Array[ModPow2], mod: BigInteger): Array[ModPowResult]
}

/**
 * Entrypoint for the implementation of the service.
 */
object MPService extends ModPowService {
  /** The underlying service */
  val service = GmpParallelModPowService

  /** Compute modular exponentiation for a list of inputs */
  def compute(work: Array[ModPow]): Array[BigInteger] = service.compute(work)

  /** Compute modular exponentiation for a list of inputs with common modulus */
  def compute(work: Array[ModPow2], mod: BigInteger): Array[BigInteger] = service.compute(work, mod)

  /** Compute modular exponentiation for a list of inputs, returns inputs also */
  def computeDebug(work: Array[ModPow2], mod: BigInteger): Array[ModPowResult] = service.computeDebug(work, mod)

  override def toString = service.getClass.toString
}


/** Sequential ModPowService implementation
 *
 *  This implementation has no benefits over un-extracted modpows
 *  it is here for consistency
 */
object SequentialModPowService extends ModPowService {
  /** Compute modular exponentiation for a list of inputs */
  def compute(work: Array[ModPow]): Array[BigInteger] = work.map(x => x.base.modPow(x.pow, x.mod))

  /** Compute modular exponentiation for a list of inputs with common modulus */
  def compute(work: Array[ModPow2], mod: BigInteger): Array[BigInteger] = work.map(x => x.base.modPow(x.pow, mod))

  /** Compute modular exponentiation for a list of inputs, returns inputs also */
  def computeDebug(work: Array[ModPow2], mod: BigInteger): Array[ModPowResult] = {
    work.map(x => ModPowResult(x.base, x.pow, mod, x.base.modPow(x.pow, mod))).seq.toArray
  }
}

/** Parallel and native ModPowService implementation
 *
 *  Uses both parallelism and native modpow calls.
 *  Uses scala parllel collections to parallelize modpow calls.
 *  Uses GMP (via jna-gmp) to make native modpow calls
 */
object GmpParallelModPowService extends ModPowService {
  /** Compute modular exponentiation for a list of inputs */
  def compute(work: Array[ModPow]): Array[BigInteger] = {
    work.par.map(x => Gmp.modPowInsecure(x.base, x.pow, x.mod)).seq.toArray
  }

  /** Compute modular exponentiation for a list of inputs with common modulus */
  def compute(work: Array[ModPow2], mod: BigInteger): Array[BigInteger] = {
    work.par.map(x => Gmp.modPowInsecure(x.base, x.pow, mod)).seq.toArray
  }

  /** Compute modular exponentiation for a list of inputs, returns inputs also */
  def computeDebug(work: Array[ModPow2], mod: BigInteger): Array[ModPowResult] = {
    work.par.map(x => ModPowResult(x.base, x.pow, mod, Gmp.modPowInsecure(x.base, x.pow, mod))).seq.toArray
  }
}

/** Parallel and native ModPowService implementation
 *
 *  Uses scala parllel collections to parallelize modpow calls
 */
object ParallelModPowService extends ModPowService {
  /** Compute modular exponentiation for a list of inputs */
  def compute(work: Array[ModPow]): Array[BigInteger] = work.par.map(x => x.base.modPow(x.pow, x.mod)).seq.toArray

  /** Compute modular exponentiation for a list of inputs with common modulus */
  def compute(work: Array[ModPow2], mod: BigInteger): Array[BigInteger] = work.par.map(x => x.base.modPow(x.pow, mod)).seq.toArray

  /** Compute modular exponentiation for a list of inputs, returns inputs also */
  def computeDebug(work: Array[ModPow2], mod: BigInteger): Array[ModPowResult] = {
    work.par.map(x => ModPowResult(x.base, x.pow, mod, x.base.modPow(x.pow, mod))).seq.toArray
  }
}

/** Scala version of MPBridge
 *
 *  NOTE: Currently unused
 */
object MPBridgeScala {

  val logger = LoggerFactory.getLogger(MPBridgeScala.getClass)

  /** Extract modpows from the given function
   *
   *  Uses MPBridge record/replay mechanism
   */
  def ex[T](f: => T, v: String) = {
    MPBridge.a()
    MPBridge.startRecord(v)
    val now = System.currentTimeMillis
    var ret = f
    val r = System.currentTimeMillis - now
    logger.trace(s"Record: [$r ms]")
    val requests = MPBridge.stopRecord()
    MPBridge.b(3)
    if(requests.length > 0) {
        val now2 = System.currentTimeMillis
        val answers = MPService.compute(requests, MPBridge.getModulus);
        val c = System.currentTimeMillis - now2
        MPBridge.startReplay(answers)
        ret = f
        val t = System.currentTimeMillis - now
        logger.trace(s"Compute: [$c ms] R+C: [${r+c} ms] Total: [$t ms]")
        MPBridge.stopReplay()
    }
    MPBridge.reset()

    ret
  }
}