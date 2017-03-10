package org.nvotes.mix.mpservice

import scala.concurrent.duration.DurationInt
import java.math.BigInteger
import scala.collection._
import scala.util.Try
import scala.util.Success
import com.squareup.jnagmp.Gmp

/******************** PUBLIC API ********************/

/**
 * Represents a modular exponentiation operation
 */
case class ModPow(base: BigInteger, pow: BigInteger, mod: BigInteger)

/**
 * Represents a modular exponentiation operation with common modulus (see below)
 */
case class ModPow2(base: BigInteger, pow: BigInteger)

/**
 * Represents a modular exponentiation operation with common modulus and result
 */
case class ModPowResult(base: BigInteger, pow: BigInteger, mod: BigInteger, result: BigInteger)

/**
 * The mpservice public api
 */
trait ModPowService {
  // compute modular exponentiation for a list of inputs
  def compute(work: Array[ModPow]): Array[BigInteger]
  // compute modular exponentiation for a list of inputs with common modulus
  def compute(work: Array[ModPow2], mod: BigInteger): Array[BigInteger]

  def computeDebug(work: Array[ModPow2], mod: BigInteger): Array[ModPowResult]
}

/******************** IMPLEMENTATION ********************/

object MPService extends ModPowService {
  val service = ParallelModPowService

  def compute(work: Array[ModPow]): Array[BigInteger] = service.compute(work)
  def compute(work: Array[ModPow2], mod: BigInteger): Array[BigInteger] = service.compute(work, mod)
  def computeDebug(work: Array[ModPow2], mod: BigInteger): Array[ModPowResult] = service.computeDebug(work, mod)

  def shutdown = service.shutdown
  def init = {}
  override def toString = service.getClass.toString
}

object MPBridgeS {
  // FIXME move to Util
  // val generatorParallelism = ConfigFactory.load().getInt("generators-parallelism-level")

  def ex[T](f: => T, v: String) = {
    MPBridge.a()
    MPBridge.startRecord(v)
    val now = System.currentTimeMillis
    var ret = f
    val r = System.currentTimeMillis - now
    println(s"R: [$r ms]")
    val requests = MPBridge.stopRecord()
    MPBridge.b(3)
    if(requests.length > 0) {
        val now2 = System.currentTimeMillis
        val answers = MPService.compute(requests, MPBridge.getModulus);
        val c = System.currentTimeMillis - now2
        MPBridge.startReplay(answers)
        ret = f
        val t = System.currentTimeMillis - now
        println(s"\nC: [$c ms] T: [$t ms] R+C: [${r+c} ms]")
        MPBridge.stopReplay()
    }
    MPBridge.reset()

    ret
  }

  def init(useGmp: Boolean, useExtractor: Boolean) = MPBridge.init(useGmp, useExtractor)
  def shutdown = MPBridge.shutdown
}

object SequentialModPowService extends ModPowService {
  def compute(work: Array[ModPow]): Array[BigInteger] = work.map(x => x.base.modPow(x.pow, x.mod))
  def compute(work: Array[ModPow2], mod: BigInteger): Array[BigInteger] = work.map(x => x.base.modPow(x.pow, mod))
  def computeDebug(work: Array[ModPow2], mod: BigInteger): Array[ModPowResult] = {
    work.map(x => ModPowResult(x.base, x.pow, mod, x.base.modPow(x.pow, mod))).seq.toArray
  }
}
object GmpParallelModPowService extends ModPowService {
  def compute(work: Array[ModPow]): Array[BigInteger] = {
    work.par.map(x => Gmp.modPowInsecure(x.base, x.pow, x.mod)).seq.toArray
  }
  def compute(work: Array[ModPow2], mod: BigInteger): Array[BigInteger] = {
    work.par.map(x => Gmp.modPowInsecure(x.base, x.pow, mod)).seq.toArray
  }
  def computeDebug(work: Array[ModPow2], mod: BigInteger): Array[ModPowResult] = {
    work.par.map(x => ModPowResult(x.base, x.pow, mod, Gmp.modPowInsecure(x.base, x.pow, mod))).seq.toArray
  }
}
object ParallelModPowService extends ModPowService {
  def compute(work: Array[ModPow]): Array[BigInteger] = work.par.map(x => x.base.modPow(x.pow, x.mod)).seq.toArray
  def compute(work: Array[ModPow2], mod: BigInteger): Array[BigInteger] = work.par.map(x => x.base.modPow(x.pow, mod)).seq.toArray
  def computeDebug(work: Array[ModPow2], mod: BigInteger): Array[ModPowResult] = {
    work.par.map(x => ModPowResult(x.base, x.pow, mod, x.base.modPow(x.pow, mod))).seq.toArray
  }
  def shutdown = {}
}