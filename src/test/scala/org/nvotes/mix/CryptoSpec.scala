package org.nvotes.libmix

import ch.bfh.unicrypt.crypto.keygenerator.interfaces.KeyPairGenerator
import ch.bfh.unicrypt.crypto.schemes.encryption.classes.ElGamalEncryptionScheme
import ch.bfh.unicrypt.math.algebra.general.interfaces.Element
import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModSafePrime
import ch.bfh.unicrypt.crypto.encoder.classes.ZModPrimeToGStarModSafePrime
import org.nvotes.libmix.threshold.FeldmanSecretSharingScheme
import ch.bfh.unicrypt.crypto.schemes.sharing.interfaces.SecretSharingScheme
import ch.bfh.unicrypt.math.algebra.dualistic.classes.ZModPrime
import ch.bfh.unicrypt.math.algebra.general.classes.Tuple
import ch.bfh.unicrypt.math.algebra.general.interfaces.Element
import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModElement
import ch.bfh.unicrypt.math.algebra.dualistic.classes.ZModElement
import ch.bfh.unicrypt.math.algebra.general.classes.Pair
import java.math.BigInteger

import org.scalatest.FlatSpec

class CryptoSpec extends FlatSpec {

  val grp = GStarModSafePrime.getFirstInstance(2048)

  val gen = grp.getDefaultGenerator()
  val Csettings = CryptoSettings(grp, gen)

  val shares = scala.collection.mutable.ArrayBuffer.empty[GStarModElement]
  val privates = scala.collection.mutable.ArrayBuffer.empty[ZModElement]

  object KM extends KeyMaker
  object MX extends Mixer

  "The shuffle process" should "verify ok and decrypt correctly" in {
    val elGamal = ElGamalEncryptionScheme.getInstance(Csettings.generator)
    val keyPair = elGamal.getKeyPairGenerator().generateKeyPair()
    val privateKey = keyPair.getFirst()
    val publicKey = keyPair.getSecond().asInstanceOf[GStarModElement]

    val plaintexts = Seq.fill(10)(scala.util.Random.nextInt(10))
    val votes = Util.encryptVotes(plaintexts, Csettings, publicKey)

    val shuffleResult = MX.shuffle(Util.tupleFromSeq(votes), publicKey, Csettings, "proverId")
    val shuffled = shuffleResult.votes.map( v => Util.fromString(elGamal.getEncryptionSpace, v) )

    val verified = Verifier.verifyShuffle(Util.tupleFromSeq(votes), Util.tupleFromSeq(shuffled),
      shuffleResult.shuffleProof, "proverId", publicKey, Csettings)

    assert(verified)

    val encoder = ZModPrimeToGStarModSafePrime.getInstance(Csettings.group)
    val decrypted = shuffled.map { v =>
      encoder.decode(elGamal.decrypt(privateKey, v)).convertToString
    }

    assert(plaintexts.sorted == decrypted.map(_.toInt).sorted)
  }

  "The dkg process" should "verify shares, verify decryptions, decrypt correctly" in {
    val (share, key) = KM.createShare("1", Csettings)
    var ok = addShare(share, "1", Csettings, key.convertToString)
    assert(ok)

    val (share2, key2) = KM.createShare("2", Csettings)
    ok = addShare(share2, "2", Csettings, key2.convertToString)
    assert(ok)

    val publicKey = combineShares(shares, Csettings)

    val plaintexts = Seq.fill(10)(scala.util.Random.nextInt(10))
    val ciphertexts = Util.encryptVotes(plaintexts, Csettings, publicKey)

    // a^-x1
    val elementsOne = KM.partialDecrypt(ciphertexts, privates(0), "0", Csettings)
    ok = Verifier.verifyPartialDecryption(elementsOne, ciphertexts, Csettings, "0", shares(0))
    assert(ok)
    // a^-x2
    val elementsTwo = KM.partialDecrypt(ciphertexts, privates(1), "1", Csettings)
    ok = Verifier.verifyPartialDecryption(elementsTwo, ciphertexts, Csettings, "1", shares(1))
    assert(ok)

    // a^-x = a^-x1 * a^-x2 ...
    val combined = (elementsOne.partialDecryptions.map(Csettings.group.getElementFrom(_))
      zip elementsTwo.partialDecryptions.map(Csettings.group.getElementFrom(_))).map(c => c._1.apply(c._2))
    // println(s"a^-x ****\n$combined")
    // a^-x * b = m
    val decrypted = (ciphertexts zip combined).map(c => c._1.getSecond().apply(c._2))
    val encoder = ZModPrimeToGStarModSafePrime.getInstance(Csettings.group)
    val decoded = decrypted.map(encoder.decode(_).convertToString)

    assert(plaintexts.sorted == decoded.map(_.toInt).sorted)
  }

  "feldman vss" should "distribute and recover ok" in {
    val g59 = GStarModSafePrime.getInstance(59);
    val f = FeldmanSecretSharingScheme.getInstance(g59, g59.getDefaultGenerator(), 5, 3);

    // Create message m=25
    val message = f.getMessageSpace().getElementFrom(5);

    // Compute shares
    val sharesAndCommitments = f.share(message)
    val shareXs = sharesAndCommitments.xs
    val shareYs = sharesAndCommitments.ys

    // Select subset of shares
    val someSharesX = shareXs.drop(2)
    val someSharesY = shareYs.drop(2)

    // Recover message
    val recoveredMessage1 = f.recover(someSharesX, someSharesY)

    // Recover message differently
    val recoveredMessage2 = f.recover(shareXs, shareYs)

    assert(recoveredMessage1 == message)
    assert(recoveredMessage2 == message)

    val notEnoughX = shareXs.drop(3)
    val notEnoughY = shareYs.drop(3)

    assertThrows[IllegalArgumentException]{
      f.recover(notEnoughY, notEnoughY)
    }
  }

  "pedersen vss" should "encrypt and decrypt ok" in {

    // see section 6.8 threshold elgamal in user anonymization pdf

    val group = GStarModSafePrime.getFirstInstance(10)
    val generator = group.getDefaultGenerator()
    val trustees = 5
    val threshold = 3

    // Create ElGamal encryption scheme
    val elGamal = ElGamalEncryptionScheme.getInstance(generator)

    val f = FeldmanSecretSharingScheme.getInstance(group, generator, trustees, threshold)

    // Compute shares
    val allShares = Array.fill(trustees)(f.share(f.getMessageSpace().getRandomElement()))
    // compute the public key
    val publicKey: GStarModElement = allShares.map(_.commitments(0)).reduce((x,y) => x.apply(y))

    val message = elGamal.getMessageSpace().getRandomElement()
    println("message " + message)

    val encryption = elGamal.encrypt(publicKey, message)

    val subset = (0 to trustees - 1).filter(_ != 1).filter(_ != 4)
    println(subset)

    // get the trustee positions together with the trustee secrets
    val s = subset.map{ t =>
      // the trustee secrets are the sum of all shares received from other trustees
      val points = allShares.filter(_ != t).map{ sc =>
        val x = sc.xs(t)
        val y = sc.ys(t)
        (x,y)
      }
      // the trustee secrets are the sum of all shares received from other trustees
      points.reduce( (x,y) => (x._1, x._2.apply(y._2)))
    }

    // get the positions in order to compute lagrange coefficients
    val xs = s.map(_._1)
    // get the secrets
    val secrets = s.map(_._2)

    // calculate partial decryptions
    val partials = secrets.map(encryption.getFirst().selfApply(_))

    // calculate lagrange coefficients
    val lagrange = f.lagrangeCoefficients(xs.toArray)

    val zipped = partials zip lagrange

    // raise the partials to the power of the lagrange coefficients
    val exp = zipped.map(x => x._1.selfApply(x._2))
    // multiply the results
    val mult = exp.reduce( (x,y) => x.apply(y))
    // invert in order to decrypt
    val inverted = mult.invert()
    // decrypt
    val plaintext = inverted.apply(encryption.getSecond())

    println("plaintext " + plaintext)
    assert(message == plaintext)
  }

  def combineShares(shares: Seq[GStarModElement], Csettings: CryptoSettings) = {
    var encKey = Csettings.group.getIdentityElement()

    // y = y1 * y2 * y3....
    for (keyShare <- shares) {
      encKey = encKey.apply(keyShare)
    }

    encKey
  }

  def addShare(encryptionKeyShare: EncryptionKeyShareDTO, proverId: String, cSettings: CryptoSettings, privateK: String) = {
    val result = Verifier.verifyKeyShare(encryptionKeyShare, cSettings, proverId: String)
    if(result) {
      val elGamal = ElGamalEncryptionScheme.getInstance(cSettings.generator)
      val keyPairGen: KeyPairGenerator = elGamal.getKeyPairGenerator()
      val publicKey = cSettings.group.getElementFrom(encryptionKeyShare.keyShare)
      shares += publicKey
      val privateKey = keyPairGen.getPrivateKeySpace().getElementFrom(privateK).asInstanceOf[ZModElement]

      privates += privateKey
    }

    result
  }
}