package org.nvotes.mix.benchmark

import ch.bfh.unicrypt.crypto.schemes.encryption.classes.ElGamalEncryptionScheme
import ch.bfh.unicrypt.crypto.encoder.classes.ZModPrimeToGStarModSafePrime
import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModSafePrime
import ch.bfh.unicrypt.math.algebra.general.classes.Pair
import ch.bfh.unicrypt.math.algebra.general.classes.Tuple
import org.nvotes.mix._

/** Simulates a two authority election for benchmarking purposes
 *
 *  The sequence is
 *
 *  Share generation, share pok verification, public key generation, vote casting
 *  mixing, mix verification, decryption, decryption verification
 *
 */
object Benchmark extends App {

  val totalVotes = 10
  val proverId1 = "auth1"
  val proverId2 = "auth2"
  val group = GStarModSafePrime.getFirstInstance(2048)
  val generator = group.getDefaultGenerator()
  val cSettings = CryptoSettings(group, generator)

  // create shares
  val (share1, private1) = KeyMakerTrustee.createShare(proverId1, cSettings)
  val (share2, private2) = KeyMakerTrustee.createShare(proverId2, cSettings)
  val allShares = List(share1, share2)

  // verify shares
  val ok1 = Verifier.verifyKeyShare(share1, cSettings, proverId1)
  val ok2 = Verifier.verifyKeyShare(share2, cSettings, proverId2)
  if(!(ok1 && ok2)) {
    throw new Exception("failed to verify shares $ok1 $ok2")
  }

  // create public key
  val shares = allShares.map { share =>
    Util.getPublicKeyFromString(share.keyShare, cSettings.generator)
  }
  // the public key is the multiplcation of each share (or the addition of each exponent)
  val publicKey = shares.reduce( (a,b) => a.apply(b) )
  val publicKeyString = publicKey.convertToString

  // create votes
  val plaintexts = Seq.fill(totalVotes)(scala.util.Random.nextInt(1000))

  // encrypt the votes with the public key of the election
  val votes = Util.encryptVotes(plaintexts, cSettings, publicKey).map(_.convertToString)

  // shuffle
  val mixOne = MixerTrustee.shuffleVotes(votes, publicKeyString, proverId1, cSettings)
  val mixTwo = MixerTrustee.shuffleVotes(mixOne.votes, publicKeyString, proverId2, cSettings)

  // verify shuffle
  val elGamal = ElGamalEncryptionScheme.getInstance(cSettings.generator)
  val votes0 = votes.map(Util.fromString(elGamal.getEncryptionSpace, _))
  val votes1 = mixOne.votes.map(Util.fromString(elGamal.getEncryptionSpace, _))
  val votes2 = mixTwo.votes.map(Util.fromString(elGamal.getEncryptionSpace, _).asInstanceOf[Pair])

  val oks1 = Verifier.verifyShuffle(Util.tupleFromSeq(votes0), Util.tupleFromSeq(votes1), mixOne.shuffleProof,
    proverId1, publicKey, cSettings)
  val oks2 = Verifier.verifyShuffle(Util.tupleFromSeq(votes1), Util.tupleFromSeq(votes2), mixTwo.shuffleProof,
    proverId2, publicKey, cSettings)
  if(!(oks1 && oks2)) {
    throw new Exception("failed to verify shuffles $oks1 $oks2")
  }

  val decryption1 = KeyMakerTrustee.partialDecryption(proverId1, mixTwo.votes, private1, cSettings)
  val decryption2 = KeyMakerTrustee.partialDecryption(proverId2, mixTwo.votes, private2, cSettings)
  val decryptions = List(decryption1, decryption2)

  // verify decryptions
  val okd1 = Verifier.verifyPartialDecryption(decryption1, votes2, cSettings, proverId1, shares(0))
  val okd2 = Verifier.verifyPartialDecryption(decryption2, votes2, cSettings, proverId2, shares(1))
  if(!(okd1 && okd2)) {
    throw new Exception(s"failed to verify decryptions $okd1 $okd2")
  }

  // combine decryptions
  val decrypted = combineDecryptions(decryptions, mixTwo.votes, cSettings)

  // println(plaintexts.sorted)
  // println(decrypted.map(_.toInt).sorted)
  println("Plaintexts match: " + (decrypted.map(_.toInt).sorted == plaintexts.sorted))

  /** Helper to combine decryptions and yield plaintexts.
   *
   *  Combines the decryptions, applies them to the ciphertexts and
   *  finally decodes.
   */
  def combineDecryptions(decryptions: Seq[PartialDecryptionDTO], mixedVotes: Seq[String],
    cSettings: CryptoSettings) = {

    val decryptionElements = decryptions.map(
      ds => ds.partialDecryptions.par.map(Util.fromString(cSettings.group, _)).seq
    )

    val combined = decryptionElements.reduce { (a, b) =>
      (a zip b).par.map(c => c._1.apply(c._2)).seq
    }

    val elGamal = ElGamalEncryptionScheme.getInstance(cSettings.generator)

    val votes = mixedVotes.par.map( v => Util.fromString(elGamal.getEncryptionSpace, v).asInstanceOf[Pair] ).seq
    // a^-x * b = m
    val decrypted = (votes zip combined).par.map(c => c._1.getSecond().apply(c._2)).seq
    val encoder = ZModPrimeToGStarModSafePrime.getInstance(cSettings.group)

    val plaintexts = decrypted.par.map(encoder.decode(_).convertToString).seq
    plaintexts
  }
}

/** Represents a key maker trustee
 *
 *  Methods to create shares and partially decrypt votes.
 *  Mixes in the nMix KeyMaker trait.
 */
object KeyMakerTrustee extends KeyMaker {

  /** Creates a key share
   *
   *  Returns the key share and proof of knowledge as an nMix EncryptionKeyShareDTO.
   *  Returns the private key part of the share as a unicrypted converted String
   */
  def createKeyShare(id: String, cSettings: CryptoSettings): (EncryptionKeyShareDTO, String) = {

    val (encryptionKeyShareDTO, privateKey) = createShare(id, cSettings)

    (encryptionKeyShareDTO, privateKey)
  }

  /** Partially decrypt a ciphertext with the private part of a share
   *
   *  Returns the partial decryption and proof of knowledge as an nMix EncryptionKeyShareDTO.
   */
  def partialDecryption(id: String, votes: Seq[String],
    privateShare: String, cSettings: CryptoSettings): PartialDecryptionDTO = {

    val elGamal = ElGamalEncryptionScheme.getInstance(cSettings.generator)
    val v = votes.par.map( v => Util.fromString(elGamal.getEncryptionSpace, v).asInstanceOf[Pair]).seq
    val secretKey = cSettings.group.getZModOrder().getElementFrom(privateShare)

    partialDecrypt(v, secretKey, id, cSettings)
  }
}


/** Represents a shuffling trustee
 *
 *  Methods to mix votes.
 *  Mixes in the nMix Mixer trait.
 */
object MixerTrustee extends Mixer {

  /** Shuffle the provided votes
   *
   *  Returns the shuffle and proof of knowledgeas an nMix ShuffleResultDTO
   */
  def shuffleVotes(votes: Seq[String], publicKey: String, id: String, cSettings: CryptoSettings): ShuffleResultDTO = {
    println("Mixer shuffle..")

    // not using Util.getPublicKeyFromString since we need the scheme below
    val elGamal = ElGamalEncryptionScheme.getInstance(cSettings.generator)
    val keyPairGen = elGamal.getKeyPairGenerator()
    val pk = keyPairGen.getPublicKeySpace().getElementFrom(publicKey)

    println("Convert votes..")

    val vs = votes.par.map( v => Util.fromString(elGamal.getEncryptionSpace, v) ).seq

    println("Mixer creating shuffle..")

    shuffle(Util.tupleFromSeq(vs), pk, cSettings, id)
  }

  // TODO add support for offline phase

  /* def preShuffleVotes(e: Election[_, VotesStopped]) = {
    val elGamal = ElGamalEncryptionScheme.getInstance(e.state.cSettings.generator)
    val keyPairGen = elGamal.getKeyPairGenerator()
    val publicKey = keyPairGen.getPublicKeySpace().getElementFrom(e.state.publicKey)

    preShuffle(e.state.votes.size, publicKey, e.state.cSettings, id)
  } */

  /* def shuffleVotes(e: Election[_, Mixing[_]], preData: PreShuffleData, pdtoFuture: Future[PermutationProofDTO]) = {
    println("Mixer..")
    val elGamal = ElGamalEncryptionScheme.getInstance(e.state.cSettings.generator)
    val keyPairGen = elGamal.getKeyPairGenerator()
    val publicKey = keyPairGen.getPublicKeySpace().getElementFrom(e.state.publicKey)
    println("Convert votes..")

    val votes = e.state match {
      case s: Mixing[_0] => e.state.votes.par.map( v => Util.fromString(elGamal.getEncryptionSpace, v) ).seq
      case _ => e.state.mixes.toList.last.votes.par.map( v => Util.fromString(elGamal.getEncryptionSpace, v) ).seq
    }

    println("Mixer creating shuffle..")

    shuffle(Util.tupleFromSeq(votes), publicKey, e.state.cSettings, id, preData, pdtoFuture)
  }*/
}
