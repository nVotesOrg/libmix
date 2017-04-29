package org.nvotes.libmix

import java.nio.ByteOrder
import java.nio.charset.Charset

import ch.bfh.unicrypt.crypto.keygenerator.interfaces.KeyPairGenerator
import ch.bfh.unicrypt.crypto.proofsystem.challengegenerator.classes.FiatShamirSigmaChallengeGenerator
import ch.bfh.unicrypt.crypto.proofsystem.challengegenerator.interfaces.ChallengeGenerator
import ch.bfh.unicrypt.crypto.proofsystem.challengegenerator.interfaces.SigmaChallengeGenerator
import ch.bfh.unicrypt.crypto.proofsystem.classes.EqualityPreimageProofSystem
import ch.bfh.unicrypt.crypto.proofsystem.classes.PermutationCommitmentProofSystem
import ch.bfh.unicrypt.crypto.proofsystem.classes.PlainPreimageProofSystem
import ch.bfh.unicrypt.crypto.proofsystem.classes.ReEncryptionShuffleProofSystem
import ch.bfh.unicrypt.crypto.schemes.commitment.classes.PermutationCommitmentScheme
import ch.bfh.unicrypt.crypto.schemes.encryption.classes.ElGamalEncryptionScheme
import ch.bfh.unicrypt.helper.converter.classes.ConvertMethod
import ch.bfh.unicrypt.helper.converter.classes.biginteger.ByteArrayToBigInteger
import ch.bfh.unicrypt.helper.converter.classes.bytearray.BigIntegerToByteArray
import ch.bfh.unicrypt.helper.converter.classes.bytearray.StringToByteArray
import ch.bfh.unicrypt.helper.hash.HashAlgorithm
import ch.bfh.unicrypt.helper.hash.HashMethod
import ch.bfh.unicrypt.helper.math.Alphabet
import ch.bfh.unicrypt.math.algebra.concatenative.classes.StringElement
import ch.bfh.unicrypt.math.algebra.concatenative.classes.StringMonoid
import ch.bfh.unicrypt.math.algebra.general.classes.Pair
import ch.bfh.unicrypt.math.algebra.general.classes.Triple
import ch.bfh.unicrypt.math.algebra.general.classes.Tuple
import ch.bfh.unicrypt.math.algebra.general.interfaces.Element
import ch.bfh.unicrypt.math.function.classes.CompositeFunction
import ch.bfh.unicrypt.math.function.classes.GeneratorFunction
import ch.bfh.unicrypt.math.function.classes.InvertFunction
import ch.bfh.unicrypt.math.function.classes.MultiIdentityFunction
import ch.bfh.unicrypt.math.function.classes.ProductFunction
import ch.bfh.unicrypt.math.function.interfaces.Function
import ch.bfh.unicrypt.math.algebra.general.abstracts.AbstractSet

import org.slf4j.Logger
import org.slf4j.LoggerFactory

import mpservice.MPBridgeS

/**
 * Proof settings common for proof generators and verifiers
 *
 * We mix in this trait wherever necessary to ensure consistent use of conversions and hashing
 *
 */
trait ProofSettings {
  val convertMethod = ConvertMethod.getInstance(
        BigIntegerToByteArray.getInstance(ByteOrder.BIG_ENDIAN),
        StringToByteArray.getInstance(Charset.forName("UTF-8")))
  val hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA256
  val hashMethod = HashMethod.getInstance(hashAlgorithm)
  val converter = ByteArrayToBigInteger.getInstance(hashAlgorithm.getByteLength(), 1)
}

/**
 * Verification methods for keyshares, shuffles and partial decryptions
 *
 */
object Verifier extends ProofSettings {

  val logger = LoggerFactory.getLogger(Verifier.getClass)

  /**
   * Verifies a key share.
   *
   * Returns true if the proof is correct, false otherwise.
   */
  def verifyKeyShare(share: EncryptionKeyShareDTO, cSettings: CryptoSettings, proverId: String)
    : Boolean = {

    val elGamal = ElGamalEncryptionScheme.getInstance(cSettings.generator)
    val keyPairGen: KeyPairGenerator = elGamal.getKeyPairGenerator();
    val publicKey = keyPairGen.getPublicKeySpace().getElementFrom(share.keyShare)
    val proofFunction = keyPairGen.getPublicKeyGenerationFunction()

    val otherInput: StringElement = StringMonoid.getInstance(Alphabet.UNICODE_BMP).getElement(proverId)

    val challengeGenerator: SigmaChallengeGenerator = FiatShamirSigmaChallengeGenerator.getInstance(
        cSettings.group.getZModOrder(), otherInput, convertMethod, hashMethod, converter)

    val pg: PlainPreimageProofSystem = PlainPreimageProofSystem.getInstance(challengeGenerator, proofFunction)

    val commitment = pg.getCommitmentSpace().getElementFrom(share.sigmaProofDTO.commitment)
    val challenge = pg.getChallengeSpace().getElementFrom(share.sigmaProofDTO.challenge)
    val response = pg.getResponseSpace().getElementFrom(share.sigmaProofDTO.response)

    val proofTriple: Triple = Triple.getInstance(commitment, challenge, response)

    val result = pg.verify(proofTriple, publicKey)
    logger.info(s"Verifier: verifyKeyShare......$result")

    result
  }

  /**
   * Verifies a set of partial decryptions.
   *
   * Returns true if the proof is correct, false otherwise.
   */
  def verifyPartialDecryption(pd: PartialDecryptionDTO, votes: Seq[Tuple], cSettings: CryptoSettings,
    proverId: String, publicShare: Element[_]): Boolean = {

    val encryptionGenerator = cSettings.generator
    val generatorFunctions = votes.par.map { x: Tuple =>
      GeneratorFunction.getInstance(x.getFirst)
    }.seq

    // Create proof functions
    val f1: Function = GeneratorFunction.getInstance(encryptionGenerator)
    val f2: Function = CompositeFunction.getInstance(
        InvertFunction.getInstance(cSettings.group.getZModOrder()),
        MultiIdentityFunction.getInstance(cSettings.group.getZModOrder(), generatorFunctions.length),
        ProductFunction.getInstance(generatorFunctions :_*))

    val pdElements = pd.partialDecryptions.par.map(cSettings.group.asInstanceOf[AbstractSet[_,_]].getElementFrom(_)).seq

    val publicInput: Pair = Pair.getInstance(publicShare, Tuple.getInstance(pdElements:_*))
    val otherInput = StringMonoid.getInstance(Alphabet.UNICODE_BMP).getElement(proverId)
    val challengeGenerator: SigmaChallengeGenerator = FiatShamirSigmaChallengeGenerator.getInstance(
        cSettings.group.getZModOrder(), otherInput, convertMethod, hashMethod, converter)
    val proofSystem: EqualityPreimageProofSystem = EqualityPreimageProofSystem.getInstance(challengeGenerator, f1, f2)

    val commitment = proofSystem.getCommitmentSpace().getElementFrom(pd.proofDTO.commitment)
    val challenge = proofSystem.getChallengeSpace().getElementFrom(pd.proofDTO.challenge)
    val response = proofSystem.getResponseSpace().getElementFrom(pd.proofDTO.response)

    val proof: Triple = Triple.getInstance(commitment, challenge, response)
    val result = proofSystem.verify(proof, publicInput)

    logger.info(s"Verifier: verifyPartialDecryptions $result")

    result
  }

  /**
   * Verifies a a mix.
   *
   * Returns true if the proof is correct, false otherwise.
   */
  def verifyShuffle(votes: Tuple, shuffledVotes: Tuple, shuffleProof: ShuffleProofDTO,
    proverId: String, publicKey: Element[_], cSettings: CryptoSettings): Boolean = {

    val elGamal = ElGamalEncryptionScheme.getInstance(cSettings.generator)

    val otherInput: StringElement = StringMonoid.getInstance(Alphabet.UNICODE_BMP).getElement(proverId)
    val challengeGenerator: SigmaChallengeGenerator = FiatShamirSigmaChallengeGenerator.getInstance(
        cSettings.group.getZModOrder(), otherInput, convertMethod, hashMethod, converter)

    logger.debug("Getting proof systems..")

    val ecg: ChallengeGenerator = PermutationCommitmentProofSystem.createNonInteractiveEValuesGenerator(
        cSettings.group.getZModOrder(), votes.getArity())

    val pcps: PermutationCommitmentProofSystem = PermutationCommitmentProofSystem.getInstance(challengeGenerator, ecg,
      cSettings.group, votes.getArity())

    val spg: ReEncryptionShuffleProofSystem = ReEncryptionShuffleProofSystem.getInstance(challengeGenerator, ecg, votes.getArity(), elGamal, publicKey)

    val pcs: PermutationCommitmentScheme = PermutationCommitmentScheme.getInstance(cSettings.group, votes.getArity())

    val permutationCommitment = Util.fromString(pcs.getCommitmentSpace(), shuffleProof.permutationCommitment)

    logger.debug("Getting values..")

    val commitment1 = Util.fromString(pcps.getCommitmentSpace(), shuffleProof.permutationProof.commitment)
    val challenge1 = pcps.getChallengeSpace.getElementFrom(shuffleProof.permutationProof.challenge)
    val response1 = pcps.getResponseSpace.asInstanceOf[AbstractSet[_,_]].getElementFrom(shuffleProof.permutationProof.response)

    // FIXME remove trace (conversion bug code)
    // logger.info(s"deserialize commitment ${shuffleProof.mixProof.commitment}")
    // logger.info(s"commitmentspace ${spg.getCommitmentSpace}")

    // FIXME conversion bug code triggered here
    val commitment2 = spg.getCommitmentSpace.asInstanceOf[AbstractSet[_,_]].getElementFrom(shuffleProof.mixProof.commitment)

    val challenge2 = spg.getChallengeSpace.getElementFrom(shuffleProof.mixProof.challenge)
    val response2 = spg.getResponseSpace.asInstanceOf[AbstractSet[_,_]].getElementFrom(shuffleProof.mixProof.response)

    val permutationProofDTO = shuffleProof.permutationProof
    val mixProofDTO = shuffleProof.mixProof

    logger.debug("Converting bridging commitments..")

    // bridging commitments: GStarmod
    val bridgingCommitments = permutationProofDTO.bridgingCommitments.par.map { x =>
      Util.fromString(cSettings.group, x)
    }.seq

    logger.debug("Converting permutation e values..")

    // evalues: ZMod
    val eValues = permutationProofDTO.eValues.par.map { x =>
      cSettings.group.getZModOrder.getElementFrom(x)
    }.seq
    logger.info("Converting shuffle e values..")
    val eValues2 = mixProofDTO.eValues.par.map { x =>
      cSettings.group.getZModOrder.getElementFrom(x)
    }.seq

    logger.debug("Getting proof instances..")
    val permutationProof: Tuple = Tuple.getInstance(Util.tupleFromSeq(eValues), Util.tupleFromSeq(bridgingCommitments),
      commitment1, challenge1, response1)
    val mixProof: Tuple = Tuple.getInstance(Util.tupleFromSeq(eValues2), commitment2, challenge2, response2)

    logger.debug("Getting public inputs..")
    val publicInputShuffle: Tuple = Tuple.getInstance(permutationCommitment, votes, shuffledVotes)
    val publicInputPermutation = permutationCommitment

    logger.debug("Verifying..")
    val v1 = pcps.verify(permutationProof, publicInputPermutation)

    val v2 = spg.verify(mixProof, publicInputShuffle)

    val v3 = publicInputPermutation.isEquivalent(publicInputShuffle.getFirst())

    val result = v1 && v2 && v3
    logger.info(s"Verifier: verifyShuffle: $result")

    result
  }
}