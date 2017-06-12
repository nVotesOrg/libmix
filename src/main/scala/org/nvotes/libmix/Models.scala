package org.nvotes.libmix

import ch.bfh.unicrypt.math.algebra.general.interfaces.Element
import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModSafePrime
import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModElement
import ch.bfh.unicrypt.math.algebra.general.classes.PermutationElement
import ch.bfh.unicrypt.math.algebra.general.classes.Tuple

/**
 * The group and generator for an election
 */
case class CryptoSettings(group: GStarModSafePrime, generator: GStarModElement)

/**
 *  Private permutation data
 *
 *	Used to separate the offline and online phases of the shuffle
 */
case class PermutationData(permutation: PermutationElement, randomizations: Tuple)

/**
 * Serialization (Data Transfer Object) classes
 *
 * Allows persisting and transporting data over the network. In the current implementation
 * serializations take the form of strings, using unicrypts built-in conversions.
 * Another more efficient possibility is binary data.
 */

/** Generic sigma proof, used for both key shares and partial decryption proofs */
case class SigmaProofDTO(commitment: String, challenge: String, response: String)

/** A key share, composed of the proof and public share */
case class EncryptionKeyShareDTO(sigmaProofDTO: SigmaProofDTO, keyShare: String)

/** A partial decryption of ciphertexts, and corresponding proof
	The partial decryption is obtained applying the private part of the share*/
case class PartialDecryptionDTO(partialDecryptions: Seq[String], proofDTO: SigmaProofDTO)

/** A mix of ciphertexts, with all associated proofs */
case class ShuffleResultDTO(shuffleProof: ShuffleProofDTO, votes: Seq[String])

/** Combination of offline and online parts of the proof */
case class ShuffleProofDTO(mixProof: MixProofDTO, permutationProof: PermutationProofDTO, permutationCommitment: String)

/** Proof for the offline part of the mix, permutation */
case class PermutationProofDTO(commitment: String, challenge: String, response: String,
  bridgingCommitments: Seq[String], eValues: Seq[String])

/** Proof for the online part of the mix */
case class MixProofDTO(commitment: String, challenge: String, response: String, eValues: Seq[String])

/** Data for the offline phase of the mix: private permutation data + proof */
case class PermutationDTO(permutation: String, randomizations: String, proof: PermutationProofDTO)