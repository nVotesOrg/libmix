package org.nvotes.libmix.threshold;

import ch.bfh.unicrypt.crypto.schemes.sharing.classes.*;
import ch.bfh.unicrypt.helper.random.hybrid.HybridRandomByteSequence;
import ch.bfh.unicrypt.math.algebra.general.classes.ProductSet;

import ch.bfh.unicrypt.crypto.schemes.sharing.abstracts.AbstractThresholdSecretSharingScheme;
import ch.bfh.unicrypt.helper.random.RandomByteSequence;
import ch.bfh.unicrypt.math.algebra.dualistic.classes.PolynomialElement;
import ch.bfh.unicrypt.math.algebra.dualistic.classes.PolynomialRing;
import ch.bfh.unicrypt.math.algebra.dualistic.classes.ZModElement;
import ch.bfh.unicrypt.math.algebra.dualistic.classes.ZModPrime;
import ch.bfh.unicrypt.math.algebra.dualistic.interfaces.DualisticElement;
import ch.bfh.unicrypt.math.algebra.general.classes.Pair;
import ch.bfh.unicrypt.math.algebra.general.classes.ProductGroup;
import ch.bfh.unicrypt.math.algebra.general.classes.Tuple;
import ch.bfh.unicrypt.math.algebra.general.interfaces.Element;
import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModSafePrime;
import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModElement;
import java.math.BigInteger;

/**
 *	Feldman secret sharing scheme specialized for ElGamal encryption.
 *
 *  Feldman' scheme is an extension of Shamir's secret sharing where the dealer
 *  calculates commitments that can be verified by the rest of the parties.
 *
 *  Derived from unicrypt's ShamirSecretSharingScheme.
 */
public class FeldmanSecretSharingScheme {

	private static final long serialVersionUID = 1L;

	private final ZModPrime zModPrime;
	private final PolynomialRing polynomialRing;
	private ZModPrime messageSpace;
	protected final int size;
	private final int threshold;
	private final ProductGroup shareSpace;
	private GStarModElement generator;

	/**
 	 *	Constructor takes the ElGamal group and generator, plus sharing parameters.
 	 *
 	 *  The polynomial will be over the ElGamal keyspace field, Zq.
     */
	public FeldmanSecretSharingScheme(GStarModSafePrime gStarModSafePrime, GStarModElement generator,
		int size, int threshold) {

		this.zModPrime = gStarModSafePrime.getZModOrder();
		this.shareSpace = ProductGroup.getInstance(zModPrime, 2);
		this.polynomialRing = PolynomialRing.getInstance(zModPrime);
		this.size = size;
		this.threshold = threshold;
		this.generator = generator;
	}

	/**
 	 *	The underlying polynomial.
     */
	public PolynomialRing getPolynomialRing() {
		return polynomialRing;
	}

	/**
 	 *	The message space is Zq for ElGamal secret keys.
     */
	public final ZModPrime getMessageSpace() {
		return zModPrime;
	}

	/**
 	 *	The number of shares required to reconstruct the secret.
     */
	public int getThreshold() {
		return threshold;
	}

	/**
 	 *	The total number of shares to produce.
     */
	public final int getSize() {
		return size;
	}

	/**
 	 *	Compute shares (and commitments), uses the default random source
     */
	public final SharesAndCommitments share(ZModElement message) {
		return share(message, HybridRandomByteSequence.getInstance());
	}

	/**
 	 *	Compute shares (and commitments), passing in a random source.
     */
	public final SharesAndCommitments share(ZModElement message, RandomByteSequence randomByteSequence) {
		if (message == null || !this.getMessageSpace().contains(message) || randomByteSequence == null) {
			throw new IllegalArgumentException();
		}
		return share_(message, randomByteSequence);
	}

	/**
 	 *	Reconstruct the secret from a threshold number of shares.
     */
	public final ZModElement recover(ZModElement[] xs, ZModElement[] ys) {
		if (xs == null || ys == null || xs.length < threshold ||
			xs.length > this.getSize() || xs.length != ys.length) {

			throw new IllegalArgumentException();
		}
		for(int i = 0; i < xs.length; i++) {
			if(!zModPrime.contains(xs[i]) || !zModPrime.contains(ys[i]) ) {
				throw new IllegalArgumentException();
			}
		}

		return recover_(xs, ys);
	}

	/**
 	 *	Compute the lagrange coefficients necessary to reconstruct the secret.
     */
	public ZModElement[] lagrangeCoefficients(ZModElement[] in) {
		int length = in.length;

		ZModElement product;
		ZModElement[] lagrangeCoefficients = new ZModElement[length];
		for (int j = 0; j < length; j++) {
			product = null;
			ZModElement elementJ = in[j];
			for (int l = 0; l < length; l++) {
				ZModElement elementL = in[l];
				if (!elementJ.equals(elementL)) {
					if (product == null) {
						product = elementL.divide(elementL.subtract(elementJ));
					} else {
						product = product.multiply(elementL.divide(elementL.subtract(elementJ)));
					}
				}
			}
			lagrangeCoefficients[j] = product;
		}

		return lagrangeCoefficients;
	}

	/**
 	 *	Core method to compute shares
 	 *
 	 *	A random polynomial is generated and the required number of
 	 *  points are calculated as shares, along with Feldman commitments.
 	 *
 	 *  The distributed shares are f(1)....f(size), f(0) is the secret.
 	 *  The commitments are c(0)....c(threshold), where c(n) = g^coefficient(n).
 	 *	coefficient(n) is the nth coefficient of the polynomial, c(0) is the secret.
     */
	private SharesAndCommitments share_(ZModElement message, RandomByteSequence randomByteSequence) {
		// create an array of coefficients with size threshold
		// the coefficient of degree 0 is fixed (message)
		// all other coefficients are random
		ZModElement[] coefficients = new ZModElement[threshold];
		coefficients[0] = message;
		for (int i = 1; i < threshold; i++) {
			coefficients[i] = this.zModPrime.getRandomElement(randomByteSequence);
		}

		// create a polynomial out of the coefficients
		final PolynomialElement polynomial = this.polynomialRing.getElement(coefficients);

		ZModElement[] xs = new ZModElement[this.getSize()];
		ZModElement[] ys = new ZModElement[this.getSize()];
		ZModElement xVal;

		for (int i = 0; i < size; i++) {
			xs[i] = this.zModPrime.getElement(BigInteger.valueOf(i + 1));
			ys[i] = (ZModElement) polynomial.getPoint(xs[i]).getSecond();
		}

		// commitments
		GStarModElement[] commitments = new GStarModElement[threshold];
		for (int i = 0; i < threshold; i++) {
			commitments[i] = generator.selfApply(coefficients[i]);
		}

		// verify shares
		// https://wikimedia.org/api/rest_v1/media/math/render/svg/1d2a6fb3eb256ad402648f93e6b06646bf6c8195
		for (int i = 0; i < size; i++) {
			GStarModElement lhs = generator.selfApply(ys[i]);

			GStarModElement rhs = null;
			for (int j = 0; j < threshold; j++) {
				// share at index 0 is share for party 1, and so forth
				Double exponent = Math.pow(i + 1, j);
				GStarModElement tmp = commitments[j].selfApply(exponent.intValue());
				if(rhs == null) {
					rhs = tmp;
				}
				else {
					rhs = rhs.apply(tmp);
				}
			}
			assert(lhs == rhs);
		}

		return new SharesAndCommitments(xs, ys, commitments);
	}

	/**
 	 *	Core method to reconstruct secret
 	 *
 	 *	First, the lagrange coefficients are calculated, then they are multiplied
 	 *  by the corresponding y-point of the shares, and finally summed.
 	 *
 	 *  https://wikimedia.org/api/rest_v1/media/math/render/svg/585a96ff9200e5619498e4cbf366a55aea37f360
     */
	private ZModElement recover_(ZModElement[] xs, ZModElement[] ys) {
		int length = xs.length;

		ZModElement[] lagrangeCoefficients = lagrangeCoefficients(xs);

		// multiply the y-value of the point with the lagrange coefficient and sum everything up
		ZModElement result = this.zModPrime.getIdentityElement();
		for (int j = 0; j < length; j++) {
			result = result.add(ys[j].multiply(lagrangeCoefficients[j]));
		}
		return result;
	}

	/**
	 *	Factory method
	 */
	public static FeldmanSecretSharingScheme getInstance(GStarModSafePrime gStarModSafePrime, GStarModElement generator,
		int size, int threshold) {

		ZModPrime zModPrime = gStarModSafePrime.getZModOrder();

		if (zModPrime == null || size < 1 || threshold < 1 || threshold > size
			   || BigInteger.valueOf(size).compareTo(zModPrime.getOrder()) >= 0) {
			throw new IllegalArgumentException();
		}
		return new FeldmanSecretSharingScheme(gStarModSafePrime, generator, size, threshold);
	}
}