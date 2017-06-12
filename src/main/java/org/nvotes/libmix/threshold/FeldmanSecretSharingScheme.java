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
 *	Feldman secret sharing scheme
 *
 *  Derived from ShamirSecretSharingScheme
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

	public FeldmanSecretSharingScheme(GStarModSafePrime gStarModSafePrime, GStarModElement generator,
		int size, int threshold) {

		this.zModPrime = gStarModSafePrime.getZModOrder();
		this.shareSpace = ProductGroup.getInstance(zModPrime, 2);
		this.polynomialRing = PolynomialRing.getInstance(zModPrime);
		this.size = size;
		this.threshold = threshold;
		this.generator = generator;
	}

	public ZModPrime getZModPrime() {
		return this.zModPrime;
	}

	public PolynomialRing getPolynomialRing() {
		return this.polynomialRing;
	}

	public final ZModPrime getMessageSpace() {
		return this.zModPrime;
	}

	public final ProductGroup getShareSpace() {
		return this.shareSpace;
	}

	public int getThreshold() {
		return this.threshold;
	}

	public final int getSize() {
		return this.size;
	}

	public final SharesAndCommitments share(ZModElement message) {
		return this.share(message, HybridRandomByteSequence.getInstance());
	}

	public final SharesAndCommitments share(ZModElement message, RandomByteSequence randomByteSequence) {
		if (message == null || !this.getMessageSpace().contains(message) || randomByteSequence == null) {
			throw new IllegalArgumentException();
		}
		return this.abstractShare(message, randomByteSequence);
	}

	public final ZModElement recover(ZModElement[] xs, ZModElement[] ys) {
		if (xs == null || ys == null || xs.length < this.getThreshold() ||
			xs.length > this.getSize() || xs.length != ys.length) {

			throw new IllegalArgumentException();
		}
		for(int i = 0; i < xs.length; i++) {
			if(!zModPrime.contains(xs[i]) || !zModPrime.contains(ys[i]) ) {
				throw new IllegalArgumentException();
			}
		}

		return abstractRecover(xs, ys);
	}

	public SharesAndCommitments abstractShare(ZModElement message, RandomByteSequence randomByteSequence) {
		// create an array of coefficients with size threshold
		// the coefficient of degree 0 is fixed (message)
		// all other coefficients are random
		ZModElement[] coefficients = new ZModElement[getThreshold()];
		coefficients[0] = message;
		for (int i = 1; i < getThreshold(); i++) {
			coefficients[i] = this.zModPrime.getRandomElement(randomByteSequence);
		}

		// create a polynomial out of the coefficients
		final PolynomialElement polynomial = this.polynomialRing.getElement(coefficients);

		// create a tuple which stores the shares
		ZModElement[] xs = new ZModElement[this.getSize()];
		ZModElement[] ys = new ZModElement[this.getSize()];
		ZModElement xVal;

		// populate the tuple array with tuples of x and y values
		for (int i = 0; i < this.getSize(); i++) {
			xs[i] = this.zModPrime.getElement(BigInteger.valueOf(i + 1));
			ys[i] = (ZModElement) polynomial.getPoint(xs[i]).getSecond();
		}

		// commitments
		GStarModElement[] commitments = new GStarModElement[this.getThreshold()];
		for (int i = 0; i < getThreshold(); i++) {
			commitments[i] = generator.selfApply(coefficients[i]);
		}

		// verify shares
		for (int i = 0; i < this.getSize(); i++) {
			GStarModElement lhs = generator.selfApply(ys[i]);

			GStarModElement rhs = null;
			for (int j = 0; j < getThreshold(); j++) {
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


	public ZModElement[] lagrangeCoefficients(ZModElement[] in) {
		int length = in.length;
		// Calculating the lagrange coefficients for each point we got
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


	public ZModElement abstractRecover(ZModElement[] xs, ZModElement[] ys) {
		int length = xs.length;
		ZModElement[] lagrangeCoefficients = lagrangeCoefficients(xs);

		// multiply the y-value of the point with the lagrange coefficient and sum everything up
		ZModElement result = this.zModPrime.getIdentityElement();
		for (int j = 0; j < length; j++) {
			result = result.add(ys[j].multiply(lagrangeCoefficients[j]));
		}
		return result;
	}

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