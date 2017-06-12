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

	public final SharesAndCommitments share(Element message) {
		return this.share(message, HybridRandomByteSequence.getInstance());
	}

	public final SharesAndCommitments share(Element message, RandomByteSequence randomByteSequence) {
		if (message == null || !this.getMessageSpace().contains(message) || randomByteSequence == null) {
			throw new IllegalArgumentException();
		}
		return this.abstractShare(message, randomByteSequence);
	}

	public final ZModElement recover(Element... shares) {
		return this.recover(Tuple.getInstance(shares));
	}

	public final ZModElement recover(Tuple shares) {
		if (shares == null || shares.getArity() < this.getThreshold() || shares.getArity() > this.getSize()
			   || !ProductSet.getInstance(this.getShareSpace(), shares.getArity()).contains(shares)) {
			throw new IllegalArgumentException();
		}
		return abstractRecover(shares);
	}


	public SharesAndCommitments abstractShare(Element message, RandomByteSequence randomByteSequence) {
		// create an array of coefficients with size threshold
		// the coefficient of degree 0 is fixed (message)
		// all other coefficients are random
		DualisticElement[] coefficients = new DualisticElement[getThreshold()];
		coefficients[0] = (DualisticElement) message;
		for (int i = 1; i < getThreshold(); i++) {
			coefficients[i] = this.zModPrime.getRandomElement(randomByteSequence);
		}

		// create a polynomial out of the coefficients
		final PolynomialElement polynomial = this.polynomialRing.getElement(coefficients);

		// create a tuple which stores the shares
		Pair[] shares = new Pair[this.getSize()];
		DualisticElement xVal;

		// populate the tuple array with tuples of x and y values
		for (int i = 0; i < this.getSize(); i++) {
			xVal = this.zModPrime.getElement(BigInteger.valueOf(i + 1));
			shares[i] = polynomial.getPoint(xVal);
		}

		// commitments
		GStarModElement[] commitments = new GStarModElement[this.getThreshold()];
		for (int i = 0; i < getThreshold(); i++) {
			commitments[i] = generator.selfApply(coefficients[i]);
		}

		// verify shares
		for (int i = 0; i < this.getSize(); i++) {
			GStarModElement lhs = generator.selfApply(shares[i].getSecond());

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

		return new SharesAndCommitments(Tuple.getInstance(shares), commitments);
	}


	public ZModElement[] lg(ZModElement[] in) {
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


	public ZModElement abstractRecover(Tuple shares) {
		int length = shares.getArity();
		// Calculating the lagrange coefficients for each point we got
		DualisticElement product;
		DualisticElement[] lagrangeCoefficients = new DualisticElement[length];
		for (int j = 0; j < length; j++) {
			product = null;
			DualisticElement elementJ = (DualisticElement) shares.getAt(j, 0);
			for (int l = 0; l < length; l++) {
				DualisticElement elementL = (DualisticElement) shares.getAt(l, 0);
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
		// multiply the y-value of the point with the lagrange coefficient and sum everything up
		ZModElement result = this.zModPrime.getIdentityElement();
		for (int j = 0; j < length; j++) {
			DualisticElement value = (DualisticElement) shares.getAt(j, 1);
			result = result.add(value.multiply(lagrangeCoefficients[j]));
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