package org.nvotes.libmix.threshold;

import ch.bfh.unicrypt.math.algebra.general.classes.Tuple;
import ch.bfh.unicrypt.math.algebra.dualistic.classes.ZModElement;
import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModElement;

public class SharesAndCommitments {
	public ZModElement[] xs;
	public ZModElement[] ys;
	public GStarModElement[] commitments;

	public SharesAndCommitments(ZModElement[] xs, ZModElement[] ys, GStarModElement[] commitments) {
		this.xs = xs;
		this.ys = ys;
		this.commitments = commitments;
	}
}