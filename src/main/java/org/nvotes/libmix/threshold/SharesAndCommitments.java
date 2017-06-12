package org.nvotes.libmix.threshold;

import ch.bfh.unicrypt.math.algebra.general.classes.Tuple;
import ch.bfh.unicrypt.math.algebra.dualistic.classes.ZModElement;
import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModElement;

public class SharesAndCommitments {
	public Tuple shares;
	public GStarModElement[] commitments;

	public SharesAndCommitments(Tuple shares, GStarModElement[] commitments) {
		this.shares = shares;
		this.commitments = commitments;
	}
}