/*
 * Copyright 2013 Google Inc.
 * Copyright 2015 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.params;

import static com.google.common.base.Preconditions.checkState;

import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

import org.bitcoinj.core.Block;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.Utils;
import org.bitcoinj.utils.MonetaryFormat;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Stopwatch;

import org.bitcoinj.core.BitcoinSerializer;
import org.spongycastle.util.Store;

/**
 * Parameters for Bitcoin-like networks.
 */
public abstract class AbstractBitcoinNetParams extends NetworkParameters {
    private static final Logger log = LoggerFactory.getLogger(AbstractBitcoinNetParams.class);
    public static final String BITCOIN_SCHEME = "bitcoin";

    public AbstractBitcoinNetParams() {
        super();
    }

    private StoredBlock findPrevStoredPoSBlock(final StoredBlock storedPrev, final BlockStore blockStore)
            throws VerificationException, BlockStoreException {

        StoredBlock resultStoredBlock = storedPrev;

        while (!resultStoredBlock.getHeader().isProofOfStake()) {
            StoredBlock cursor = resultStoredBlock.getPrev(blockStore);
            if (null == cursor || cursor.getHeight() <= BCAHeight) return null;
            else resultStoredBlock = cursor;
        }

        return resultStoredBlock;
    }

    private long getNextWorkRequiredForPoS(final StoredBlock storedPrev, final BlockStore blockStore)
            throws VerificationException, BlockStoreException {

        checkState(storedPrev.getHeight() + 1 > BCAHeight + BCAInitLim, "PoS block height is incorrect");

        StoredBlock prevPoSBlock = findPrevStoredPoSBlock(storedPrev, blockStore);
        if (null == prevPoSBlock) return Utils.encodeCompactBits(initialHashTargetPoS);

        StoredBlock prevPrevPoSBlock = findPrevStoredPoSBlock(prevPoSBlock.getPrev(blockStore), blockStore);
        if (null == prevPrevPoSBlock || null == prevPrevPoSBlock.getPrev(blockStore)) return Utils.encodeCompactBits(initialHashTargetPoS);

        long actualSpacing = prevPoSBlock.getHeader().getTimeSeconds() - prevPrevPoSBlock.getHeader().getTimeSeconds();
        BigInteger posTarget = Utils.decodeCompactBits(prevPoSBlock.getHeader().getDifficultyTarget());

        posTarget = posTarget.multiply(BigInteger.valueOf((POS_INTERVAL - 1) * POS_TARGET_SPACING + actualSpacing + actualSpacing));
        posTarget = posTarget.divide(BigInteger.valueOf((POS_INTERVAL + 1) * POS_TARGET_SPACING));

        if (posTarget.compareTo(this.getMaxTarget()) > 0) {
            log.info("PoS difficulty hit proof of work limit: {}", posTarget.toString(16));
            posTarget = this.getMaxTarget();
        }

        return Utils.encodeCompactBits(posTarget);
    }

    private long getNextWorkRequiredForPoW(final StoredBlock storedPrev, final BlockStore blockStore)
            throws VerificationException, BlockStoreException {

        int i = 0;
        StoredBlock storedFirst = storedPrev;
        BigInteger totalDifficulty = BigInteger.ZERO;
        while (null != storedFirst && i < POW_AVERAGING_WINDOW) {
            if (!storedFirst.getHeader().isProofOfStake()) {
                totalDifficulty = totalDifficulty.add(storedFirst.getHeader().getDifficultyTargetAsInteger());
                ++i;
            }

            storedFirst = storedFirst.getPrev(blockStore);
        }

        if (null == storedFirst) {
            return Utils.encodeCompactBits(this.getMaxTarget());
        }

        BigInteger avg = totalDifficulty.divide(BigInteger.valueOf(POW_AVERAGING_WINDOW));
        return calculateNextWorkRequired(avg, storedPrev.getHeader().getTimeSeconds(), storedFirst.getHeader().getTimeSeconds());
    }

    private long calculateNextWorkRequired(BigInteger avg, long lastBlockTime, long firstBlockTime) {
        long actualTimespan = lastBlockTime - firstBlockTime;
        actualTimespan = POW_AVERAGING_WINDOW_TIMESPAN + (actualTimespan - POW_AVERAGING_WINDOW_TIMESPAN) / 4;

        avg = avg.divide(BigInteger.valueOf(POW_AVERAGING_WINDOW_TIMESPAN));
        avg = avg.multiply(BigInteger.valueOf(actualTimespan));

        if (avg.compareTo(this.getMaxTarget()) > 0) {
            log.info("PoS difficulty hit proof of work limit: {}", avg.toString(16));
            avg = this.getMaxTarget();
        }

        return Utils.encodeCompactBits(avg);
    }

    @Override
    public void checkDifficultyTransitions(final StoredBlock storedPrev, final Block nextBlock,
    	final BlockStore blockStore) throws VerificationException, BlockStoreException {

        int nHeight = storedPrev.getHeight() + 1;
        if (nHeight >= newDifficultyAdjustmentAlgoHeight) {

            long newTargetCompact = nextBlock.isProofOfStake() ?
                    getNextWorkRequiredForPoS(storedPrev, blockStore) :
                    getNextWorkRequiredForPoW(storedPrev, blockStore);

            long receivedTargetCompact = nextBlock.getDifficultyTarget();

            if (newTargetCompact != receivedTargetCompact) {
                throw new VerificationException("Network provided difficulty bits do not match what was calculated, calculated: " +
                        Long.toHexString(newTargetCompact) + " vs received: " + Long.toHexString(receivedTargetCompact));
            }
        }
    }

    @Override
    public Coin getMaxMoney() {
        return MAX_MONEY;
    }

    @Override
    public Coin getMinNonDustOutput() {
        return Transaction.MIN_NONDUST_OUTPUT;
    }

    @Override
    public MonetaryFormat getMonetaryFormat() {
        return new MonetaryFormat();
    }

    @Override
    public int getProtocolVersionNum(final ProtocolVersion version) {
        return version.getBitcoinProtocolVersion();
    }

    @Override
    public BitcoinSerializer getSerializer(boolean parseRetain) {
        return new BitcoinSerializer(this, parseRetain);
    }

    @Override
    public String getUriScheme() {
        return BITCOIN_SCHEME;
    }

    @Override
    public boolean hasMaxMoney() {
        return true;
    }
}