/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

import java.math.BigInteger;
import java.util.Date;

import org.bitcoinj.core.Block;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;

import static com.google.common.base.Preconditions.checkState;

/**
 * Parameters for the testnet, a separate public instance of Bitcoin that has relaxed rules suitable for development
 * and testing of applications and new Bitcoin versions.
 */
public class TestNet3Params extends AbstractBitcoinNetParams {
    public static final int TESTNET_MAJORITY_WINDOW = 100;
    public static final int TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED = 75;
    public static final int TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE = 51;

    public TestNet3Params() {
        super();
        id = ID_TESTNET;
        interval = INTERVAL;
        targetTimespan = TARGET_TIMESPAN;
        maxTarget = new BigInteger("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16);
        maxTargetStart = new BigInteger("000007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16);
        initialHashTargetPoS = new BigInteger("00000007ffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16);

        port = 17333;
        addressHeader = 111;
        p2shHeader = 196;
        dumpedPrivateKeyHeader = 239;
        segwitAddressHrp = "tbca";

        genesisBlock.setDifficultyTarget(Utils.encodeCompactBits(maxTarget));
        genesisBlock.setTime(1296688602L);
        genesisBlock.setNonce(414098458);

        spendableCoinbaseDepth = 100;
        subsidyDecreaseBlockCount = 210000;
        String genesisHash = genesisBlock.getHashAsString();
        checkState(genesisHash.equals("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"));

        dnsSeeds = new String[] {
                "testnet-seed.bitcoinatom.io",
                "testnet-seed.bitcoinatom.org",
                "testnet-seed.bitcoinatom.net",
        };

        addrSeeds = null;
        packetMagic = 0xa68e3fd6L;
        bip32HeaderPub = 0x043587CF;
        bip32HeaderPriv = 0x04358394;

        BCAHeight = 1260000;
        BCAInitLim = 50000;
        newDifficultyAdjustmentAlgoHeight = 1314131;

        majorityEnforceBlockUpgrade = TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = TESTNET_MAJORITY_WINDOW;
    }

    private static TestNet3Params instance;
    public static synchronized TestNet3Params get() {
        if (instance == null) {
            instance = new TestNet3Params();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return PAYMENT_PROTOCOL_ID_TESTNET;
    }
}
