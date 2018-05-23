/*
 * Copyright 2014 Mike Hearn
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

package org.bitcoinj.wallet;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.BloomFilter;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.*;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.script.Script.ScriptType;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.listeners.KeyChainEventListener;

import com.google.common.collect.ImmutableList;
import org.junit.Before;
import org.junit.Test;
import org.spongycastle.crypto.params.KeyParameter;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.junit.Assert.*;

public class KeyChainGroupTest {
    // Number of initial keys in this tests HD wallet, including interior keys.
    private static final int INITIAL_KEYS = 4;
    private static final int LOOKAHEAD_SIZE = 5;
    private static final NetworkParameters MAINNET = MainNetParams.get();
    private static final String XPUB = "xpub68KFnj3bqUx1s7mHejLDBPywCAKdJEu1b49uniEEn2WSbHmZ7xbLqFTjJbtx1LUcAt1DwhoqWHmo2s5WMJp6wi38CiF2hYD49qVViKVvAoi";
    private KeyChainGroup group;
    private DeterministicKey watchingAccountKey;

    @Before
    public void setup() {
        BriefLogFormatter.init();
        Utils.setMockClock();
        group = new KeyChainGroup(MAINNET);
        group.setLookaheadSize(LOOKAHEAD_SIZE);   // Don't want slow tests.
        group.getActiveKeyChain();  // Force create a chain.

        watchingAccountKey = DeterministicKey.deserializeB58(null, XPUB, MAINNET);
    }

    @Test
    public void freshCurrentKeys() throws Exception {
        int numKeys = ((group.getLookaheadSize() + group.getLookaheadThreshold()) * 2)   // * 2 because of internal/external
                + 1  // keys issued
                + group.getActiveKeyChain().getAccountPath().size() + 2  /* account key + int/ext parent keys */;
        assertEquals(numKeys, group.numKeys());
        assertEquals(2 * numKeys, group.getBloomFilterElementCount());
        ECKey r1 = group.currentKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(numKeys, group.numKeys());
        assertEquals(2 * numKeys, group.getBloomFilterElementCount());

        ECKey i1 = new ECKey();
        group.importKeys(i1);
        numKeys++;
        assertEquals(numKeys, group.numKeys());
        assertEquals(2 * numKeys, group.getBloomFilterElementCount());

        ECKey r2 = group.currentKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(r1, r2);
        ECKey c1 = group.currentKey(KeyChain.KeyPurpose.CHANGE);
        assertNotEquals(r1, c1);
        ECKey r3 = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertNotEquals(r1, r3);
        ECKey c2 = group.freshKey(KeyChain.KeyPurpose.CHANGE);
        assertNotEquals(r3, c2);
        // Current key has not moved and will not under marked as used.
        ECKey r4 = group.currentKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(r2, r4);
        ECKey c3 = group.currentKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(c1, c3);
        // Mark as used. Current key is now different.
        group.markPubKeyAsUsed(r4.getPubKey());
        ECKey r5 = group.currentKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertNotEquals(r4, r5);
    }

    @Test
    public void imports() throws Exception {
        ECKey key1 = new ECKey();
        int numKeys = group.numKeys();
        assertFalse(group.removeImportedKey(key1));
        assertEquals(1, group.importKeys(ImmutableList.of(key1)));
        assertEquals(numKeys + 1, group.numKeys());   // Lookahead is triggered by requesting a key, so none yet.
        group.removeImportedKey(key1);
        assertEquals(numKeys, group.numKeys());
    }

    @Test
    public void findKey() throws Exception {
        ECKey a = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        ECKey b = group.freshKey(KeyChain.KeyPurpose.CHANGE);
        ECKey c = new ECKey();
        ECKey d = new ECKey();   // Not imported.
        group.importKeys(c);
        assertTrue(group.hasKey(a));
        assertTrue(group.hasKey(b));
        assertTrue(group.hasKey(c));
        assertFalse(group.hasKey(d));
        ECKey result = group.findKeyFromPubKey(a.getPubKey());
        assertEquals(a, result);
        result = group.findKeyFromPubKey(b.getPubKey());
        assertEquals(b, result);
        result = group.findKeyFromPubHash(a.getPubKeyHash());
        assertEquals(a, result);
        result = group.findKeyFromPubHash(b.getPubKeyHash());
        assertEquals(b, result);
        result = group.findKeyFromPubKey(c.getPubKey());
        assertEquals(c, result);
        result = group.findKeyFromPubHash(c.getPubKeyHash());
        assertEquals(c, result);
        assertNull(group.findKeyFromPubKey(d.getPubKey()));
        assertNull(group.findKeyFromPubHash(d.getPubKeyHash()));
    }


    // Check encryption with and without a basic keychain.

    @Test
    public void bloom() throws Exception {
        ECKey key1 = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        ECKey key2 = new ECKey();
        BloomFilter filter = group.getBloomFilter(group.getBloomFilterElementCount(), 0.001, (long)(Math.random() * Long.MAX_VALUE));
        assertTrue(filter.contains(key1.getPubKeyHash()));
        assertFalse(filter.contains(key2.getPubKey()));
        // Check that the filter contains the lookahead buffer and threshold zone.
        for (int i = 0; i < LOOKAHEAD_SIZE + group.getLookaheadThreshold(); i++) {
            ECKey k = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
            assertTrue(filter.contains(k.getPubKeyHash()));
        }
        // We ran ahead of the lookahead buffer.
        assertFalse(filter.contains(group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).getPubKey()));
        group.importKeys(key2);
        filter = group.getBloomFilter(group.getBloomFilterElementCount(), 0.001, (long) (Math.random() * Long.MAX_VALUE));
        assertTrue(filter.contains(key1.getPubKeyHash()));
    }

    @Test
    public void earliestKeyTime() throws Exception {
        long now = Utils.currentTimeSeconds();   // mock
        long yesterday = now - 86400;
        assertEquals(now, group.getEarliestKeyCreationTime());
        Utils.rollMockClock(10000);
        group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        Utils.rollMockClock(10000);
        group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        // Check that all keys are assumed to be created at the same instant the seed is.
        assertEquals(now, group.getEarliestKeyCreationTime());
        ECKey key = new ECKey();
        key.setCreationTimeSeconds(yesterday);
        group.importKeys(key);
        assertEquals(yesterday, group.getEarliestKeyCreationTime());
    }

    @Test
    public void events() throws Exception {
        // Check that events are registered with the right chains and that if a chain is added, it gets the event
        // listeners attached properly even post-hoc.
        final AtomicReference<ECKey> ran = new AtomicReference<>(null);
        final KeyChainEventListener listener = new KeyChainEventListener() {
            @Override
            public void onKeysAdded(List<ECKey> keys) {
                ran.set(keys.get(0));
            }
        };
        group.addEventListener(listener, Threading.SAME_THREAD);
        ECKey key = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(key, ran.getAndSet(null));
        ECKey key2 = new ECKey();
        group.importKeys(key2);
        assertEquals(key2, ran.getAndSet(null));
        group.removeEventListener(listener);
        ECKey key3 = new ECKey();
        group.importKeys(key3);
        assertNull(ran.get());
    }

    @Test
    public void serialization() throws Exception {
        int initialKeys = INITIAL_KEYS + group.getActiveKeyChain().getAccountPath().size() - 1;
        assertEquals(initialKeys + 1 /* for the seed */, group.serializeToProtobuf().size());
        group = KeyChainGroup.fromProtobufUnencrypted(MAINNET, group.serializeToProtobuf());
        group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key1 = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key2 = group.freshKey(KeyChain.KeyPurpose.CHANGE);
        group.getBloomFilterElementCount();
        List<Protos.Key> protoKeys1 = group.serializeToProtobuf();
        assertEquals(initialKeys + ((LOOKAHEAD_SIZE + 1) * 2) + 1 /* for the seed */ + 1, protoKeys1.size());
        group.importKeys(new ECKey());
        List<Protos.Key> protoKeys2 = group.serializeToProtobuf();
        assertEquals(initialKeys + ((LOOKAHEAD_SIZE + 1) * 2) + 1 /* for the seed */ + 2, protoKeys2.size());

        group = KeyChainGroup.fromProtobufUnencrypted(MAINNET, protoKeys1);
        assertEquals(initialKeys + ((LOOKAHEAD_SIZE + 1)  * 2)  + 1 /* for the seed */ + 1, protoKeys1.size());
        assertTrue(group.hasKey(key1));
        assertTrue(group.hasKey(key2));
        assertEquals(key2, group.currentKey(KeyChain.KeyPurpose.CHANGE));
        assertEquals(key1, group.currentKey(KeyChain.KeyPurpose.RECEIVE_FUNDS));
        group = KeyChainGroup.fromProtobufUnencrypted(MAINNET, protoKeys2);
        assertEquals(initialKeys + ((LOOKAHEAD_SIZE + 1) * 2) + 1 /* for the seed */ + 2, protoKeys2.size());
        assertTrue(group.hasKey(key1));
        assertTrue(group.hasKey(key2));

        KeyCrypterScrypt scrypt = new KeyCrypterScrypt(2);
        final KeyParameter aesKey = scrypt.deriveKey("password");
        group.encrypt(scrypt, aesKey);
        List<Protos.Key> protoKeys3 = group.serializeToProtobuf();
        group = KeyChainGroup.fromProtobufEncrypted(MAINNET, protoKeys3, scrypt);
        assertTrue(group.isEncrypted());
        assertTrue(group.checkPassword("password"));
        group.decrypt(aesKey);

        // No need for extensive contents testing here, as that's done in the keychain class tests.
    }

    @Test
    public void serializeWatching() throws Exception {
        group = new KeyChainGroup(MAINNET, watchingAccountKey);
        group.setLookaheadSize(LOOKAHEAD_SIZE);
        group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        group.freshKey(KeyChain.KeyPurpose.CHANGE);
        group.getBloomFilterElementCount();  // Force lookahead.
        List<Protos.Key> protoKeys1 = group.serializeToProtobuf();
        assertEquals(3 + (group.getLookaheadSize() + group.getLookaheadThreshold() + 1) * 2, protoKeys1.size());
        group = KeyChainGroup.fromProtobufUnencrypted(MAINNET, protoKeys1);
        assertEquals(3 + (group.getLookaheadSize() + group.getLookaheadThreshold() + 1) * 2, group.serializeToProtobuf().size());
    }

    @Test
    public void constructFromSeed() throws Exception {
        ECKey key1 = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        final DeterministicSeed seed = checkNotNull(group.getActiveKeyChain().getSeed());
        KeyChainGroup group2 = new KeyChainGroup(MAINNET, seed);
        group2.setLookaheadSize(5);
        ECKey key2 = group2.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(key1, key2);
    }

    @Test
    public void markAsUsed() throws Exception {
        Address addr1 = group.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        Address addr2 = group.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(addr1, addr2);
        group.markPubKeyHashAsUsed(addr1.getHash());
        Address addr3 = group.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertNotEquals(addr2, addr3);
    }

    @Test
    public void isNotWatching() {
        group = new KeyChainGroup(MAINNET);
        final ECKey key = ECKey.fromPrivate(BigInteger.TEN);
        group.importKeys(key);
        assertFalse(group.isWatching());
    }

    @Test
    public void isWatching() {
        group = new KeyChainGroup(
                MAINNET,
                DeterministicKey
                        .deserializeB58(
                                "xpub69bjfJ91ikC5ghsqsVDHNq2dRGaV2HHVx7Y9LXi27LN9BWWAXPTQr4u8U3wAtap8bLdHdkqPpAcZmhMS5SnrMQC4ccaoBccFhh315P4UYzo",
                                MAINNET));
        final ECKey watchingKey = ECKey.fromPublicOnly(new ECKey().getPubKeyPoint());
        group.importKeys(watchingKey);
        assertTrue(group.isWatching());
    }

    @Test(expected = IllegalStateException.class)
    public void isWatchingNoKeys() {
        group = new KeyChainGroup(MAINNET);
        group.isWatching();
    }

    @Test(expected = IllegalStateException.class)
    public void isWatchingMixedKeys() {
        group = new KeyChainGroup(
                MAINNET,
                DeterministicKey
                        .deserializeB58(
                                "xpub69bjfJ91ikC5ghsqsVDHNq2dRGaV2HHVx7Y9LXi27LN9BWWAXPTQr4u8U3wAtap8bLdHdkqPpAcZmhMS5SnrMQC4ccaoBccFhh315P4UYzo",
                                MAINNET));
        final ECKey key = ECKey.fromPrivate(BigInteger.TEN);
        group.importKeys(key);
        group.isWatching();
    }
}
