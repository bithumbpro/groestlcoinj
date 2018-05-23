/*
 * Copyright 2011 Google Inc.
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

package org.bitcoinj.core;

import com.google.common.base.Charsets;
import com.google.common.io.ByteStreams;

import com.google.common.io.Resources;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.script.ScriptOpCodes;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.net.URL;
import java.util.Arrays;
import java.util.EnumSet;

import static org.junit.Assert.*;

public class BlockTest {
    private static final NetworkParameters TESTNET = TestNet3Params.get();
    private static final NetworkParameters UNITTEST = UnitTestParams.get();
    private static final NetworkParameters MAINNET = MainNetParams.get();

    private byte[] block1325549Bytes;
    private Block block1325549;

    @Before
    public void setUp() throws Exception {
        new Context(TESTNET);
        // One with some of transactions in, so a good test of the merkle tree hashing.
        URL resource = BlockTest.class.getResource("block1325549_testnet.txt");
        String text = Resources.toString(resource, Charsets.UTF_8);

        block1325549Bytes = Utils.HEX.decode(text);
        block1325549 = TESTNET.getDefaultSerializer().makeBlock(block1325549Bytes);
        assertEquals("8e3aae1d7d8de407283a60e2123d3bbaa3aab7c525a1bd2537e166ee23d68047", block1325549.getHashAsString());
    }

    @Test
    public void testWork() throws Exception {
        BigInteger work = TESTNET.getGenesisBlock().getWork();
        double log2Work = Math.log(work.longValue()) / Math.log(2);
        // This number is printed by Bitcoin Core at startup as the calculated value of chainWork on testnet:
        // UpdateTip: new best=000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943 height=0 version=0x00000001 log2_work=32.000022 tx=1 date='2011-02-02 23:16:42' ...
        assertEquals(32.000022, log2Work, 0.0000001);
    }

    @Test
    public void testBlockVerification() throws Exception {
        block1325549.verify(Block.BLOCK_HEIGHT_GENESIS, EnumSet.noneOf(Block.VerifyFlag.class));
    }

    @Test
    public void testBadTransactions() throws Exception {
        // Re-arrange so the coinbase transaction is not first.
        Transaction tx1 = block1325549.transactions.get(0);
        Transaction tx2 = block1325549.transactions.get(1);
        block1325549.transactions.set(0, tx2);
        block1325549.transactions.set(1, tx1);
        try {
            block1325549.verify(Block.BLOCK_HEIGHT_GENESIS, EnumSet.noneOf(Block.VerifyFlag.class));
            fail();
        } catch (VerificationException e) {
            // We should get here.
        }
    }

    @Test
    public void testHeaderParse() throws Exception {
        Block header = block1325549.cloneAsHeader();
        Block reparsed = TESTNET.getDefaultSerializer().makeBlock(header.bitcoinSerialize());
        assertEquals(reparsed, header);
    }

    @Test
    public void testBitcoinSerialization() throws Exception {
        // We have to be able to reserialize everything exactly as we found it for hashing to work. This test also
        // proves that transaction serialization works, along with all its subobjects like scripts and in/outpoints.
        //
        // NB: This tests the bitcoin serialization protocol.
        assertTrue(Arrays.equals(block1325549Bytes, block1325549.bitcoinSerialize()));
    }

    @Test
    public void testUpdateLength() {
        Block block = UNITTEST.getGenesisBlock().createNextBlockWithCoinbase(Block.BLOCK_VERSION_GENESIS, new ECKey().getPubKey(), Block.BLOCK_HEIGHT_GENESIS);
        assertEquals(block.bitcoinSerialize().length, block.length);
        final int origBlockLen = block.length;
        Transaction tx = new Transaction(UNITTEST);
        // this is broken until the transaction has > 1 input + output (which is required anyway...)
        //assertTrue(tx.length == tx.bitcoinSerialize().length && tx.length == 8);
        byte[] outputScript = new byte[10];
        Arrays.fill(outputScript, (byte) ScriptOpCodes.OP_FALSE);
        tx.addOutput(new TransactionOutput(UNITTEST, null, Coin.SATOSHI, outputScript));
        tx.addInput(new TransactionInput(UNITTEST, null, new byte[] {(byte) ScriptOpCodes.OP_FALSE},
                new TransactionOutPoint(UNITTEST, 0, Sha256Hash.of(new byte[] { 1 }))));
        int origTxLength = 8 + 2 + 8 + 1 + 10 + 40 + 1 + 1;
        assertEquals(tx.unsafeBitcoinSerialize().length, tx.length);
        assertEquals(origTxLength, tx.length);
        block.addTransaction(tx);
        assertEquals(block.unsafeBitcoinSerialize().length, block.length);
        assertEquals(origBlockLen + tx.length, block.length);
        block.getTransactions().get(1).getInputs().get(0).setScriptBytes(new byte[] {(byte) ScriptOpCodes.OP_FALSE, (byte) ScriptOpCodes.OP_FALSE});
        assertEquals(block.length, origBlockLen + tx.length);
        assertEquals(tx.length, origTxLength + 1);
        block.getTransactions().get(1).getInputs().get(0).clearScriptBytes();
        assertEquals(block.length, block.unsafeBitcoinSerialize().length);
        assertEquals(block.length, origBlockLen + tx.length);
        assertEquals(tx.length, origTxLength - 1);
        block.getTransactions().get(1).addInput(new TransactionInput(UNITTEST, null, new byte[] {(byte) ScriptOpCodes.OP_FALSE},
                new TransactionOutPoint(UNITTEST, 0, Sha256Hash.of(new byte[] { 1 }))));
        assertEquals(block.length, origBlockLen + tx.length);
        assertEquals(tx.length, origTxLength + 41); // - 1 + 40 + 1 + 1
    }

    @Test
    public void isBIPs() throws Exception {
        final Block genesis = MAINNET.getGenesisBlock();
        assertFalse(genesis.isBIP34());
        assertFalse(genesis.isBIP66());
        assertFalse(genesis.isBIP65());

        // 227835/00000000000001aa077d7aa84c532a4d69bdbff519609d1da0835261b7a74eb6: last version 1 block
        final Block block227835 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block227835.dat")));
        assertFalse(block227835.isBIP34());
        assertFalse(block227835.isBIP66());
        assertFalse(block227835.isBIP65());

        // 227836/00000000000000d0dfd4c9d588d325dce4f32c1b31b7c0064cba7025a9b9adcc: version 2 block
        final Block block227836 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block227836.dat")));
        assertTrue(block227836.isBIP34());
        assertFalse(block227836.isBIP66());
        assertFalse(block227836.isBIP65());

        // 363703/0000000000000000011b2a4cb91b63886ffe0d2263fd17ac5a9b902a219e0a14: version 3 block
        final Block block363703 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block363703.dat")));
        assertTrue(block363703.isBIP34());
        assertTrue(block363703.isBIP66());
        assertFalse(block363703.isBIP65());

        // 383616/00000000000000000aab6a2b34e979b09ca185584bd1aecf204f24d150ff55e9: version 4 block
        final Block block383616 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block383616.dat")));
        assertTrue(block383616.isBIP34());
        assertTrue(block383616.isBIP66());
        assertTrue(block383616.isBIP65());

        // 370661/00000000000000001416a613602d73bbe5c79170fd8f39d509896b829cf9021e: voted for BIP101
        final Block block370661 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block370661.dat")));
        assertTrue(block370661.isBIP34());
        assertTrue(block370661.isBIP66());
        assertTrue(block370661.isBIP65());
    }
}
