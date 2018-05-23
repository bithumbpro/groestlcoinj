/*
 * Copyright 2014 Google Inc.
 * Copyright 2016 Andreas Schildbach
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
import static org.bitcoinj.script.ScriptOpCodes.*;

import org.bitcoinj.core.TransactionConfidence.*;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.params.*;
import org.bitcoinj.script.*;
import org.bitcoinj.testing.*;
import org.easymock.*;
import org.junit.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import static org.bitcoinj.core.Utils.HEX;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

/**
 * Just check the Transaction.verify() method. Most methods that have complicated logic in Transaction are tested
 * elsewhere, e.g. signing and hashing are well exercised by the wallet tests, the full block chain tests and so on.
 * The verify method is also exercised by the full block chain tests, but it can also be used by API users alone,
 * so we make sure to cover it here as well.
 */
public class TransactionTest {
    private static final NetworkParameters UNITTEST = UnitTestParams.get();
    private static final Address ADDRESS = LegacyAddress.fromKey(UNITTEST, new ECKey());

    private Transaction tx;

    @Before
    public void setUp() throws Exception {
        Context context = new Context(UNITTEST);
        tx = FakeTxBuilder.createFakeTx(UNITTEST);
    }

    @Test(expected = VerificationException.EmptyInputsOrOutputs.class)
    public void emptyOutputs() throws Exception {
        tx.clearOutputs();
        tx.verify();
    }

    @Test(expected = VerificationException.EmptyInputsOrOutputs.class)
    public void emptyInputs() throws Exception {
        tx.clearInputs();
        tx.verify();
    }

    @Test(expected = VerificationException.LargerThanMaxBlockSize.class)
    public void tooHuge() throws Exception {
        tx.getInput(0).setScriptBytes(new byte[Block.MAX_BLOCK_SIZE]);
        tx.verify();
    }

    @Test(expected = VerificationException.DuplicatedOutPoint.class)
    public void duplicateOutPoint() throws Exception {
        TransactionInput input = tx.getInput(0);
        input.setScriptBytes(new byte[1]);
        tx.addInput(input.duplicateDetached());
        tx.verify();
    }

    @Test(expected = VerificationException.NegativeValueOutput.class)
    public void negativeOutput() throws Exception {
        tx.getOutput(0).setValue(Coin.NEGATIVE_SATOSHI);
        tx.verify();
    }

    @Test(expected = VerificationException.ExcessiveValue.class)
    public void exceedsMaxMoney2() throws Exception {
        Coin half = UNITTEST.getMaxMoney().divide(2).add(Coin.SATOSHI);
        tx.getOutput(0).setValue(half);
        tx.addOutput(half, ADDRESS);
        tx.verify();
    }

    @Test(expected = VerificationException.UnexpectedCoinbaseInput.class)
    public void coinbaseInputInNonCoinbaseTX() throws Exception {
        tx.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new ScriptBuilder().data(new byte[10]).build());
        tx.verify();
    }

    @Test(expected = VerificationException.CoinbaseScriptSizeOutOfRange.class)
    public void coinbaseScriptSigTooSmall() throws Exception {
        tx.clearInputs();
        tx.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new ScriptBuilder().build());
        tx.verify();
    }

    @Test(expected = VerificationException.CoinbaseScriptSizeOutOfRange.class)
    public void coinbaseScriptSigTooLarge() throws Exception {
        tx.clearInputs();
        TransactionInput input = tx.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new ScriptBuilder().data(new byte[99]).build());
        assertEquals(101, input.getScriptBytes().length);
        tx.verify();
    }

    @Test
    public void testEstimatedLockTime_WhenParameterSignifiesBlockHeight() {
        int TEST_LOCK_TIME = 20;
        Date now = Calendar.getInstance().getTime();

        BlockChain mockBlockChain = createMock(BlockChain.class);
        EasyMock.expect(mockBlockChain.estimateBlockTime(TEST_LOCK_TIME)).andReturn(now);

        Transaction tx = FakeTxBuilder.createFakeTx(UNITTEST);
        tx.setLockTime(TEST_LOCK_TIME); // less than five hundred million

        replay(mockBlockChain);

        assertEquals(tx.estimateLockTime(mockBlockChain), now);
    }

    @Test
    public void testOptimalEncodingMessageSize() {
        Transaction tx = new Transaction(UNITTEST);

        int length = tx.length;

        // add basic transaction input, check the length
        tx.addOutput(new TransactionOutput(UNITTEST, null, Coin.COIN, ADDRESS));
        length += getCombinedLength(tx.getOutputs());

        // add basic output, check the length
        length += getCombinedLength(tx.getInputs());

        // optimal encoding size should equal the length we just calculated
        assertEquals(tx.getOptimalEncodingMessageSize(), length);
    }

    private int getCombinedLength(List<? extends Message> list) {
        int sumOfAllMsgSizes = 0;
        for (Message m: list) { sumOfAllMsgSizes += m.getMessageSize() + 1; }
        return sumOfAllMsgSizes;
    }

    @Test
    public void testIsMatureReturnsFalseIfTransactionIsCoinbaseAndConfidenceTypeIsNotEqualToBuilding() {
        Transaction tx = FakeTxBuilder.createFakeCoinbaseTx(UNITTEST);

        tx.getConfidence().setConfidenceType(ConfidenceType.UNKNOWN);
        assertEquals(tx.isMature(), false);

        tx.getConfidence().setConfidenceType(ConfidenceType.PENDING);
        assertEquals(tx.isMature(), false);

        tx.getConfidence().setConfidenceType(ConfidenceType.DEAD);
        assertEquals(tx.isMature(), false);
    }

    @Test
    public void testCLTVPaymentChannelTransactionSpending() {
        BigInteger time = BigInteger.valueOf(20);

        ECKey from = new ECKey(), to = new ECKey(), incorrect = new ECKey();
        Script outputScript = ScriptBuilder.createCLTVPaymentChannelOutput(time, from, to);

        Transaction tx = new Transaction(UNITTEST);
        tx.addInput(new TransactionInput(UNITTEST, tx, new byte[] {}));
        tx.getInput(0).setSequenceNumber(0);
        tx.setLockTime(time.subtract(BigInteger.ONE).longValue());
        TransactionSignature fromSig =
                tx.calculateSignature(
                        0,
                        from,
                        outputScript,
                        Transaction.SigHash.SINGLE,
                        false);
        TransactionSignature toSig =
                tx.calculateSignature(
                        0,
                        to,
                        outputScript,
                        Transaction.SigHash.SINGLE,
                        false);
        TransactionSignature incorrectSig =
                tx.calculateSignature(
                        0,
                        incorrect,
                        outputScript,
                        Transaction.SigHash.SINGLE,
                        false);
        Script scriptSig =
                ScriptBuilder.createCLTVPaymentChannelInput(fromSig, toSig);
        Script refundSig =
                ScriptBuilder.createCLTVPaymentChannelRefund(fromSig);
        Script invalidScriptSig1 =
                ScriptBuilder.createCLTVPaymentChannelInput(fromSig, incorrectSig);
        Script invalidScriptSig2 =
                ScriptBuilder.createCLTVPaymentChannelInput(incorrectSig, toSig);

        try {
            scriptSig.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
        } catch (ScriptException e) {
            e.printStackTrace();
            fail("Settle transaction failed to correctly spend the payment channel");
        }

        try {
            refundSig.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
            fail("Refund passed before expiry");
        } catch (ScriptException e) { }
        try {
            invalidScriptSig1.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
            fail("Invalid sig 1 passed");
        } catch (ScriptException e) { }
        try {
            invalidScriptSig2.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
            fail("Invalid sig 2 passed");
        } catch (ScriptException e) { }
    }

    @Test
    public void testCLTVPaymentChannelTransactionRefund() {
        BigInteger time = BigInteger.valueOf(20);

        ECKey from = new ECKey(), to = new ECKey(), incorrect = new ECKey();
        Script outputScript = ScriptBuilder.createCLTVPaymentChannelOutput(time, from, to);

        Transaction tx = new Transaction(UNITTEST);
        tx.addInput(new TransactionInput(UNITTEST, tx, new byte[] {}));
        tx.getInput(0).setSequenceNumber(0);
        tx.setLockTime(time.add(BigInteger.ONE).longValue());
        TransactionSignature fromSig =
                tx.calculateSignature(
                        0,
                        from,
                        outputScript,
                        Transaction.SigHash.SINGLE,
                        false);
        TransactionSignature incorrectSig =
                tx.calculateSignature(
                        0,
                        incorrect,
                        outputScript,
                        Transaction.SigHash.SINGLE,
                        false);
        Script scriptSig =
                ScriptBuilder.createCLTVPaymentChannelRefund(fromSig);
        Script invalidScriptSig =
                ScriptBuilder.createCLTVPaymentChannelRefund(incorrectSig);

        try {
            scriptSig.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
        } catch (ScriptException e) {
            e.printStackTrace();
            fail("Refund failed to correctly spend the payment channel");
        }

        try {
            invalidScriptSig.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
            fail("Invalid sig passed");
        } catch (ScriptException e) { }
    }

    @Test
    public void witnessTransaction() {
        byte[] hex = null;
        byte[] hex2 = null;
        Transaction tx = null;

        // Roundtrip without witness
        hex = HEX.decode(
                "0100000003362c10b042d48378b428d60c5c98d8b8aca7a03e1a2ca1048bfd"
                + "469934bbda95010000008b483045022046c8bc9fb0e063e2fc8c6b1084af"
                + "e6370461c16cbf67987d97df87827917d42d022100c807fa0ab95945a6e7"
                + "4c59838cc5f9e850714d8850cec4db1e7f3bcf71d5f5ef0141044450af01"
                + "b4cc0d45207bddfb47911744d01f768d23686e9ac784162a5b3a15bc01e6"
                + "653310bdd695d8c35d22e9bb457563f8de116ecafea27a0ec831e4a3e9fe"
                + "ffffffffc19529a54ae15c67526cc5e20e535973c2d56ef35ff51bace544"
                + "4388331c4813000000008b48304502201738185959373f04cc73dbbb1d06"
                + "1623d51dc40aac0220df56dabb9b80b72f49022100a7f76bde06369917c2"
                + "14ee2179e583fefb63c95bf876eb54d05dfdf0721ed772014104e6aa2cf1"
                + "08e1c650e12d8dd7ec0a36e478dad5a5d180585d25c30eb7c88c3df0c6f5"
                + "fd41b3e70b019b777abd02d319bf724de184001b3d014cb740cb83ed21a6"
                + "ffffffffbaae89b5d2e3ca78fd3f13cf0058784e7c089fb56e1e596d70ad"
                + "cfa486603967010000008b483045022055efbaddb4c67c1f1a46464c8f77"
                + "0aab03d6b513779ad48735d16d4c5b9907c2022100f469d50a5e5556fc2c"
                + "932645f6927ac416aa65bc83d58b888b82c3220e1f0b73014104194b3f8a"
                + "a08b96cae19b14bd6c32a92364bea3051cb9f018b03e3f09a57208ff058f"
                + "4b41ebf96b9911066aef3be22391ac59175257af0984d1432acb8f2aefca"
                + "ffffffff0340420f00000000001976a914c0fbb13eb10b57daa78b47660a"
                + "4ffb79c29e2e6b88ac204e0000000000001976a9142cae94ffdc05f8214c"
                + "cb2b697861c9c07e3948ee88ac1c2e0100000000001976a9146e03561cd4"
                + "d6033456cc9036d409d2bf82721e9888ac00000000");
        tx = new Transaction(NetworkParameters.fromID(NetworkParameters.ID_MAINNET), hex);
        assertEquals(3, tx.getOutputs().size());
        assertEquals(3, tx.getInputs().size());
        assertFalse(tx.hasWitness());
        hex2 = tx.bitcoinSerialize();
        assertArrayEquals(hex, hex2);
        assertEquals(
                "Incorrect hash",
                "38d4cfeb57d6685753b7a3b3534c3cb576c34ca7344cd4582f9613ebf0c2b02a",
                tx.getHash().toString());

        // Roundtrip with witness
        hex = HEX.decode(
                "0100000000010213206299feb17742091c3cb2ab45faa3aa87922d3c030caf"
                + "b3f798850a2722bf0000000000feffffffa12f2424b9599898a1d30f06e1"
                + "ce55eba7fabfeee82ae9356f07375806632ff3010000006b483045022100"
                + "fcc8cf3014248e1a0d6dcddf03e80f7e591605ad0dbace27d2c0d87274f8"
                + "cd66022053fcfff64f35f22a14deb657ac57f110084fb07bb917c3b42e7d"
                + "033c54c7717b012102b9e4dcc33c9cc9cb5f42b96dddb3b475b067f3e211"
                + "25f79e10c853e5ca8fba31feffffff02206f9800000000001976a9144841"
                + "b9874d913c430048c78a7b18baebdbea440588ac80969800000000001600"
                + "14e4873ef43eac347471dd94bc899c51b395a509a502483045022100dd82"
                + "50f8b5c2035d8feefae530b10862a63030590a851183cb61b3672eb4f26e"
                + "022057fe7bc8593f05416c185d829b574290fb8706423451ebd0a0ae50c2"
                + "76b87b43012102179862f40b85fa43487500f1d6b13c864b5eb0a8399973"
                + "8db0f7a6b91b2ec64f00db080000");
        tx = new Transaction(NetworkParameters.fromID(NetworkParameters.ID_MAINNET), hex);
        assertEquals(2, tx.getOutputs().size());
        assertEquals(2, tx.getInputs().size());
        assertTrue(tx.hasWitness());
        hex2 = tx.bitcoinSerialize();
        assertArrayEquals(hex, hex2);
        assertEquals(
                "Incorrect hash",
                "99e7484eafb6e01622c395c8cae7cb9f8822aab6ba993696b39df8b60b0f4b11",
                tx.getHash().toString());

        // Check signature witness
        hex = HEX.decode(
                "0100000000010213206299feb17742091c3cb2ab45faa3aa87922d3c030caf"
                + "b3f798850a2722bf0000000000feffffffa12f2424b9599898a1d30f06e1"
                + "ce55eba7fabfeee82ae9356f07375806632ff3010000006b483045022100"
                + "fcc8cf3014248e1a0d6dcddf03e80f7e591605ad0dbace27d2c0d87274f8"
                + "cd66022053fcfff64f35f22a14deb657ac57f110084fb07bb917c3b42e7d"
                + "033c54c7717b012102b9e4dcc33c9cc9cb5f42b96dddb3b475b067f3e211"
                + "25f79e10c853e5ca8fba31feffffff02206f9800000000001976a9144841"
                + "b9874d913c430048c78a7b18baebdbea440588ac80969800000000001600"
                + "14e4873ef43eac347471dd94bc899c51b395a509a502483045022100dd82"
                + "50f8b5c2035d8feefae530b10862a63030590a851183cb61b3672eb4f26e"
                + "022057fe7bc8593f05416c185d829b574290fb8706423451ebd0a0ae50c2"
                + "76b87b43012102179862f40b85fa43487500f1d6b13c864b5eb0a8399973"
                + "8db0f7a6b91b2ec64f00db080000");
        tx = new Transaction(NetworkParameters.fromID(NetworkParameters.ID_MAINNET), hex);
        Sha256Hash hash = tx.hashForSignatureWitness(0,
                new Script(HEX.decode("76a914e4873ef43eac347471dd94bc899c51b395a509a588ac")),
                Coin.valueOf(10000000),
                Transaction.SigHash.ALL, false);
        hash = Sha256Hash.wrapReversed(hash.getBytes());
        assertEquals(
                "Hash does not match",
                "36c6483c901d82f55a6557b5060653036f3ba96cd8c55ddb0f204c9e1fbd5b15",
                hash.toString());

        // Check signature witness from https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki sample
        hex = HEX.decode(
                "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf43354"
                + "1db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa8"
                + "9e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb2"
                + "06000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988"
                + "ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167f"
                + "aa815988ac11000000");
        tx = new Transaction(NetworkParameters.fromID(NetworkParameters.ID_MAINNET), hex);
        hash = tx.hashForSignatureWitness(1,
                new Script(HEX.decode("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac")),
                Coin.valueOf(0x23c34600L),
                Transaction.SigHash.ALL, false);
        assertEquals(
                "Hash does not match",
                "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670",
                hash.toString());
    }

    @Test
    public void testToStringWhenLockTimeIsSpecifiedInBlockHeight() {
        Transaction tx = FakeTxBuilder.createFakeTx(UNITTEST);
        TransactionInput input = tx.getInput(0);
        input.setSequenceNumber(42);

        int TEST_LOCK_TIME = 20;
        tx.setLockTime(TEST_LOCK_TIME);

        Calendar cal = Calendar.getInstance();
        cal.set(2085, 10, 4, 17, 53, 21);
        cal.set(Calendar.MILLISECOND, 0);

        BlockChain mockBlockChain = createMock(BlockChain.class);
        EasyMock.expect(mockBlockChain.estimateBlockTime(TEST_LOCK_TIME)).andReturn(cal.getTime());

        replay(mockBlockChain);

        String str = tx.toString(mockBlockChain);

        assertEquals(str.contains("block " + TEST_LOCK_TIME), true);
        assertEquals(str.contains("estimated to be reached at"), true);
    }

    @Test
    public void testToStringWhenIteratingOverAnInputCatchesAnException() {
        Transaction tx = FakeTxBuilder.createFakeTx(UNITTEST);
        TransactionInput ti = new TransactionInput(UNITTEST, tx, new byte[0]) {
            @Override
            public Script getScriptSig() throws ScriptException {
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "");
            }
        };

        tx.addInput(ti);
        assertEquals(tx.toString().contains("[exception: "), true);
    }

    @Test
    public void testToStringWhenThereAreZeroInputs() {
        Transaction tx = new Transaction(UNITTEST);
        assertEquals(tx.toString().contains("No inputs!"), true);
    }

    @Test
    public void testTheTXByHeightComparator() {
        Transaction tx1 = FakeTxBuilder.createFakeTx(UNITTEST);
        tx1.getConfidence().setAppearedAtChainHeight(1);

        Transaction tx2 = FakeTxBuilder.createFakeTx(UNITTEST);
        tx2.getConfidence().setAppearedAtChainHeight(2);

        Transaction tx3 = FakeTxBuilder.createFakeTx(UNITTEST);
        tx3.getConfidence().setAppearedAtChainHeight(3);

        SortedSet<Transaction> set = new TreeSet<>(Transaction.SORT_TX_BY_HEIGHT);
        set.add(tx2);
        set.add(tx1);
        set.add(tx3);

        Iterator<Transaction> iterator = set.iterator();

        assertEquals(tx1.equals(tx2), false);
        assertEquals(tx1.equals(tx3), false);
        assertEquals(tx1.equals(tx1), true);

        assertEquals(iterator.next().equals(tx3), true);
        assertEquals(iterator.next().equals(tx2), true);
        assertEquals(iterator.next().equals(tx1), true);
        assertEquals(iterator.hasNext(), false);
    }

    @Test(expected = ScriptException.class)
    public void testAddSignedInputThrowsExceptionWhenScriptIsNotToRawPubKeyAndIsNotToAddress() {
        ECKey key = new ECKey();
        Address addr = LegacyAddress.fromKey(UNITTEST, key);
        Transaction fakeTx = FakeTxBuilder.createFakeTx(UNITTEST, Coin.COIN, addr);

        Transaction tx = new Transaction(UNITTEST);
        tx.addOutput(fakeTx.getOutput(0));

        Script script = ScriptBuilder.createOpReturnScript(new byte[0]);

        tx.addSignedInput(fakeTx.getOutput(0).getOutPointFor(), script, key);
    }

    @Test
    public void testCoinbaseHeightCheck() throws VerificationException {
        // Coinbase transaction from block 300,000
        final byte[] transactionBytes = HEX.decode(
                "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4803e09304062f503253482f0403c86d53087ceca141295a00002e522cfabe6d6d7561cf262313da1144026c8f7a43e3899c44f6145f39a36507d36679a8b7006104000000000000000000000001c8704095000000001976a91480ad90d403581fa3bf46086a91b2d9d4125db6c188ac00000000");
        final int height = 300000;
        final Transaction transaction = UNITTEST.getDefaultSerializer().makeTransaction(transactionBytes);
        transaction.checkCoinBaseHeight(height);
    }

    /**
     * Test a coinbase transaction whose script has nonsense after the block height.
     * See https://github.com/bitcoinj/bitcoinj/issues/1097
     */
    @Test
    public void testCoinbaseHeightCheckWithDamagedScript() throws VerificationException {
        // Coinbase transaction from block 224,430
        final byte[] transactionBytes = HEX.decode(
            "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3b03ae6c0300044bd7031a0400000000522cfabe6d6d00000000000000b7b8bf0100000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff01e0587597000000001976a91421c0d001728b3feaf115515b7c135e779e9f442f88ac00000000");
        final int height = 224430;
        final Transaction transaction = UNITTEST.getDefaultSerializer().makeTransaction(transactionBytes);
        transaction.checkCoinBaseHeight(height);
    }

    @Test
    public void optInFullRBF() {
        // a standard transaction as wallets would create
        Transaction tx = FakeTxBuilder.createFakeTx(UNITTEST);
        assertFalse(tx.isOptInFullRBF());

        tx.getInputs().get(0).setSequenceNumber(TransactionInput.NO_SEQUENCE - 2);
        assertTrue(tx.isOptInFullRBF());
    }

    /**
     * Ensure that hashForSignature() doesn't modify a transaction's data, which could wreak multithreading havoc.
     */
    @Test
    public void testHashForSignatureThreadSafety() {
        Block genesis = UNITTEST.getGenesisBlock();
        Block block1 = genesis.createNextBlock(LegacyAddress.fromKey(UNITTEST, new ECKey()),
                    genesis.getTransactions().get(0).getOutput(0).getOutPointFor());

        final Transaction tx = block1.getTransactions().get(1);
        final String txHash = tx.getHashAsString();
        final String txNormalizedHash = tx.hashForSignature(
                0,
                new byte[0],
                Transaction.SigHash.ALL.byteValue())
                .toString();

        for (int i = 0; i < 100; i++) {
            // ensure the transaction object itself was not modified; if it was, the hash will change
            assertEquals(txHash, tx.getHashAsString());
            new Thread(){
                public void run() {
                    assertEquals(
                            txNormalizedHash,
                            tx.hashForSignature(
                                    0,
                                    new byte[0],
                                    Transaction.SigHash.ALL.byteValue())
                                    .toString());
                }
            };
        }
    }

    /**
     * Native P2WPKH transaction. From BIP-143.
     */
    @Test
    public void testNativeP2WPKH() {
        final byte[] unsignedTxBin = HEX.decode(
                "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf43354"
                + "1db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa8"
                + "9e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb2"
                + "06000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988"
                + "ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167f"
                + "aa815988ac11000000");
        final Transaction tx = new Transaction(MainNetParams.get(), unsignedTxBin);
        final byte[] input0 = HEX.decode(
                "4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d"
                + "114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede9"
                + "44ccf4ecbab4cc618ef3ed01");
        tx.getInput(0).setScriptBytes(input0);

        final Script scriptPubKey = new Script(HEX.decode(
                "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"));
        final Script scriptCode = scriptPubKey.scriptCode();
        final ECKey prvKey  = ECKey.fromPrivate(HEX.decode(
                "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9"));
        final Coin value = Coin.valueOf(6,0);

        final byte[] expectedSigHash = HEX.decode(
                "ab8b65f459483954031f62fa11aa5cee9f959be8f5d9854eabb016a11220ec20");
        final byte[] expectedSignature = HEX.decode(
                "304402205835965ae81db6ce5440e594db71db1276e0c0acee8721ddd76a2d140e6a99b90" +
                        "22003b84c0148a8ffbea38859b7ec3aaf156db4ff7037e7062546f4d75d20b173c1");

        final byte[] signedTx = HEX.decode(
                "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f" +
                        "00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c" +
                        "8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3" +
                        "ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a" +
                        "0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76" +
                        "ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa8159" +
                        "88ac000247304402205835965ae81db6ce5440e594db71db1276e0c0acee8721ddd76a2d140e" +
                        "6a99b9022003b84c0148a8ffbea38859b7ec3aaf156db4ff7037e7062546f4d75d20b173c141" +
                        "21025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000");

        final Sha256Hash sigHash = tx.hashForSignatureWitness(
            1, scriptCode, value, Transaction.SigHash.BCAFORK, false);
        assertArrayEquals(expectedSigHash, sigHash.getBytes());

        final TransactionSignature sig = tx.calculateWitnessSignature(
            1, prvKey, scriptCode, value, Transaction.SigHash.BCAFORK, false);
        assertArrayEquals(expectedSignature, sig.encodeToDER());

        final TransactionWitness witness = new TransactionWitness(2);
        witness.setPush(0, sig.encodeToBitcoin());
        witness.setPush(1, prvKey.getPubKey());

        tx.setWitness(1, witness);
        assertArrayEquals(signedTx, tx.bitcoinSerialize());

        tx.getInput(1).getScriptSig().correctlySpends(
            tx, 1, scriptPubKey, value, Script.ALL_VERIFY_FLAGS);
    }

    /**
     * P2WPKH nested in P2SH transaction. From BIP-143.
     */
    @Test
    public void testP2SHP2WPKH() {
        final byte[] unsignedTxBin = HEX.decode(
                "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac"
                + "4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457"
                + "b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976"
                + "a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000");
        final Transaction tx = new Transaction(MainNetParams.get(), unsignedTxBin);

        final Script scriptPubKey = new Script(HEX.decode(
                "a9144733f37cf4db86fbc2efed2500b4f4e49f31202387"));
        final Script redeemScript = new Script(HEX.decode(
                "001479091972186c449eb1ded22b78e40d009bdf0089"));
        final Script scriptCode = redeemScript.scriptCode();
        final ECKey prvKey  = ECKey.fromPrivate(HEX.decode(
                "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf"));
        final Coin value = Coin.valueOf(10,0);

        final byte[] expectedSigHash = HEX.decode(
                "5dbebc444e0ded2806e63de0e87c454667a480c4479213f6c3704386bd28a53c");
        final byte[] expectedSignature = HEX.decode(
                "304402203d1fa13f5ed940ea2f0c4541c70dedcf8f16ec4f074ce3b184540058429e37d2022079d4463a" +
                        "f8528ebfc1478adfe71ed1aff5ea057d3ca05eee726f9b17db39825141");

        final byte[] signedTx = HEX.decode(
                "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000" +
                        "01716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914" +
                        "a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcae" +
                        "a97fea7ad0402e8bd8ad6d77c88ac0247304402203d1fa13f5ed940ea2f0c4541c70dedcf8f16ec4f07" +
                        "4ce3b184540058429e37d2022079d4463af8528ebfc1478adfe71ed1aff5ea057d3ca05eee726f9b17d" +
                        "b398251412103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000");

        final Sha256Hash sigHash = tx.hashForSignatureWitness(
            0,
            scriptCode,
            value,
            Transaction.SigHash.BCAFORK,
            false);
        assertArrayEquals(expectedSigHash, sigHash.getBytes());

        final TransactionSignature sig = tx.calculateWitnessSignature(
            0, prvKey, scriptCode, value, Transaction.SigHash.BCAFORK, false);
        assertArrayEquals(expectedSignature, sig.encodeToBitcoin());

        final TransactionWitness witness = new TransactionWitness(2);
        witness.setPush(0, sig.encodeToBitcoin());
        witness.setPush(1, prvKey.getPubKey());

        tx.setWitness(0, witness);
        final ScriptBuilder sigScript = new ScriptBuilder();
        sigScript.data(redeemScript.getProgram());
        tx.getInput(0).setScriptBytes(sigScript.build().getProgram());
        assertArrayEquals(signedTx, tx.bitcoinSerialize());

        tx.getInput(0).getScriptSig().correctlySpends(
            tx, 0, scriptPubKey, value, Script.ALL_VERIFY_FLAGS);
    }

    /**
     * Native P2WPKH transaction using OP_CODESEPARATOR and SIGHASH_SINGLE. From BIP-143.
     */
    @Test
    public void testP2WPKHCodeSepSingle() {
        int opCodeSepLocation = 0;
        final byte[] unsignedTxBin = HEX.decode(
                "0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d"
                + "1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8"
                + "a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f205"
                + "2a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788"
                + "ac00000000");
        final Transaction tx = new Transaction(MainNetParams.get(), unsignedTxBin);
        final byte[] input0 = Script.createInputScript(HEX.decode(
                "304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3"
                + "aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae6221736709"
                + "6bc02ee5e435b67da201"));
        tx.getInput(0).setScriptBytes(input0);

        final Script scriptPubKey = new Script(HEX.decode(
                "00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0"));
        final Script witnessScript = new Script(HEX.decode(
                "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac70645"
                + "3880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086a"
                + "a8ced5e0d0215ea465ac"));
        final Coin value = Coin.valueOf(49,0);

        final ECKey prvKey0 = ECKey.fromPrivate(HEX.decode(
                "8e02b539b1500aa7c81cf3fed177448a546f19d2be416c0c61ff28e577d8d0cd"),
                true);

        final byte[] expectedSigHash0 = HEX.decode(
                "82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391");
        final byte[] expectedSignature0 = HEX.decode(
                "3044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3"
                + "789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286"
                + "963bb48517a7058e2703");

        final byte[] signedTx = HEX.decode(
                "01000000000102fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c"
                + "565d1c6b9216b36e000000004847304402200af4e47c9b9629dbecc21f73"
                + "af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb"
                + "1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201ffffffff08"
                + "15cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925"
                + "f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5a"
                + "cadf23f751864167f32e0963f788ac000347304402200de66acf4527789b"
                + "fda55fc5459e214fa6083f936b430a762c629656216805ac0220396f5506"
                + "92cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e50347"
                + "3044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9"
                + "e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c2"
                + "86963bb48517a7058e27034721026dccc749adc2a9d0d89497ac511f760f"
                + "45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e65"
                + "38428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac00000000");

        final Sha256Hash sigHash0 = tx.hashForSignatureWitness(
            1, witnessScript, value, Transaction.SigHash.SINGLE, false);
        assertArrayEquals(expectedSigHash0, sigHash0.getBytes());

        final TransactionSignature sig0 = tx.calculateWitnessSignature(
            1, prvKey0, witnessScript, value, Transaction.SigHash.SINGLE, false);
        assertArrayEquals(expectedSignature0, sig0.encodeToBitcoin());

        // Find OP_CODESEPARATOR
        for (ScriptChunk chunk: witnessScript.getChunks()) {
            if (chunk.equalsOpCode(OP_CODESEPARATOR)) {
                opCodeSepLocation = chunk.getStartLocationInProgram() + 1;
                break;
            }
        }
        assertNotEquals(0, opCodeSepLocation);

        final byte[] expectedScriptCodeBin1 = HEX.decode(
                "210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac");
        final byte[] scriptCodeBin1 = Arrays.copyOfRange(
            witnessScript.getProgram(), opCodeSepLocation, witnessScript.getProgram().length);
        assertArrayEquals(expectedScriptCodeBin1, scriptCodeBin1);

        final Script scriptCode1 = new Script(scriptCodeBin1);
        final ECKey prvKey1 = ECKey.fromPrivate(HEX.decode(
                "86bf2ed75935a0cbef03b89d72034bb4c189d381037a5ac121a70016db8896ec"), true);

        final byte[] expectedSigHash1 = HEX.decode(
                "fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47");
        final byte[] expectedSignature1 = HEX.decode(
                "304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c6296"
                + "56216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b3086"
                + "0dc77c8f78bc8501e503");

        final Sha256Hash sigHash1 = tx.hashForSignatureWitness(
            1, scriptCode1, value, Transaction.SigHash.SINGLE, false);
        assertArrayEquals(expectedSigHash1, sigHash1.getBytes());

        final TransactionSignature sig1 = tx.calculateWitnessSignature(
            1, prvKey1, scriptCode1, value, Transaction.SigHash.SINGLE, false);
        assertArrayEquals(expectedSignature1, sig1.encodeToBitcoin());

        final TransactionWitness witness = new TransactionWitness(3);
        witness.setPush(0, sig1.encodeToBitcoin());
        witness.setPush(1, sig0.encodeToBitcoin());
        witness.setPush(2, witnessScript.getProgram());

        tx.setWitness(1, witness);

        assertArrayEquals(signedTx, tx.bitcoinSerialize());

        tx.getInput(1).getScriptSig().correctlySpends(
            tx, 1, scriptPubKey, value, Script.ALL_VERIFY_FLAGS);
    }

    /**
     * Unexecuted OP_CODESEPARATOR. SINGLE|ANYONECANPAY does not commit to input index. From BIP-143.
     */
    @Test
    public void testSegwitNoExecCodeSep() {
        final byte[] unsignedTxBin = HEX.decode(
                "0100000002e9b542c5176808107ff1df906f46bb1f2583b16112b95ee53806"
                + "65ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7"
                + "b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff02809698"
                + "00000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888"
                + "ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237"
                + "294d1e88ac00000000");
        final Transaction tx = new Transaction(MainNetParams.get(), unsignedTxBin);
        final Script scriptPubKey0 = new Script(HEX.decode(
                "0020ba468eea561b26301e4cf69fa34bde4ad60c81e70f059f045ca9a79931004a4d"));
        final Script witnessScript0 = new Script(HEX.decode(
                "0063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac"));

        final Script scriptPubKey1 = new Script(HEX.decode(
                "0020d9bbfbe56af7c4b7f960a70d7ea107156913d9e5a26b0a71429df5e097ca6537"));
        final Script witnessScript1 = new Script(HEX.decode(
                "5163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac"));

        final Coin value = Coin.valueOf(16777215L);
        final ECKey prvKey = ECKey.fromPrivate(
                HEX.decode("f52b3484edd96598e02a9c89c4492e9c1e2031f471c49fd721fe68b3ce37780d"),
                true);

        final byte[] expectedSigHash0 = HEX.decode(
                "bb154395790612a11fc8ba40dc9fc2570e9baefb04b5364c0bb05f8046452362");
        final byte[] expectedSignature0 = HEX.decode(
                "3045022100cd7b5195e436ee40b55b4e3f0cff019943ccec46ce2a5ac7df12cb52ab01906" +
                        "402207fc86bf1c50957e62142c2b33e2e394d28a0eac2983a6b4a17aef3cb470acea483");

        final Sha256Hash sigHash0 = tx.hashForSignatureWitness(
                0,
                witnessScript0,
                value,
                Transaction.SigHash.SINGLE,
                true);

        assertArrayEquals(expectedSigHash0, sigHash0.getBytes());

        final TransactionSignature sig0 = tx.calculateWitnessSignature(
                0,
                prvKey,
                witnessScript0,
                value,
                Transaction.SigHash.SINGLE,
                true);

        assertArrayEquals(expectedSignature0, sig0.encodeToBitcoin());


        byte[] scriptCode1 = null;
        for (ScriptChunk chunk: witnessScript1.getChunks()) {
            if (chunk.equalsOpCode(OP_CODESEPARATOR)) {
                scriptCode1 = Arrays.copyOfRange(
                    witnessScript1.getProgram(),
                    chunk.getStartLocationInProgram() + 1,
                    witnessScript1.getProgram().length);
                break;
            }
        }

        final TransactionWitness witness0 = new TransactionWitness(2);
        witness0.setPush(0, sig0.encodeToBitcoin());
        witness0.setPush(1, witnessScript0.getProgram());
        tx.setWitness(0, witness0);

        final byte[] expectedSigHash1 = HEX.decode(
                "a8c6c1e1242e929bafe423f8609cef4ff9320ceef2aa6e4b7902f1c380762fc7");
        final byte[] expectedSignature1 = HEX.decode(
                "304402204acabbdf2f3b24549568850351cf878a4674eabaf232fb892d716281a" +
                        "a27fb04022052de98e380e8c8e54cecc0922e873cc6bbb704dbc8d5d1f3ac6c9c300d26ea4583");

        final Sha256Hash sigHash1 = tx.hashForSignatureWitness(
                1,
                scriptCode1,
                value,
                Transaction.SigHash.SINGLE,
                true);

        assertArrayEquals(expectedSigHash1, sigHash1.getBytes());

        final TransactionSignature sig1 = tx.calculateWitnessSignature(
                1,
                prvKey,
                scriptCode1,
                value,
                Transaction.SigHash.SINGLE,
                true);

        assertArrayEquals(expectedSignature1, sig1.encodeToBitcoin());

        final TransactionWitness witness1 = new TransactionWitness(2);
        witness1.setPush(0, sig1.encodeToBitcoin());
        witness1.setPush(1, witnessScript1.getProgram());
        tx.setWitness(1, witness1);

        final byte[] signedTx = HEX.decode(
                "01000000000102e9b542c5176808107ff1df906f46bb1f2583b16112b95ee53806" +
                        "65ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95" +
                        "c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000" +
                        "001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac8096980000000" +
                        "0001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac024830450221" +
                        "00cd7b5195e436ee40b55b4e3f0cff019943ccec46ce2a5ac7df12cb52ab019064" +
                        "02207fc86bf1c50957e62142c2b33e2e394d28a0eac2983a6b4a17aef3cb470acea" +
                        "483270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550" +
                        "447a4c3e39da98ac0247304402204acabbdf2f3b24549568850351cf878a4674eab" +
                        "af232fb892d716281aa27fb04022052de98e380e8c8e54cecc0922e873cc6bbb704" +
                        "dbc8d5d1f3ac6c9c300d26ea4583275163ab68210392972e2eb617b2388771abe272" +
                        "35fd5ac44af8e61693261550447a4c3e39da98ac00000000");

        assertArrayEquals(signedTx, tx.bitcoinSerialize());
    }

    /**
     * No FindAndDelete. From BIP-143.
     */
    @Test
    public void testNoFindAndDelete() {
        final byte[] unsignedTx = HEX.decode(
                "010000000169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab"
                + "38e1ac8387f14c1d000000ffffffff0101000000000000000000000000");
        final Transaction tx = new Transaction(MainNetParams.get(), unsignedTx);
        final Script scriptPubKey = new Script(HEX.decode(
                "00209e1be07558ea5cc8e02ed1d80c0911048afad949affa36d5c3951e3159dbea19"));
        final Script redeemScript = new Script(HEX.decode(
                "ad4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490e"
                + "dd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e3"
                + "9f59eaa46ff7f15ae626c53e01"));
        final Coin value = Coin.valueOf(200000L);

        final byte[] expectedSigHash = HEX.decode(
                "772ebfe89206efe3adab11c44a9a5206bcfba45c54f04ee29fc607f6452b5ac3");
        final Sha256Hash sigHash = tx.hashForSignatureWitness(
                0,
                redeemScript,
                value,
                Transaction.SigHash.BCAFORK,
                false);
        assertArrayEquals(expectedSigHash, sigHash.getBytes());

        final byte[] pubKey = HEX.decode("02a9781d66b61fb5a7ef00ac5ad5bc6ffc78be7b44a566e3c87870e1079368df4c");
        final byte[] sig = HEX.decode(
                "30450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d"
                + "891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e01");
        final TransactionWitness witness = new TransactionWitness(3);
        witness.setPush(0, sig);
        witness.setPush(1, pubKey);
        witness.setPush(2, redeemScript.getProgram());

        tx.setWitness(0, witness);

        final byte[] signedTx = HEX.decode(
                "0100000000010169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5d"
                + "acab38e1ac8387f14c1d000000ffffffff01010000000000000000034830"
                + "450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d"
                + "891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59"
                + "eaa46ff7f15ae626c53e012102a9781d66b61fb5a7ef00ac5ad5bc6ffc78"
                + "be7b44a566e3c87870e1079368df4c4aad4830450220487fb382c4974de3"
                + "f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95f"
                + "eb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e01"
                + "00000000");
        assertArrayEquals(signedTx, tx.bitcoinSerialize());
        tx.getInput(0).getScriptSig().correctlySpends(
            tx, 0, scriptPubKey, value,
            EnumSet.of(
                Script.VerifyFlag.P2SH,
                Script.VerifyFlag.STRICTENC,
                Script.VerifyFlag.DERSIG,
                Script.VerifyFlag.NULLDUMMY,
                Script.VerifyFlag.SIGPUSHONLY,
                Script.VerifyFlag.MINIMALDATA,
                Script.VerifyFlag.DISCOURAGE_UPGRADABLE_NOPS,
                Script.VerifyFlag.CLEANSTACK,
                Script.VerifyFlag.CHECKLOCKTIMEVERIFY)); // LOW_S should cannot be enforced on this signature
    }

    /**
     * Transaction weight calculation following BIP-141.
     */
    @Test
    public void testSegWitWeight() {
        final byte[] binaryTx = HEX.decode(
                "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf4"
                + "33541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b"
                + "02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9"
                + "281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffff"
                + "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90e"
                + "c68a0100000000ffffffff02202cb206000000001976a9148280b37df378"
                + "db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde"
                + "42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e1"
                + "7b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a02"
                + "20573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de6"
                + "7eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f6"
                + "2fc70f07aeee635711000000");
        final Transaction tx = new Transaction(MainNetParams.get(), binaryTx);

        final int baseSize;
        {
            final ByteArrayOutputStream base = new UnsafeByteArrayOutputStream();
            try {
                tx.bitcoinSerializeToStream(base, TransactionOptions.NONE);
            } catch (IOException e) {
                // Cannot happen, we are serializing to a memory stream
            }
            baseSize = base.size();
        }
        assertEquals(233, baseSize);

        final int totalSize;
        {
            final ByteArrayOutputStream total = new UnsafeByteArrayOutputStream();
            try {
                tx.bitcoinSerializeToStream(total, TransactionOptions.WITNESS);
            } catch (IOException e) {
                // Cannot happen, we are serializing to a memory stream
            }
            totalSize = total.size();
        }
        assertEquals(343, totalSize);

        assertEquals(233 * 3 + 343, tx.getWeight());
    }

    @Test
    public void testNoSegWitWeight() {
        final byte[] binaryTx = HEX.decode(
                "0100000001c36ca0f28b0fa5b56b20d69f3300c8e13b92db21d1f7965fb2b3"
                + "2e7c4eb85267000000006b483045022100fa8198bcb0e49ddd71ba2aa6a5"
                + "65db95db71338be8f971d4d39c5724f489e8bc02207e1cf456c7521ce552"
                + "3fe597ec50c196fd4b94b0381e693fc467602246490a08012103aa6309cb"
                + "e70e76597867806abe0751cf116bec865e374d445b6d85337a015bc0ffff"
                + "ffff027e090000000000001976a91424af560bbec150aeeea15ee798ad90"
                + "7c8b7b74cb88acf6d90600000000001976a9149a90ec63dba41ede9ada81"
                + "bb62a0a46ba59a16f888ac00000000");
        final Transaction tx = new Transaction(MainNetParams.get(), binaryTx);

        final int baseSize;
        {
            final ByteArrayOutputStream base = new UnsafeByteArrayOutputStream();
            try {
                tx.bitcoinSerializeToStream(base, TransactionOptions.NONE);
            } catch (IOException e) {
                // Cannot happen, we are serializing to a memory stream
            }
            baseSize = base.size();
        }
        assertEquals(226, baseSize);

        final int totalSize;
        {
            final ByteArrayOutputStream total = new UnsafeByteArrayOutputStream();
            try {
                tx.bitcoinSerializeToStream(total, TransactionOptions.WITNESS);
            } catch (IOException e) {
                // Cannot happen, we are serializing to a memory stream
            }
            totalSize = total.size();
        }
        assertEquals(226, totalSize);

        assertEquals(226 * 4, tx.getWeight());
    }
}