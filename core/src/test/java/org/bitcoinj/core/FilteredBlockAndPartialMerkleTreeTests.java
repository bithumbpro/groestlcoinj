/*
 * Copyright 2012 Matt Corallo
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

import com.google.common.collect.*;
import org.bitcoinj.core.TransactionConfidence.*;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.store.*;
import org.bitcoinj.testing.*;
import org.bitcoinj.wallet.*;
import org.junit.*;
import org.junit.runner.*;
import org.junit.runners.*;

import java.math.*;
import java.util.*;

import static org.bitcoinj.core.Utils.*;
import static org.junit.Assert.*;

@RunWith(value = Parameterized.class)
public class FilteredBlockAndPartialMerkleTreeTests extends TestWithPeerGroup {
    @Parameterized.Parameters
    public static Collection<ClientType[]> parameters() {
        return Arrays.asList(new ClientType[] {ClientType.NIO_CLIENT_MANAGER},
                new ClientType[] {ClientType.BLOCKING_CLIENT_MANAGER});
    }

    public FilteredBlockAndPartialMerkleTreeTests(ClientType clientType) {
        super(clientType);
    }

    @Before
    public void setUp() throws Exception {
        context = new Context(UNITTEST);
        MemoryBlockStore store = new MemoryBlockStore(UNITTEST);

        // Cheat and place the previous block (block 100000) at the head of the block store without supporting blocks
        store.put(new StoredBlock(new Block(UNITTEST, HEX.decode("00000020eff05a7f24b85e6daced3be816b88d29dd1787b3a538ff8bf06c892200000000cb27b6b0b2e1ef25ab5fb466b8d55236273287fbb5145b183d8b155522a460a4d31da15a2d3c2b1cee976a1700000000")),
                BigInteger.valueOf(1), 1595000, 1595000));
        store.setChainHead(store.get(Sha256Hash.wrap("000000000d63932ab4735e780773eceff160068308cf1cfca7b68b6c72000129")));

        KeyChainGroup group = new KeyChainGroup(UNITTEST);
        group.importKeys(ECKey.fromPublicOnly(HEX.decode("04b27f7e9475ccf5d9a431cb86d665b8302c140144ec2397fce792f4a4e7765fecf8128534eaa71df04f93c74676ae8279195128a1506ebf7379d23dab8fca0f63")),
                ECKey.fromPublicOnly(HEX.decode("04732012cb962afa90d31b25d8fb0e32c94e513ab7a17805c14ca4c3423e18b4fb5d0e676841733cb83abaf975845c9f6f2a8097b7d04f4908b18368d6fc2d68ec")),
                ECKey.fromPublicOnly(HEX.decode("04cfb4113b3387637131ebec76871fd2760fc430dd16de0110f0eb07bb31ffac85e2607c189cb8582ea1ccaeb64ffd655409106589778f3000fdfe3263440b0350")),
                ECKey.fromPublicOnly(HEX.decode("04b2f30018908a59e829c1534bfa5010d7ef7f79994159bba0f534d863ef9e4e973af6a8de20dc41dbea50bc622263ec8a770b2c9406599d39e4c9afe61f8b1613")));
        wallet = new Wallet(UNITTEST, group);

        super.setUp(store);
    }

    @After
    public void tearDown() {
        super.tearDown();
    }

    @Test
    public void deserializeFilteredBlock() throws Exception {
        // Random real block (000000000000dab0130bbcc991d3d7ae6b81aa6f50a798888dfe62337458dc45)
        // With one tx
        FilteredBlock block = new FilteredBlock(TestNet3Params.get(), HEX.decode("00000020eaaa1c149bde69ed4a686080b9fb2af2755a16bee942e31cc0e8d41400000000070525c409d534969e52bceadad0c9f2801086b4c56e3bfd42d330a643e7fd3fbda5f65acc7b1f1ca5486b5c000000800100000001070525c409d534969e52bceadad0c9f2801086b4c56e3bfd42d330a643e7fd3f0100"));

        // Check that the header was properly deserialized
        assertTrue(block.getBlockHeader().getHash().equals(Sha256Hash.wrap("0000000007922f5e6122d35fb07325782c3251f2edc05c7f6a743bbcd0e938a6")));

        // Check round tripping.
        assertEquals(block, new FilteredBlock(TestNet3Params.get(), block.bitcoinSerialize()));
    }

    @Test
    public void createFilteredBlock() throws Exception {
        ECKey key1 = new ECKey();
        ECKey key2 = new ECKey();
        Transaction tx1 = FakeTxBuilder.createFakeTx(UNITTEST, Coin.COIN, SegwitAddress.fromKey(UNITTEST, key2));
        Transaction tx2 = FakeTxBuilder.createFakeTx(UNITTEST, Coin.FIFTY_COINS, SegwitAddress.fromKey(UNITTEST, key2));

        Block block = FakeTxBuilder.makeSolvedTestBlock(UNITTEST.getGenesisBlock(), LegacyAddress.fromBase58(UNITTEST, "msg2t2V2sWNd85LccoddtWysBTR8oPnkzW"), tx1, tx2);
        BloomFilter filter = new BloomFilter(4, 0.1, 1);
        filter.insert(key1);
        filter.insert(key2);
        FilteredBlock filteredBlock = filter.applyAndUpdate(block);
        assertEquals(4, filteredBlock.getTransactionCount());
        // This call triggers verification of the just created data.
        List<Sha256Hash> txns = filteredBlock.getTransactionHashes();
        assertTrue(txns.contains(tx1.getHash()));
        assertTrue(txns.contains(tx2.getHash()));
    }

    private Sha256Hash numAsHash(int num) {
        byte[] bits = new byte[32];
        bits[0] = (byte) num;
        return Sha256Hash.wrap(bits);
    }

    @Test(expected = VerificationException.class)
    public void merkleTreeMalleability() throws Exception {
        List<Sha256Hash> hashes = Lists.newArrayList();
        for (byte i = 1; i <= 10; i++) hashes.add(numAsHash(i));
        hashes.add(numAsHash(9));
        hashes.add(numAsHash(10));
        byte[] includeBits = new byte[2];
        Utils.setBitLE(includeBits, 9);
        Utils.setBitLE(includeBits, 10);
        PartialMerkleTree pmt = PartialMerkleTree.buildFromLeaves(UNITTEST, includeBits, hashes);
        List<Sha256Hash> matchedHashes = Lists.newArrayList();
        pmt.getTxnHashAndMerkleRoot(matchedHashes);
    }
}
