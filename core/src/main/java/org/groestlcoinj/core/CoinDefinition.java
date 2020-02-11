package org.groestlcoinj.core;

import org.groestlcoinj.net.discovery.HttpDiscovery;

import java.math.BigInteger;
import java.net.URI;
import java.util.Map;

/**
 * Created with IntelliJ IDEA.
 * User: HashEngineering
 * Date: 8/13/13
 * Time: 7:23 PM
 * To change this template use File | Settings | File Templates.
 */
public class CoinDefinition {


    public static final String coinName = "Groestlcoin";
    public static final String coinTicker = "GRS";
    public static final String coinURIScheme = "groestlcoin";
    public static final String cryptsyMarketId = "26";
    public static final String cryptsyMarketCurrency = "BTC";
    public static final String PATTERN_PRIVATE_KEY_START = "[56]";
    public static final String PATTERN_PRIVATE_KEY_START_COMPRESSED = "[KL]";
    public static final String PATTERN_PRIVATE_KEY_START_TESTNET = "9";
    public static final String PATTERN_PRIVATE_KEY_START_COMPRESSED_TESTNET = "c";

    public static String lowerCaseCoinName() { return coinName.toLowerCase(); }

    public static final String DONATION_ADDRESS = "FkknEYnex1MeZyPRnEebFK5ZBHHsFZbvaf";  //HashEngineering donation GRS address

    public static boolean checkpointFileSupport = true;
    public static int checkpointDaysBack = 21;

    public static final int TARGET_TIMESPAN = (int)(86400);  // 1 day per difficulty cycle, on average.
    public static final int TARGET_SPACING = (int)(1 * 60);  // 60 seconds per block.
    public static final int INTERVAL = TARGET_TIMESPAN / TARGET_SPACING;  //108 blocks

    public static final int getIntervalCheckpoints() {
            return 2016;    //1080

    }
    public static int spendableCoinbaseDepth = 120; //main.h: static const int CINBASE_MATURITY
    public static final int MAX_COINS = 105000000;                 //main.h:  MAX_MONEY


    public static final Coin DEFAULT_MIN_TX_FEE = Coin.valueOf(10000);   // MIN_TX_FEE
    public static final Coin DUST_LIMIT = Coin.valueOf(10000); //main.h CTransaction::GetMinFee        0.01 coins

    public static final int PROTOCOL_VERSION = 70002;          //version.h PROTOCOL_VERSION
    public static final int MIN_PROTOCOL_VERSION = 209;        //version.h MIN_PROTO_VERSION
    public static final int INIT_PROTO_VERSION = 209;            //version.h

    public static final int BLOCK_CURRENTVERSION = 112;   //CBlock::CURRENT_VERSION
    public static final int MAX_BLOCK_SIZE = 1 * 1000 * 1000;


    public static final boolean supportsBloomFiltering = true; //Requires PROTOCOL_VERSION 70000 in the client
    public static boolean supportsIrcDiscovery() {
        return PROTOCOL_VERSION <= 70000;
    }

    public static final int Port    = 1331;       //protocol.h GetDefaultPort(testnet=false)
    public static final int TestPort = 17777;     //protocol.h GetDefaultPort(testnet=true)

    //
    //  Production
    //
    public static final int AddressHeader = 36;             //base58.h CBitcoinAddress::PUBKEY_ADDRESS
    public static final int p2shHeader = 5;             //base58.h CBitcoinAddress::SCRIPT_ADDRESS
    public static final long PacketMagic = 0xf9beb4d4;      //0xf9, 0xbe, 0xb4, 0xd4

    //Genesis Block Information from main.cpp: LoadBlockIndex
    static public long genesisBlockDifficultyTarget = (0x1e0fffffL);         //main.cpp: LoadBlockIndex
    static public long genesisBlockTime = 1395342829L;                       //main.cpp: LoadBlockIndex
    static public long genesisBlockNonce = (220035);                         //main.cpp: LoadBlockIndex
    static public String genesisHash = "00000ac5927c594d49cc0bdb81759d0da8297eb614683d3acb62f0703b639023"; //main.cpp: hashGenesisBlock
    static public int genesisBlockValue = 0;
    static public int genesisBlockVersion = 112; //main.cpp: LoadBlockIndex
    //taken from the raw data of the block explorer

    static public String genesisTxInBytes = "04ffff001d0104325072657373757265206d75737420626520707574206f6e20566c6164696d697220507574696e206f766572204372696d6561";   //"Digitalcoin, A Currency for a Digital Age"
    static public String genesisTxOutBytes = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f";



    static public String genesisMerkleRoot = "3ce968df58f9c8a752306c4b7264afab93149dbc578bd08a42c446caaa6628bb";


     // "Pressure must be put on Vladimir Putin over Crimea"


    //net.cpp strDNSSeed
    static public String[] dnsSeeds = new String[] {
            "dnsseed1.groestlcoin.org",
            "dnsseed2.groestlcoin.org",
            "dnsseed3.groestlcoin.org",
            "dnsseed4.groestlcoin.org",
            "groestlsight.groestlcoin.org",
            "groestlcoin.org",
            "electrum1.groestlcoin.org",
            "electrum2.groestlcoin.org",
            "electrum20.groestlcoin.org",
            "jswallet.groestlcoin.org",
    };

    public static final HttpDiscovery.Details[] httpSeeds = new HttpDiscovery.Details[] {
            new HttpDiscovery.Details(
                    ECKey.fromPublicOnly(Utils.HEX.decode("0248876142c407e9a05a07f96caf212eb5b54b68845ddee44739094b02e24d13e4")),
                    URI.create("http://groestlcoin.org:8080/peers")
            )
    };

    public static final int[] addrSeeds = new int[] {
            0x68EC82DE,
            0x68EC85C4,
            0x68ECB2F5,
            0x904CEF42,
            0x95D2E231,
            0xBC8648D5,
            0xC06306CF,
            0xC18862B8,
            0xC6C7692B,
            0xD2BA3B44,
            0x1715CC22,
            0x253B180F,
            0x2A738931,
            0x05092709,
            0x36DF4CA5,
            0x482E98FA,
            0x4C707B0D,
            0x535418B4,
            0x5402225E,
            0x5762B9F4,
            0x5E17217A,
            0x5E1737D3,
            0x5F85745C,
            0x5F85782F};

    public static int minBroadcastConnections = 1;   //0 for default; we need more peers.

    //
    // TestNet
    //
    public static final boolean supportsTestNet = true;
    public static final int testnetAddressHeader = 111;             //base58.h CBitcoinAddress::PUBKEY_ADDRESS_TEST
    public static final int testnetp2shHeader = 196;             //base58.h CBitcoinAddress::SCRIPT_ADDRESS_TEST
    public static final long testnetPacketMagic = 0x0b110907;      //0xfc, 0xc1, 0xb7, 0xdc
    public static final String testnetGenesisHash = "000000ffbb50fc9898cdd36ec163e6ba23230164c0052a28876255b7dcf2cd36";
    static public long testnetGenesisBlockDifficultyTarget = (0x1e00ffffL);         //main.cpp: LoadBlockIndex
    static public long testnetGenesisBlockTime = 1440000002L;                       //main.cpp: LoadBlockIndex
    static public long testnetGenesisBlockNonce = (6556309);                         //main.cpp: LoadBlockIndex

    //main.cpp GetBlockValue(height, fee)
    public static final Coin GetBlockReward(int height)
    {
        int COIN = 1;
        Coin nSubsidy = Coin.valueOf(15, 0);
        return nSubsidy.shiftRight(height / subsidyDecreaseBlockCount);
    }
    static final Coin nGenesisBlockRewardCoin = Coin.valueOf(1,0);
    static final Coin minimumSubsidy = Coin.valueOf(5,0);
    static final Coin nPremine = Coin.valueOf(240640,0);

    public static Coin GetBlockSubsidy(int nHeight){


        if (nHeight == 0)
        {
            return nGenesisBlockRewardCoin;
        }

        if (nHeight == 1)
        {
            return nPremine;
		/*
		optimized standalone cpu miner 	60*512=30720
		standalone gpu miner 			120*512=61440
		first pool			 			70*512 =35840
		block-explorer		 			60*512 =30720
		mac wallet binary    			30*512 =15360
		linux wallet binary  			30*512 =15360
		web-site						100*512	=51200
		total									=240640
		*/
        }

        Coin nSubsidy = Coin.valueOf(512);

        // Subsidy is reduced by 6% every 10080 blocks, which will occur approximately every 1 week
        int exponent=(nHeight / 10080);
        for(int i=0;i<exponent;i++){
            nSubsidy=nSubsidy.multiply(47);
            nSubsidy=nSubsidy.divide(50);
        }
        if(nSubsidy.compareTo(minimumSubsidy) < 0) {nSubsidy=minimumSubsidy;}
        return nSubsidy;
    }
    Coin GetBlockSubsidy120000(int nHeight)
    {
        // Subsidy is reduced by 10% every day (1440 blocks)
        Coin nSubsidy = Coin.valueOf(250,0);
        int exponent = ((nHeight - 120000) / 1440);
        for(int i=0; i<exponent; i++)
            nSubsidy = nSubsidy.multiply(45).divide(50);

        return nSubsidy;
    }

    Coin GetBlockSubsidy150000(int nHeight)
    {
        // Subsidy is reduced by 1% every week (10080 blocks)
        Coin nSubsidy = Coin.valueOf(25,0);
        int exponent = ((nHeight - 150000) / 10080);
        for(int i=0; i<exponent; i++)
            nSubsidy = (nSubsidy.multiply(99).divide(100));

        return nSubsidy.compareTo(minimumSubsidy) < 0 ? minimumSubsidy : nSubsidy;
    }

    public Coin GetBlockValue(int nHeight)
    {
        if(nHeight >= 150000)
            return GetBlockSubsidy150000(nHeight);

        if(nHeight >= 120000)
            return GetBlockSubsidy120000(nHeight);

        return GetBlockSubsidy(nHeight);
    }

    public static int subsidyDecreaseBlockCount = 4730400;     //main.cpp GetBlockValue(height, fee)

    public static BigInteger proofOfWorkLimit = Utils.decodeCompactBits(0x1e0fffffL);  //main.cpp bnProofOfWorkLimit (~uint256(0) >> 20); // groestlcoin: starting difficulty is 1 / 2^12

    static public String[] testnetDnsSeeds = new String[] {
            "testnet-seed1.groestlcoin.org",
            "testnet-seed2.groestlcoin.org",
            "testnet1.groestlcoin.org",
            "testnet2.groestlcoin.org"
    };
    //from main.h: CAlert::CheckSignature
    public static final String SATOSHI_KEY = "04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284";
    public static final String TESTNET_SATOSHI_KEY = "04302390343f91cc401d56d68b123028bf52e5fca1939df127f63c6467cdf9c8e2c14b61104cf817d0b780da337893ecc4aaff1309e536162dabbdb45200ca2b0a";

    /** The string returned by getId() for the main, production network where people trade things. */
    public static final String ID_MAINNET = "org.groestlcoin.production";
    /** The string returned by getId() for the testnet. */
    public static final String ID_TESTNET = "org.groestlcoin.test";
    /** Unit test network. */
    public static final String ID_UNITTESTNET = "com.google.groestlcoin.unittest";

    //checkpoints.cpp Checkpoints::mapCheckpoints
    public static void initCheckpoints(Map<Integer, Sha256Hash> checkpoints)
    {
        checkpoints.put( 0, Sha256Hash.wrap(CoinDefinition.genesisHash));
        checkpoints.put( 28888, Sha256Hash.wrap("00000000000228ce19f55cf0c45e04c7aa5a6a873ed23902b3654c3c49884502"));
        checkpoints.put( 58888, Sha256Hash.wrap("0000000000dd85f4d5471febeb174a3f3f1598ab0af6616e9f266b56272274ef"));
        checkpoints.put(111111, Sha256Hash.wrap("00000000013de206275ee83f93bee57622335e422acbf126a37020484c6e113c"));
        checkpoints.put(222222, Sha256Hash.wrap("00000000077f5f09288285b68d68636e652f672279ba6a014fdc404fe902a631"));
        checkpoints.put(333333, Sha256Hash.wrap("00000000121e477df65543cd7289c4790ad6fee6cfa48b4391cc594141356d5f"));
        checkpoints.put(444444, Sha256Hash.wrap("0000000029558b975a9507a32895735b9d9437308fa3302e02ca3103d61d6447"));
        checkpoints.put(555555, Sha256Hash.wrap("000000000d62c3e8b8983f21b86123a5deea9ebabd162c6b13428e92866a6c1f"));
        checkpoints.put(666666, Sha256Hash.wrap("000000000603db2b89e2194214d41ccff6d1181e2d80774cf65d834e5bbd8ea1"));
        checkpoints.put(777777, Sha256Hash.wrap("00000000000649a9cd35bc39ab705379139cd72142dcba83c79ca425bc399c0b"));
        checkpoints.put(888888, Sha256Hash.wrap("000000000cce6537f3d8b22ab70a9925ba34bd9a9f850c9644f69d11ba0393e9"));
        checkpoints.put(917000, Sha256Hash.wrap("0000000012fe97c83a908d3217ce2df025fb8ba32c88bd86a14eb329e6c7259d"));
    }

    //Unit Test Information
    public static final String UNITTEST_ADDRESS = "FmpNNw388tMqsDkKW6KfyksRkCVWqjBSCe";
    public static final String UNITTEST_ADDRESS_PRIVATE_KEY = "QU1rjHbrdJonVUgjT7Mncw7PEyPv3fMPvaGXp9EHDs1uzdJ98hUZ";

}
