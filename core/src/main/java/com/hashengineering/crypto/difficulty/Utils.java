package com.hashengineering.crypto.difficulty;

import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;

/**
 * Created by Hash Engineering Solutions on 6/4/14.
 */
public class Utils {
    public static double ConvertBitsToDouble(long nBits){
        long nShift = (nBits >> 24) & 0xff;

        double dDiff =
                (double)0x0000ffff / (double)(nBits & 0x00ffffff);

        while (nShift < 29)
        {
            dDiff *= 256.0;
            nShift++;
        }
        while (nShift > 29)
        {
            dDiff /= 256.0;
            nShift--;
        }

        return dDiff;
    }

    public static double getNetworkHashRate(StoredBlock currentBlock, BlockStore blockStore)
    {
        double totalHash = 0.0;
        long totalTime = 0;
        long lastTime = currentBlock.getHeader().getTimeSeconds();
        double lastDiff = ConvertBitsToDouble(currentBlock.getHeader().getDifficultyTarget());

        StoredBlock block = currentBlock;
        for (int i = 0; i < 10; ++i)
        {
            try {
                block = block.getPrev(blockStore);

                if(block == null)
                    return 0.0;
            }
            catch(BlockStoreException x)
            {
                return 0.0;
            }
            totalHash += lastDiff * (lastTime - block.getHeader().getTimeSeconds());
            totalTime += lastTime - block.getHeader().getTimeSeconds();
            lastTime = block.getHeader().getTimeSeconds();
            lastDiff = ConvertBitsToDouble(block.getHeader().getDifficultyTarget());
        }
        return ((totalHash * Math.pow(2.0, 32)) / totalTime)/(totalTime/10);
    }
}
