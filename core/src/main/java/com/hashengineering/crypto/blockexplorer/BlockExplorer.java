package com.hashengineering.crypto.blockexplorer;

/**
 * Created by Hash Engineering on 1/21/2016.
 */
public class BlockExplorer {
    String url;
    String pathForBlock;
    String pathForTx;
    String pathForAddress;
    String pathForUnspent;

    public enum APIType {
        BitEasy,
        Blockr,
        Abe,
        Cryptoid,
    };

    public APIType api = APIType.Abe;

    public BlockExplorer(String url, String pathForBlock, String pathForTx, String pathForAddress)
    {
        this.url = url;
        this.pathForAddress = pathForAddress;
        this.pathForTx = pathForTx;
        this.pathForBlock = pathForBlock;
    }

    public BlockExplorer(String url, String pathForBlock, String pathForTx, String pathForAddress, String pathForUnspent)
    {
        this.url = url;
        this.pathForAddress = pathForAddress;
        this.pathForTx = pathForTx;
        this.pathForBlock = pathForBlock;
        this.pathForUnspent = pathForUnspent;
    }

    public String getUrl()
    {
        return url;
    }

    public String getBlockUrl()
    {
        return url + pathForBlock;
    }

    public String getTxUrl()
    {
        return url + pathForTx;
    }

    public String getAddressUrl()
    {
        return url + pathForAddress;
    }

    public String getUnspentUrl(String address)
    {
        return url + pathForUnspent + address;
    }

}
