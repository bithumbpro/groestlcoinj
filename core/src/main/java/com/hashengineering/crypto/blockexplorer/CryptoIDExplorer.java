package com.hashengineering.crypto.blockexplorer;

/**
 * Created by Hash Engineering on 1/21/2016.
 *
 * https://chainz.cryptoid.info/
 */
public class CryptoIDExplorer extends BlockExplorer {

    String apiKey = "&key=d47da926b82e";
    public CryptoIDExplorer(String url)
    {
        super(url, "block.dws?", "tx.dws?", "address.dws?", "api.dws?q=unspent");
        api = APIType.Cryptoid;
    }

    @Override
    public String getUnspentUrl(String address)
    {
        return url + pathForUnspent + apiKey + "&active="+address;
    }
}
