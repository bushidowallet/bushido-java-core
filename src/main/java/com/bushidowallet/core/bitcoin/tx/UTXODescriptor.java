package com.bushidowallet.core.bitcoin.tx;

/**
 * Created by Jesion on 2015-03-31.
 *
 * This is a helper, see if we can remove this and use UTXO
 */
public class UTXODescriptor {

    public String txId;

    public int outputIndex;

    public String script;

    public long satoshis;

    public UTXODescriptor(String txId, int outputIndex, String script, long satoshis) {

        this.txId = txId;
        this.outputIndex = outputIndex;
        this.script = script;
        this.satoshis = satoshis;
    }

    public UTXODescriptor() {

    }
}
