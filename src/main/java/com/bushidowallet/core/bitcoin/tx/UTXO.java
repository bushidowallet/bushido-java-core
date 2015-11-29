package com.bushidowallet.core.bitcoin.tx;

import com.bushidowallet.core.bitcoin.script.Script;
import com.bushidowallet.core.crypto.util.ByteUtil;

/**
 * Created by Jesion on 2015-04-01.
 */
public class UTXO {

    public Script script;

    public long satoshis;

    public byte[] txId;

    public int outputIndex;

    public UTXO(UTXODescriptor descriptor) throws Exception {

        this.satoshis = descriptor.satoshis;
        this.txId = ByteUtil.fromHex(descriptor.txId);
        this.outputIndex = descriptor.outputIndex;
        this.script = Script.fromString(descriptor.script);
    }
}
