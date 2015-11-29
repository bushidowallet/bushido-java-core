package com.bushidowallet.core.bitcoin.tx.input;

import com.bushidowallet.core.bitcoin.bip32.ECKey;
import com.bushidowallet.core.bitcoin.script.Script;
import com.bushidowallet.core.bitcoin.tx.SigHash;
import com.bushidowallet.core.bitcoin.tx.Transaction;
import com.bushidowallet.core.bitcoin.tx.TransactionSignature;
import com.bushidowallet.core.bitcoin.tx.output.Output;
import com.bushidowallet.core.bitcoin.util.ByteReader;
import com.bushidowallet.core.bitcoin.util.ByteWriter;
import com.bushidowallet.core.crypto.util.ByteUtil;

import java.util.List;

/**
 * Created by Jesion on 2015-03-31.
 */
public class Input {

    public byte[] prevTxId;

    public int outputIndex;

    public Output output;

    public Script script;

    public long sequence;

    public Input() {

        //default
        sequence = Long.valueOf("4294967295");
    }

    public static Input fromByteReader(ByteReader reader) throws Exception {
        final Input inp = new Input();
        inp.prevTxId = ByteUtil.reverseBytes(reader.getBytes(32));
        inp.outputIndex = reader.getIntLE();
        long scriptLen = reader.getCompactInt();
        inp.script = Script.fromBytes(reader.getBytes((int) scriptLen));
        inp.sequence = reader.getUInt32();
        return inp;
    }

    public void write(ByteWriter writer) throws Exception {
        final byte[] prevTxIdReversed = ByteUtil.reverseBytes(prevTxId);
        writer.putBytes(prevTxIdReversed);
        writer.putIntLE(outputIndex);
        writer.putCompactInt(script.getBytes().length);
        writer.putBytes(script.getBytes());
        writer.putUInt32(sequence);
    }

    public int estimateSize() throws Exception {
        ByteWriter writer = new ByteWriter(0);
        write(writer);
        return writer.length();
    }

    public void addSignature(Transaction tx, TransactionSignature signature) throws Exception {

        throw new Exception("Abstract method invoked");
    }

    public List<TransactionSignature> getSignatures(Transaction tx, ECKey key, int index, int sigType, byte[] hashData) throws Exception {

        throw new Exception("Trying to sign unsupported output type only P2PKH and P2SH multisig inputs are supported");
    }

    public boolean isFullySigned() throws Exception {

        throw new Exception("Abstract method invoked");
    }

    public void clearSignatures() throws Exception {
        throw new Exception("Abstract method invoked");
    }

    public boolean isValidSignature(Transaction tx, TransactionSignature signature) throws Exception {
        return SigHash.verify(tx,
                signature.signature,
                signature.sigType,
                signature.publicKey,
                signature.publicKeyCompressed,
                signature.inputIndex,
                this.output.script
        );
    }
}
