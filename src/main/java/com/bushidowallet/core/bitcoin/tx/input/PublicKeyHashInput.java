package com.bushidowallet.core.bitcoin.tx.input;

import com.bushidowallet.core.bitcoin.bip32.ECKey;
import com.bushidowallet.core.bitcoin.script.Script;
import com.bushidowallet.core.bitcoin.tx.SigHash;
import com.bushidowallet.core.bitcoin.tx.Transaction;
import com.bushidowallet.core.bitcoin.tx.TransactionSignature;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by Jesion on 2015-04-01.
 */
public class PublicKeyHashInput extends Input {

    private static int SCRIPT_MAX_SIZE = 73 + 34;

    @Override
    public int estimateSize() throws Exception {
        return SCRIPT_MAX_SIZE;
    }

    @Override
    public List<TransactionSignature> getSignatures(Transaction tx, ECKey key, int index, int sigType, byte[] hashData) throws Exception {
        List<TransactionSignature> signatures = new ArrayList<TransactionSignature>();
        if (Arrays.equals(hashData, this.output.script.getPublicKeyHash())) {
            signatures.add(
                new TransactionSignature(key.getPublic(),
                        key.isCompressed(),
                        this.prevTxId,
                        this.outputIndex,
                        index,
                        SigHash.sign(tx, key, sigType, index, this.output.script),
                        sigType
                )
            );
        }
        return signatures;
    }

    @Override
    public void addSignature(Transaction tx, TransactionSignature signature) throws Exception {
        boolean isValidSig = isValidSignature(tx, signature);
        if (isValidSig == false) {
            throw new Exception("Signature not valid against Tx provided");
        }
        this.script = Script.buildPublicKeyHashIn(signature.publicKey, signature.signature.toDER(), signature.sigType);
    }

    @Override
    public boolean isFullySigned() throws Exception {
        return this.script.isPublicKeyHashIn();
    }

    @Override
    public void clearSignatures() {
        this.script = new Script();
    }
}
