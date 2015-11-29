package com.bushidowallet.core.bitcoin.tx;

import com.bushidowallet.core.bitcoin.ecdsa.ECDSASignature;

/**
 * Created by Jesion on 2015-04-08.
 */
public class TransactionSignature {

    public static int SIGHASH_ALL = 0x01;
    public static int SIGHASH_NONE = 0x02;
    public static int SIGHASH_SINGLE = 0x03;
    public static int SIGHASH_ANYONECANPAY = 0x80;

    public int inputIndex;
    public int outputIndex;
    public byte[] publicKey;
    public boolean publicKeyCompressed;
    public byte[] prevTxId;
    public ECDSASignature signature;
    public int sigType;

    public TransactionSignature() {

    }

    public TransactionSignature(byte[] publicKey, boolean publicKeyCompressed, byte[] prevTxId, int outputIndex, int inputIndex, ECDSASignature signature, int sigType) {
        this.publicKey = publicKey;
        this.publicKeyCompressed = publicKeyCompressed;
        this.prevTxId = prevTxId;
        this.outputIndex = outputIndex;
        this.inputIndex = inputIndex;
        this.signature = signature;
        this.sigType = sigType;
    }
}
