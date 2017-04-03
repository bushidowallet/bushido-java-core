package com.bushidowallet.core.bitcoin.tx.input;

import com.bushidowallet.core.bitcoin.bip32.ECKey;
import com.bushidowallet.core.bitcoin.script.Script;
import com.bushidowallet.core.bitcoin.tx.SigHash;
import com.bushidowallet.core.bitcoin.tx.Transaction;
import com.bushidowallet.core.bitcoin.tx.TransactionSignature;
import com.bushidowallet.core.bitcoin.tx.output.Output;
import com.bushidowallet.core.crypto.util.ByteUtil;

import java.util.*;

/**
 * Created by Jesion on 2015-04-14.
 */
public class MultiSigScriptHashInput extends Input {

    public List<ECKey> publicKeys;

    public Map<String, Integer> publicKeyIndex;

    public int treshold;

    // in order to map a transaction signature to its public key's index
    public Map<Integer, TransactionSignature> signatures;

    public Script redeemScript;

    public MultiSigScriptHashInput(Output output,
                                   byte[] prevTxId,
                                   int outputIndex,
                                   Script script,
                                   List<ECKey> publicKeys,
                                   int treshold,
                                   Map<Integer, TransactionSignature> signatures) throws Exception {
        this.output = output;
        this.prevTxId = prevTxId;
        this.outputIndex = outputIndex;
        this.script = script;
        this.publicKeys = publicKeys;
        this.publicKeyIndex = new HashMap<String, Integer>();
        for (int i = 0; i < publicKeys.size(); i++) {
            publicKeyIndex.put(publicKeys.get(i).getPublicHex(), i);
        }
        this.treshold = treshold;
        this.redeemScript = Script.buildMultisigOut(this.publicKeys, treshold);
        if (signatures != null) {
            this.signatures = signatures;
        } else {
            this.signatures = new HashMap<Integer, TransactionSignature>();
        }
        if (Script.buildScriptHashOut(this.redeemScript).equals(output.script) == false) {
            throw new Exception("Provided public keys don't hash to the provided output");
        }
    }

    public int countSignatures() {
        if (signatures != null) {
            return signatures.size();
        }
        return 0;
    }

    public int countMissingSignatures() {
        return this.treshold - this.countSignatures();
    }

    @Override
    public List<TransactionSignature> getSignatures(Transaction tx, ECKey key, int index, int sigType, byte[] hashData) throws Exception {
        List<TransactionSignature> signatures = new ArrayList<TransactionSignature>();
        for (ECKey publicKey : publicKeys) {
            if (Arrays.equals(publicKey.getPublic(), key.getPublic())) {
                TransactionSignature s = new TransactionSignature();
                s.publicKey = key.getPublic();
                s.prevTxId = this.prevTxId;
                s.outputIndex = this.outputIndex;
                s.inputIndex = index;
                s.signature = SigHash.sign(tx, key, sigType, index, redeemScript);
                s.sigType = sigType;
                s.publicKeyCompressed = key.isCompressed();
                signatures.add(s);
            }
        }
        return signatures;
    }

    public void addSignature(Transaction tx, TransactionSignature signature) throws Exception {
        if (isFullySigned() == false) {
            if (this.publicKeyIndex.get(ByteUtil.toHex(signature.publicKey)) != null) {
                if (isValidSignature(tx, signature)) {
                    int index = this.publicKeyIndex.get(ByteUtil.toHex(signature.publicKey));
                    signatures.put(index, signature);
                    updateScript();
                } else {
                    throw new Exception("Attempting to add an invalid signature");
                }
            } else {
                throw new Exception("Signature has no matching public key");
            }
        } else {
            throw new Exception("All needed signatures have already been added");
        }
    }

    private void updateScript() throws Exception {
        this.script = Script.buildP2SHMultisigIn(publicKeys,
            treshold,
            createSignatures(),
            this.redeemScript
        );
    }

    private List<byte[]> createSignatures() {
        final List<byte[]> sigBytes = new ArrayList<byte[]>();
        Iterator it = this.signatures.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry pair = (Map.Entry) it.next();
            TransactionSignature txSig = (TransactionSignature) pair.getValue();
            byte[] sigDER = txSig.signature.toDER();
            int sigType = txSig.sigType;
            byte[] sigTypeBytes = new byte[1];
            sigTypeBytes[0] = (byte) (sigType & 0xff);
            byte[] signature = new byte[sigDER.length + 1];
            System.arraycopy(sigDER, 0, signature, 0, sigDER.length);
            System.arraycopy(sigTypeBytes, 0, signature, sigDER.length, 1);
            sigBytes.add(signature);
        }
        return sigBytes;
    }

    @Override
    public void clearSignatures() throws Exception {
        this.signatures.clear();
        updateScript();
    }

    @Override
    public boolean isFullySigned() throws Exception {
        return countSignatures() == treshold;
    }

    @Override
    public boolean isValidSignature(Transaction tx, TransactionSignature signature) throws Exception {
        return SigHash.verify(tx,
                signature.signature,
                signature.sigType,
                signature.publicKey,
                signature.publicKeyCompressed,
                signature.inputIndex,
                this.redeemScript
        );
    }

    public List<ECKey> publicKeysWithoutSignature() {
        List<ECKey> keys = new ArrayList<ECKey>();
        for (int i = 0; i < publicKeys.size(); i++) {
            int index = publicKeyIndex.get(publicKeys.get(i).getPublicHex());
            TransactionSignature sig = null;
            if (index < signatures.size()) {
                sig = signatures.get(index);
            }
            if (sig == null) {
                keys.add(publicKeys.get(i));
            }
        }
        return keys;
    }
}
