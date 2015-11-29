package com.bushidowallet.core.bitcoin.tx;

import com.bushidowallet.core.bitcoin.bip32.ECKey;
import com.bushidowallet.core.bitcoin.bip32.Hash;
import com.bushidowallet.core.bitcoin.ecdsa.ECDSA;
import com.bushidowallet.core.bitcoin.ecdsa.ECDSASignature;
import com.bushidowallet.core.bitcoin.script.Script;
import com.bushidowallet.core.bitcoin.tx.input.Input;
import com.bushidowallet.core.bitcoin.tx.output.Output;
import com.bushidowallet.core.bitcoin.util.ByteWriter;
import com.bushidowallet.core.crypto.util.ByteUtil;

import java.math.BigInteger;
import java.util.ArrayList;

/**
 * Created by Jesion on 2015-04-08.
 */
public class SigHash {

    private static String SIGHASH_SINGLE_BUG = "0000000000000000000000000000000000000000000000000000000000000001";
    private static String BITS_64_ON = "ffffffffffffffff";

    /**
     * Generates a Tx signature hash. Warning, this is only tested for sig type SIGHASH_ALL
     * When we move over to SIGHASH_SINGLE and SIGHASH_NONE, put in more unit tests around
     *
     * @param tx
     * @param sigType
     * @param index
     * @param script
     * @return
     * @throws Exception
     */
    private static byte[] sighash(Transaction tx, int sigType, int index, Script script) throws Exception {
        Transaction txCopy = new Transaction(tx.uncheckedSerialize());
        Script scriptCopy = Script.fromBytes(script.getBytes());
        scriptCopy.removeCodeSeparators();
        for (int i = 0; i < txCopy.inputs.size(); i++) {
            Input input = txCopy.inputs.get(i);
            input.script = new Script();
        }
        txCopy.inputs.get(index).script = scriptCopy;
        if (sigType == TransactionSignature.SIGHASH_NONE || sigType == TransactionSignature.SIGHASH_SINGLE) {
            for (int j = 0; j < txCopy.inputs.size(); j++) {
                if (j != index) {
                    txCopy.inputs.get(j).sequence = 0;
                }
            }
        }
        if (sigType == TransactionSignature.SIGHASH_NONE) {
            txCopy.outputs = new ArrayList<Output>();
        } else if(sigType == TransactionSignature.SIGHASH_SINGLE) {
            if (index > txCopy.outputs.size() - 1) {
                return ByteUtil.fromHex(SIGHASH_SINGLE_BUG);
            }
            if (txCopy.outputs.size() <= index) {
                throw new Exception("Missing output to sign");
            }
            for (int k = 0; k < index; k++) {
                txCopy.outputs.add(k, new Output(new Script(), new BigInteger(ByteUtil.fromHex(BITS_64_ON)).longValue()));
            }
        }
        if (sigType == TransactionSignature.SIGHASH_ANYONECANPAY) {
            Input inp = txCopy.inputs.get(index);
            txCopy.inputs = new ArrayList<Input>();
            txCopy.inputs.add(inp);
        }
        ByteWriter writer = new ByteWriter(0);
        writer.putBytes( txCopy.uncheckedSerialize() );
        writer.putUInt32LE(sigType);
        byte[] b = writer.toBytes();
        byte[] r = Hash.hash(b);
        byte[] result = ByteUtil.reverseBytes(r);
        return result;
    }

    public static ECDSASignature sign(Transaction tx, ECKey key, int sigType, int index, Script script) throws Exception {
        final byte[] hash = sighash(tx, sigType, index, script);
        return new ECDSA(hash, key, "little").sign();
    }

    public static boolean verify(Transaction tx,
                                 ECDSASignature signature,
                                 int sigType,
                                 byte[] publicKey,
                                 boolean publicKeyCompressed,
                                 int inputIndex,
                                 Script subscript) throws Exception {
        final byte[] hash = sighash(tx, sigType, inputIndex, subscript);
        final ECKey key = new ECKey(publicKey, publicKeyCompressed, false);
        return new ECDSA(hash, key, "little").verify(signature);
    }
}
