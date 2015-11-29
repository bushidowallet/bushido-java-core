package com.bushidowallet.core.bitcoin.tx;

import com.bushidowallet.core.bitcoin.Address;
import com.bushidowallet.core.bitcoin.bip32.ECKey;
import com.bushidowallet.core.bitcoin.bip32.Hash;
import com.bushidowallet.core.bitcoin.script.Script;
import com.bushidowallet.core.bitcoin.tx.input.Input;
import com.bushidowallet.core.bitcoin.tx.input.MultiSigScriptHashInput;
import com.bushidowallet.core.bitcoin.tx.input.PublicKeyHashInput;
import com.bushidowallet.core.bitcoin.tx.output.Output;
import com.bushidowallet.core.bitcoin.util.ByteReader;
import com.bushidowallet.core.bitcoin.util.ByteWriter;
import com.bushidowallet.core.crypto.util.ByteUtil;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by Jesion on 2015-03-31.
 */
public class Transaction {

    private static int CURRENT_VERSION = 1;
    private static int DEFAULT_NLOCKTIME = 0;
    private static int MAXIMUM_EXTRA_SIZE = 4 + 9 + 9 + 4;
    private static int CHANGE_OUTPUT_MAX_SIZE = 20 + 4 + 34 + 4;
    private static long FEE_PER_KB = 10000;

    public int version;

    public List<Input> inputs;

    public List<Output> outputs;

    public int nLockTime;

    private Script changeScript;

    private int changeIndex;

    private long fee;

    public Transaction() {

        inputs = new ArrayList<Input>();
        outputs = new ArrayList<Output>();

        version = CURRENT_VERSION;
        nLockTime = DEFAULT_NLOCKTIME;

        changeIndex = -1;
        fee = -1;
    }

    public void sign(List<ECKey> keys) throws Exception {
        sign(keys, TransactionSignature.SIGHASH_ALL);
    }

    /**
     * Signs this Tx with a collection of private keys provided
     *
     * @param keys - collection of private keys used for signing
     * @param sigType - see Signature
     * @throws Exception
     */
    public void sign(List<ECKey> keys, int sigType) throws Exception {
        for (int i = 0; i < keys.size(); i++) {
            sign(keys.get(i), sigType);
        }
    }

    public void sign(ECKey key, int sigType) throws Exception {
        if (hasAllUtxoInfo()) {
            List<TransactionSignature> signatures = getSignatures(key, sigType);
            for (int j = 0; j < signatures.size(); j++) {
                applySignature(signatures.get(j));
            }
        } else {
            throw new Exception("Inputs not complete");
        }
    }

    private List<TransactionSignature> getSignatures(ECKey key, int sigType) throws Exception {
        List<TransactionSignature> results = new ArrayList<TransactionSignature>();
        byte[] hashData = new Hash(key.getPublic()).keyHash();
        for (int i = 0; i < inputs.size(); i++) {
            List<TransactionSignature> inputSigs = inputs.get(i).getSignatures(this, key, i, sigType, hashData);
            results.addAll(inputSigs);
        }
        return results;
    }

    private void applySignature(TransactionSignature signature) throws Exception {
        this.inputs.get(signature.inputIndex).addSignature(this, signature);
    }

    public boolean isFullySigned() {
        int numInputs = this.inputs.size();
        int signatures = 0;
        try {
            for (int i = 0; i < numInputs; i++) {
                if (inputs.get(i).isFullySigned() == true) {
                    signatures++;
                }
            }
        } catch (Exception e) {

        }
        if (numInputs == signatures) {
            return true;
        }
        return false;
    }

    public boolean hasAllUtxoInfo() {
        for (int i = 0; i < inputs.size(); i++) {
            if (inputs.get(i).output == null) {
                return false;
            }
        }
        return true;
    }

    public byte[] getHash() throws Exception {
        return ByteUtil.reverseBytes(Hash.hash(uncheckedSerialize()));
    }

    public Transaction from(UTXODescriptor utxoDescriptor) throws Exception {
        List<UTXODescriptor> utxos = new ArrayList<UTXODescriptor>();
        utxos.add(utxoDescriptor);
        return from(utxos);
    }

    public Transaction from(List<UTXODescriptor> utxos) throws Exception {

        return from(utxos, null, 0);
    }

    public Transaction from(List<UTXODescriptor> utxos, List<ECKey> publicKeys, int treshhold) throws Exception {

        for (int i = 0; i < utxos.size(); i++) {
            if (utxoIncluded(utxos.get(i)) == true) {
                throw new Exception("utxos list contains element that has been already converted to transaction input.");
            }
            if (publicKeys != null && publicKeys.size() > 0 && treshhold > 0) {
                fromMultisigUTXO(utxos.get(i), publicKeys, treshhold);
            } else {
                fromNonP2SH(utxos.get(i));
            }
        }
        return this;
    }

    public Transaction change(Address address) throws Exception {
        this.changeScript = Script.fromAddress(address);
        updateChangeOutput();
        return this;
    }

    private void updateChangeOutput() throws Exception {
        if (changeScript == null) {
            return;
        }
        clearSignatures();
        if (changeIndex >= 0) {
            this.outputs.remove(changeIndex);
        }
        long available = this.getUnspentValue();
        long fee = getFee();
        long changeAmount = available - fee;
        if (changeAmount > 0) {
            changeIndex = this.outputs.size();
            addOutput(new Output(changeScript, changeAmount));
        } else {
            changeIndex = -1;
        }
    }

    private void clearSignatures() throws Exception {
        for (Input input : inputs) {
            input.clearSignatures();
        }
    }

    public Transaction setFee(long fee) throws Exception {
        this.fee = fee;
        updateChangeOutput();
        return this;
    }

    public long getFee() throws Exception {
        if (changeScript == null) {
            return getUnspentValue();
        }
        return fee == -1 ? estimateFee() : fee;
    }

    public long estimateFee() throws Exception {
        long available = getUnspentValue();
        long size = estimateSize();
        BigDecimal feeBase = new BigDecimal(size).divide(new BigDecimal(FEE_PER_KB));
        double fee = Math.ceil(feeBase.doubleValue());
        if (available > fee) {
            size += CHANGE_OUTPUT_MAX_SIZE;
        }
        return (long) Math.ceil(new BigDecimal(size).divide(new BigDecimal(1000)).doubleValue()) * FEE_PER_KB;
    }

    public int estimateSize() throws Exception {
        int estimatedSize = MAXIMUM_EXTRA_SIZE;
        for (int i = 0; i < inputs.size(); i++) {
            estimatedSize += inputs.get(i).estimateSize();
        }
        for (int j = 0; j < outputs.size(); j++) {
            estimatedSize += outputs.get(j).script.getBytes().length + 9;
        }
        return estimatedSize;
    }

    public long getUnspentValue() throws Exception {
        return this.getInputAmount() - this.getOutputAmount();
    }

    public void removeOutput(int index) throws Exception {
        this.outputs.remove(index);
        updateChangeOutput();
    }

    /**
     * Calculates the total output amount in satoshis
     * @return
     */
    public long getOutputAmount() {
        long outputAmount = 0;
        for (int i = 0; i < outputs.size(); i++) {
            outputAmount += outputs.get(i).satoshis;
        }
        return outputAmount;
    }

    /**
     * Calculates the total input amount in satoshis
     * @return
     */
    public long getInputAmount() throws Exception {
        long inputAmount = 0;
        for (int i = 0; i < inputs.size(); i++) {
            Input input = inputs.get(i);
            Output prevOut = input.output;
            if (prevOut == null) {
                throw new Exception("Missing previous output on tx input " + input.toString());
            }
            inputAmount += prevOut.satoshis;
        }
        return inputAmount;
    }

    private void fromMultisigUTXO(UTXODescriptor utxoDescriptor, List<ECKey> publicKeys, int treshold) throws Exception {
        if (treshold > publicKeys.size()) {
            throw new Exception("Number of required signatures must be less than or equal to the number of public keys used to construct the scriptBytes");
        }
        UTXO utxo = new UTXO(utxoDescriptor);
        MultiSigScriptHashInput input = new MultiSigScriptHashInput(
            new Output(utxo.script, utxo.satoshis),
            utxo.txId,
            utxo.outputIndex,
            new Script(),
            publicKeys,
            treshold,
            null
        );
        addInput(input);
    }

    private void fromNonP2SH(UTXODescriptor utxoDescriptor) throws Exception {
        final UTXO utxo = new UTXO(utxoDescriptor);
        Class clazz = null;
        if (utxo.script.isPublicKeyHashOut()) {
            clazz = PublicKeyHashInput.class;
        } else {
            clazz = Input.class;
        }
        Input input = (Input) clazz.newInstance();
        input.output = new Output(utxo.script, utxo.satoshis);
        input.prevTxId = utxo.txId;
        input.outputIndex = utxo.outputIndex;
        input.script = new Script();
        this.addInput(input);
     }

    private boolean utxoIncluded(UTXODescriptor utxo) {
        for (int j = 0; j < inputs.size(); j++) {
            if (ByteUtil.toHex(inputs.get(j).prevTxId).equals(utxo.txId) && inputs.get(j).outputIndex == utxo.outputIndex) {
                return true;
            }
        }
        return false;
    }

    public void addInput(Input input) {
        this.inputs.add(input);
    }

    public void addOutput(Output output) {
        this.outputs.add(output);
    }

    public Transaction to(String receivingAddress, long satoshis) throws Exception {
        final Address address = new Address(receivingAddress);
        final Script script = Script.fromAddress(address);
        addOutput(new Output(script, satoshis));
        return this;
    }

    public Transaction(byte[] bytes) throws Exception {
        deserialize(bytes);
    }

    public byte[] uncheckedSerialize() throws Exception {
        ByteWriter writer = new ByteWriter(0);
        writer.putIntLE(this.version);
        writer.putCompactInt(inputs.size());
        for (int i = 0; i < inputs.size(); i++) {
            inputs.get(i).write(writer);
        }
        writer.putCompactInt(outputs.size());
        for (int j = 0; j < outputs.size(); j++) {
            outputs.get(j).write(writer);
        }
        writer.putIntLE(nLockTime);
        return writer.toBytes();
    }

    private void deserialize(byte[] bytes) throws Exception {
        ByteReader reader = new ByteReader(bytes);
        long txIns = 0;
        long txOuts = 0;
        inputs = new ArrayList<Input>();
        outputs = new ArrayList<Output>();
        this.version = reader.getIntLE();
        txIns = reader.getCompactInt();
        for (long i = 0; i < txIns; i++) {
            inputs.add(Input.fromByteReader(reader));
        }
        txOuts = reader.getCompactInt();
        for (long j = 0; j < txOuts; j++) {
            outputs.add(Output.fromByteReader(reader));
        }
        this.nLockTime = reader.getIntLE();
    }

    public String toHex() throws Exception {
        return ByteUtil.toHex(this.uncheckedSerialize());
    }
}
