package com.bushidowallet.core.bitcoin.script;

import com.bushidowallet.core.bitcoin.Address;
import com.bushidowallet.core.bitcoin.bip32.ECKey;
import com.bushidowallet.core.bitcoin.bip32.Hash;
import com.bushidowallet.core.bitcoin.util.ByteReader;
import com.bushidowallet.core.bitcoin.util.ByteWriter;
import com.bushidowallet.core.crypto.util.ByteUtil;
import org.bouncycastle.util.Arrays;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Created by Jesion on 2015-03-26.
 */
public class Script {

    private List<Chunk> chunks;

    public Script() {
        chunks = new ArrayList<Chunk>();
    }

    public void removeCodeSeparators() {
        List<Chunk> c = new ArrayList<Chunk>();
        for (int i = 0; i < this.chunks.size(); i++) {
            if (this.chunks.get(i).opcode.value != Opcode.OP_CODESEPARATOR) {
                c.add(this.chunks.get(i));
            }
        }
        this.chunks = c;
    }

    /**
     * Checks whether this instance of Script represents multi signature output script
     * @return
     */
    public boolean isMultiSigOut() {
        if (this.chunks.size() > 3 && this.chunks.get(0).opcode.isSmallIntOp()) {
            List<Chunk> keyChunks = chunks.subList(1, this.chunks.size() - 2);
            for (Chunk chunk : keyChunks) {
                if (chunk.bytes == null || chunk.bytes.length == 0) {
                    return false;
                }
            }
            if (this.chunks.get(this.chunks.size() - 2).opcode.isSmallIntOp()
                    && this.chunks.get(this.chunks.size() - 1).opcode.value == Opcode.OP_CHECKMULTISIG) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks whether this instance of Script represents pay to public key hash output script
     * @return
     */
    public boolean isPublicKeyHashOut() {

        return (this.getChunks().size() == 5 &&
                this.getChunks().get(0).opcode.value == Opcode.OP_DUP &&
                this.getChunks().get(1).opcode.value == Opcode.OP_HASH160 &&
                this.getChunks().get(2).bytes != null &&
                this.getChunks().get(3).opcode.value == Opcode.OP_EQUALVERIFY &&
                this.getChunks().get(4).opcode.value == Opcode.OP_CHECKSIG);
    }

    public byte[] getPublicKeyHash() throws Exception {
        if (isPublicKeyHashOut()) {
            return this.getChunks().get(2).bytes;
        }
        throw new Exception("This script is not a P2PKH script");
    }

    /**
     * Creates a multi signature output scriptBytes out of a collection of public keys bytes and signature treshold
     * @param publicKeys
     * @param treshold
     * @return
     */
    public static Script buildMultisigOut(List<ECKey> publicKeys, int treshold) throws Exception {
        if (treshold > publicKeys.size()) {
            throw new Exception("Number of required signatures must be less than or equal to the number of public keys used to construct the scriptBytes");
        }
        final Script script = new Script();
        script.add(new Chunk(Opcode.smallInt(treshold)));
        Collections.sort(publicKeys, new Comparator<ECKey>() {
            @Override
            public int compare(ECKey o1, ECKey o2) {
                return o1.getPublicHex().compareTo(o2.getPublicHex());
            }
        });
        for (int i = 0; i < publicKeys.size(); i++) {
            script.addChunk(publicKeys.get(i).getPublic());
        }
        script.add(new Chunk(Opcode.smallInt(publicKeys.size())));
        script.add(new Chunk(new Opcode(Opcode.OP_CHECKMULTISIG)));
        return script;
    }

    /**
     * Builds a script from a multi-sig address
     *
     * @param address
     * @return
     * @throws Exception
     */
    public static Script buildScriptHashOut(Address address) throws Exception {
        if (address.isPayToScriptHash()) {
            final Script script = new Script();
            script.add(new Chunk(new Opcode(Opcode.OP_HASH160)));
            script.addChunk(address.getHash());
            script.add(new Chunk(new Opcode(Opcode.OP_EQUAL)));
            return script;
        }
        throw new Exception("Address provided must be p2sh");
    }

    public static Script buildScriptHashOut(Script scriptParam) throws Exception {
        final Script script = new Script();
        script.add(new Chunk(new Opcode(Opcode.OP_HASH160)));
        //TODO: TEST this, keyHash = sha256ripemd160
        script.addChunk(new Hash(scriptParam.getBytes()).keyHash());
        script.add(new Chunk(new Opcode(Opcode.OP_EQUAL)));
        return script;
    }

    /**
     * @param address
     * @return
     */
    public static Script buildPublicKeyHashOut(Address address) throws Exception {
        if (address.isPayToScriptHash()) {
            throw new Exception("Address provided mst be p2pkh");
        }
        final Script script = new Script();
        script.add(new Chunk(new Opcode(Opcode.OP_DUP)));
        script.add(new Chunk(new Opcode(Opcode.OP_HASH160)));
        script.addChunk(address.getHash());
        script.add(new Chunk(new Opcode(Opcode.OP_EQUALVERIFY)));
        script.add(new Chunk(new Opcode(Opcode.OP_CHECKSIG)));
        return script;
    }

    /**
     * Builds a signature script (a script for an input) that signs a public key hash output script
     *
     * @param publicKey
     * @param sigDER
     * @param sigType
     * @return
     * @throws Exception
     */
    public static Script buildPublicKeyHashIn(byte[] publicKey, byte[] sigDER, int sigType) throws Exception {
        byte[] sigBytes = new byte[sigDER.length + 1];
        byte[] sigTypeBytes = new byte[1];
        sigTypeBytes[0] = (byte) (sigType & 0xff);
        System.arraycopy(sigDER, 0, sigBytes, 0, sigDER.length);
        System.arraycopy(sigTypeBytes, 0, sigBytes, sigDER.length, 1);
        Script script = new Script();
        script.addChunk(sigBytes);
        script.addChunk(publicKey);
        return script;
    }

    public boolean isPublicKeyHashIn() {
        if (this.chunks.size() == 2 &&
                this.chunks.get(0).bytes != null &&
                this.chunks.get(0).bytes.length >= 0x47 &&
                this.chunks.get(0).bytes.length <= 0x49) {
            return true;
        }
        return false;
    }

    /**
     * A new P2SH Multisig input script for the given public keys, requiring m of those public keys to spend
     *
     * @param publicKeys
     * @param treshold
     * @param signatures
     * @param cachedMultisig
     * @return
     * @throws Exception
     */
    public static Script buildP2SHMultisigIn(List<ECKey> publicKeys, int treshold, List<byte[]> signatures, Script cachedMultisig) throws Exception {
        Script script = new Script();
        script.add(new Chunk(new Opcode(Opcode.OP_0)));
        for (int i = 0; i < signatures.size(); i++) {
            script.addChunk(signatures.get(i));
        }
        if (cachedMultisig != null) {
            script.add(cachedMultisig);
        } else {
            //TODO: test this
            script.add(Script.buildMultisigOut(publicKeys, treshold));
        }
        return script;
    }

    private void addChunk(byte[] bytes) throws Exception {
        int opcodenum;
        int len = bytes.length;
        if (len >= 0 && len < Opcode.OP_PUSHDATA1) {
            opcodenum = bytes.length;
        } else if (len < Math.pow(2, 8)) {
            opcodenum = Opcode.OP_PUSHDATA1;
        } else if (len < Math.pow(2, 16)) {
            opcodenum = Opcode.OP_PUSHDATA2;
        } else if (len < Math.pow(2, 32)) {
            opcodenum = Opcode.OP_PUSHDATA4;
        } else {
            throw new Exception("You can't push that much data");
        }
        this.add(new Chunk(new Opcode(opcodenum), bytes));
    }

    public void add(Chunk chunk) {
        chunks.add(chunk);
    }

    public void add(Script script) {
        chunks.addAll(script.chunks);
    }

    public static Script fromString(String str) throws Exception {
        if (str == null || str.length() == 0) {
            return new Script();
        }
        final Script script = new Script();
        String[] tokens = str.split(" ");
        int i = 0;
        while (i < tokens.length) {
            String token = tokens[i];
            Opcode opcode = new Opcode(token);
            if ( opcode.isUndefined() ) {
                int opcodeNum = Integer.parseInt(token);
                if (opcodeNum > 0 && opcodeNum < Opcode.OP_PUSHDATA1) {
                    script.add(new Chunk(new Opcode(opcodeNum), ByteUtil.fromHex(tokens[i + 1].substring(2))));
                    i = i + 2;
                } else {
                    throw new Exception("Invalid script: " + str);
                }
            } else if (opcode.value == Opcode.OP_PUSHDATA1 || opcode.value == Opcode.OP_PUSHDATA2 || opcode.value == Opcode.OP_PUSHDATA4) {
                if (tokens[i + 1].substring(0, 2).equals("0x") == false) {
                    throw new Exception("Pushdata data must start with 0x");
                }
                script.add(new Chunk(opcode, ByteUtil.fromHex(tokens[i + 2].substring(2))));
                i = i + 3;
            } else {
                script.add(new Chunk(opcode));
                i = i + 1;
            }
        }
        return script;
    }

    public static Script fromBytes(byte[] bytes) throws Exception {
        ByteReader reader = new ByteReader(bytes);
        Script script = new Script();
        while (reader.available() > 0) {
            int opcodenum = reader.getUInt8();
            int len;
            if (opcodenum > 0 && opcodenum < Opcode.OP_PUSHDATA1) {
                len = opcodenum;
                script.add(new Chunk(new Opcode(opcodenum), reader.getBytes(len)));
            } else if (opcodenum == Opcode.OP_PUSHDATA1) {
                len = reader.getUInt8();
                script.add(new Chunk(new Opcode(opcodenum), reader.getBytes(len)));
            } else if (opcodenum == Opcode.OP_PUSHDATA2) {
                len = reader.getUInt16LE();
                script.add(new Chunk(new Opcode(opcodenum), reader.getBytes(len)));
            } else if (opcodenum == Opcode.OP_PUSHDATA4) {
                len = reader.getUInt32LE();
                script.add(new Chunk(new Opcode(opcodenum), reader.getBytes(len)));
            } else {
                script.add(new Chunk(new Opcode(opcodenum)));
            }
        }
        return script;
    }

    public static Script fromAddress(Address address) throws Exception {
        if (address.isPayToScriptHash()) {
            return Script.buildScriptHashOut(address);
        } else if (address.isPayToPublicKeyHash()) {
            return Script.buildPublicKeyHashOut(address);
        }
        throw new Exception("Unsupported address");
    }

    public List<Chunk> getChunks() {
        return this.chunks;
    }

    public byte[] getBytes() throws Exception {
        ByteWriter buf = new ByteWriter(0);
        for (Chunk chunk : chunks) {
            buf.putUInt8(chunk.opcode.value);
            if (chunk.bytes != null) {
                if (chunk.opcode.value < Opcode.OP_PUSHDATA1) {
                    buf.putBytes(chunk.bytes);
                } else if (chunk.opcode.value == Opcode.OP_PUSHDATA1) {
                    buf.putUInt8(chunk.bytes.length);
                    buf.putBytes(chunk.bytes);
                } else if (chunk.opcode.value == Opcode.OP_PUSHDATA2) {
                    buf.putUInt16LE(chunk.bytes.length);
                    buf.putBytes(chunk.bytes);
                } else if (chunk.opcode.value == Opcode.OP_PUSHDATA4) {
                    buf.putUInt32LE(chunk.bytes.length);
                    buf.putBytes(chunk.bytes);
                }
            }
        }
        return buf.toBytes();
    }

    public String toString() {
        String str = "";
        for (int i = 0; i < this.getChunks().size(); i++) {
            Chunk chunk = this.getChunks().get(i);
            int opcodenum = chunk.opcode.value;
            if (chunk.bytes == null) {
                if (Opcode.OP_CODE_MAP.containsValue(opcodenum)) {
                    str = str + " " + chunk.opcode.toString();
                } else {
                    String numstr = Integer.toString(opcodenum, 16);
                    if (numstr.length() % 2 != 0) {
                        numstr = "0" + numstr;
                    }
                    str = str + " " + "0x" + numstr;
                }
            } else {
                if (opcodenum == Opcode.OP_PUSHDATA1 ||
                    opcodenum == Opcode.OP_PUSHDATA2 ||
                    opcodenum == Opcode.OP_PUSHDATA4) {
                    str = str + " " + chunk.opcode.toString();
                }
                str = str + " " + chunk.bytes.length;
                if (chunk.bytes.length > 0) {
                    str = str + " " + "0x" + ByteUtil.toHex(chunk.bytes);
                }
            }
        }
        if (str.length() > 1) {
            return str.substring(1);
        }
        return null;
    }

    public boolean equals(Script script) {
        if (chunks.size() != script.chunks.size()) {
            return false;
        }
        for (int i = 0; i < chunks.size(); i++) {
            if (chunks.get(i).bytes != null && script.chunks.get(i).bytes == null) {
                return false;
            }
            if (chunks.get(i).opcode.value != script.chunks.get(i).opcode.value) {
                return false;
            }
            if (Arrays.areEqual(chunks.get(i).bytes, script.chunks.get(i).bytes) == false) {
                return false;
            }
        }
        return true;
    }
}