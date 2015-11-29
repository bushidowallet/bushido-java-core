package com.bushidowallet.core.bitcoin.tx.output;

import com.bushidowallet.core.bitcoin.script.Script;
import com.bushidowallet.core.bitcoin.util.ByteReader;
import com.bushidowallet.core.bitcoin.util.ByteWriter;
import com.bushidowallet.core.crypto.util.ByteUtil;

/**
 * Created by Jesion on 2015-03-31.
 */
public class Output {

    public long satoshis;

    public Script script;

    public Output() {

    }

    public Output(Script script, long satoshis) {
        this.satoshis = satoshis;
        this.script = script;
    }

    public static Output fromByteReader(ByteReader reader) throws Exception {
        final Output out = new Output();
        out.satoshis = reader.getLongLE();
        long scriptLen = reader.getCompactInt();
        if (scriptLen > 0) {
            out.script = Script.fromBytes(reader.getBytes((int) scriptLen));
        } else {
            out.script = new Script();
        }
        return out;
    }

    public void write(ByteWriter writer) throws Exception {
        writer.putLongLE(satoshis);
        writer.putCompactInt(script.getBytes().length);
        writer.putBytes(script.getBytes());
    }

    public byte[] toBytes() throws Exception {
        ByteWriter writer = new ByteWriter(0);
        writer.putLongLE(satoshis);
        writer.putCompactInt(script.getBytes().length);
        writer.putBytes(script.getBytes());
        return writer.toBytes();
    }

    public String toHex() throws Exception {
        return ByteUtil.toHex(toBytes());
    }
}
