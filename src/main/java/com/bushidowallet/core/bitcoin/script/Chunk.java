package com.bushidowallet.core.bitcoin.script;

/**
 * Created by Jesion on 2015-03-26.
 */
public class Chunk {

    public Opcode opcode;

    public byte[] bytes;

    public Chunk(Opcode opcode, byte[] bytes) {
        this.opcode = opcode;
        this.bytes = bytes;
    }

    public Chunk(Opcode opcode) {
        this.opcode = opcode;
    }

    public Chunk() {

    }
}
