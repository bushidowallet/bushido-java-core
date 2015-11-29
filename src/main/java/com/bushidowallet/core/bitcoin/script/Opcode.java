package com.bushidowallet.core.bitcoin.script;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Jesion on 2015-03-26.
 */
public class Opcode {

    // push value
    public static final int OP_FALSE        = 0;
    public static final int OP_0            = 0;
    public static final int OP_PUSHDATA1    = 76;
    public static final int OP_PUSHDATA2    = 77;
    public static final int OP_PUSHDATA4    = 78;
    public static final int OP_1NEGATE      = 79;
    public static final int OP_RESERVED     = 80;
    public static final int OP_TRUE         = 81;
    public static final int OP_1            = 81;
    public static final int OP_2            = 82;
    public static final int OP_3            = 83;
    public static final int OP_4            = 84;
    public static final int OP_5            = 85;
    public static final int OP_6            = 86;
    public static final int OP_7            = 87;
    public static final int OP_8            = 88;
    public static final int OP_9            = 89;
    public static final int OP_10           = 90;
    public static final int OP_11           = 91;
    public static final int OP_12           = 92;
    public static final int OP_13           = 93;
    public static final int OP_14           = 94;
    public static final int OP_15           = 95;
    public static final int OP_16           = 96;

    // control
    public static final int OP_NOP          = 97;
    public static final int OP_VER          = 98;
    public static final int OP_IF           = 99;
    public static final int OP_NOTIF        = 100;
    public static final int OP_VERIF        = 101;
    public static final int OP_VERNOTIF     = 102;
    public static final int OP_ELSE         = 103;
    public static final int OP_ENDIF        = 104;
    public static final int OP_VERIFY       = 105;
    public static final int OP_RETURN       = 106;

    // stack ops
    public static final int OP_TOALTSTACK   = 107;
    public static final int OP_FROMALTSTACK = 108;
    public static final int OP_2DROP        = 109;
    public static final int OP_2DUP         = 110;
    public static final int OP_3DUP         = 111;
    public static final int OP_2OVER        = 112;
    public static final int OP_2ROT         = 113;
    public static final int OP_2SWAP        = 114;
    public static final int OP_IFDUP        = 115;
    public static final int OP_DEPTH        = 116;
    public static final int OP_DROP         = 117;
    public static final int OP_DUP          = 118;
    public static final int OP_NIP          = 119;
    public static final int OP_OVER         = 120;
    public static final int OP_PICK         = 121;
    public static final int OP_ROLL         = 122;
    public static final int OP_ROT          = 123;
    public static final int OP_SWAP         = 124;
    public static final int OP_TUCK         = 125;

    // splice ops
    public static final int OP_CAT          = 126;
    public static final int OP_SUBSTR       = 127;
    public static final int OP_LEFT         = 128;
    public static final int OP_RIGHT        = 129;
    public static final int OP_SIZE         = 130;

    // bit logic
    public static final int OP_INVERT       = 131;
    public static final int OP_AND          = 132;
    public static final int OP_OR           = 133;
    public static final int OP_XOR          = 134;
    public static final int OP_EQUAL        = 135;
    public static final int OP_EQUALVERIFY  = 136;
    public static final int OP_RESERVED1    = 137;
    public static final int OP_RESERVED2    = 138;

    // numeric
    public static final int OP_1ADD         = 139;
    public static final int OP_1SUB         = 140;
    public static final int OP_2MUL         = 141;
    public static final int OP_2DIV         = 142;
    public static final int OP_NEGATE       = 143;
    public static final int OP_ABS          = 144;
    public static final int OP_NOT          = 145;
    public static final int OP_0NOTEQUAL    = 146;

    public static final int OP_ADD          = 147;
    public static final int OP_SUB          = 148;
    public static final int OP_MUL          = 149;
    public static final int OP_DIV          = 150;
    public static final int OP_MOD          = 151;
    public static final int OP_LSHIFT       = 152;
    public static final int OP_RSHIFT       = 153;

    public static final int OP_BOOLAND              = 154;
    public static final int OP_BOOLOR               = 155;
    public static final int OP_NUMEQUAL             = 156;
    public static final int OP_NUMEQUALVERIFY       = 157;
    public static final int OP_NUMNOTEQUAL          = 158;
    public static final int OP_LESSTHAN             = 159;
    public static final int OP_GREATERTHAN          = 160;
    public static final int OP_LESSTHANOREQUAL      = 161;
    public static final int OP_GREATERTHANOREQUAL   = 162;
    public static final int OP_MIN                  = 163;
    public static final int OP_MAX                  = 164;

    public static final int OP_WITHIN               = 165;

    // crypto
    public static final int OP_RIPEMD160            = 166;
    public static final int OP_SHA1                 = 167;
    public static final int OP_SHA256               = 168;
    public static final int OP_HASH160              = 169;
    public static final int OP_HASH256              = 170;
    public static final int OP_CODESEPARATOR        = 171;
    public static final int OP_CHECKSIG             = 172;
    public static final int OP_CHECKSIGVERIFY       = 173;
    public static final int OP_CHECKMULTISIG        = 174;
    public static final int OP_CHECKMULTISIGVERIFY  = 175;

    // expansion
    public static final int OP_NOP1                 = 176;
    public static final int OP_NOP2                 = 177;
    public static final int OP_NOP3                 = 178;
    public static final int OP_NOP4                 = 179;
    public static final int OP_NOP5                 = 180;
    public static final int OP_NOP6                 = 181;
    public static final int OP_NOP7                 = 182;
    public static final int OP_NOP8                 = 183;
    public static final int OP_NOP9                 = 184;
    public static final int OP_NOP10                = 185;

    // template matching params
    public static final int OP_PUBKEYHASH           = 253;
    public static final int OP_PUBKEY               = 254;
    public static final int OP_INVALIDOPCODE        = 255;

    public static final Map<String, Integer> OP_CODE_MAP;
    static {
        OP_CODE_MAP = new HashMap<String, Integer>();
        OP_CODE_MAP.put("OP_FALSE", OP_FALSE);
        OP_CODE_MAP.put("OP_0", OP_0);
        OP_CODE_MAP.put("OP_PUSHDATA1", OP_PUSHDATA1);
        OP_CODE_MAP.put("OP_PUSHDATA2", OP_PUSHDATA2);
        OP_CODE_MAP.put("OP_PUSHDATA4", OP_PUSHDATA4);
        OP_CODE_MAP.put("OP_1NEGATE", OP_1NEGATE);
        OP_CODE_MAP.put("OP_RESERVED", OP_RESERVED);
        OP_CODE_MAP.put("OP_TRUE", OP_TRUE);
        OP_CODE_MAP.put("OP_1", OP_1);
        OP_CODE_MAP.put("OP_2", OP_2);
        OP_CODE_MAP.put("OP_3", OP_3);
        OP_CODE_MAP.put("OP_4", OP_4);
        OP_CODE_MAP.put("OP_5", OP_5);
        OP_CODE_MAP.put("OP_6", OP_6);
        OP_CODE_MAP.put("OP_7", OP_7);
        OP_CODE_MAP.put("OP_8", OP_8);
        OP_CODE_MAP.put("OP_9", OP_9);
        OP_CODE_MAP.put("OP_10", OP_10);
        OP_CODE_MAP.put("OP_11", OP_11);
        OP_CODE_MAP.put("OP_12", OP_12);
        OP_CODE_MAP.put("OP_13", OP_13);
        OP_CODE_MAP.put("OP_14", OP_14);
        OP_CODE_MAP.put("OP_15", OP_15);
        OP_CODE_MAP.put("OP_16", OP_16);
        OP_CODE_MAP.put("OP_NOP", OP_NOP);
        OP_CODE_MAP.put("OP_VER", OP_VER);
        OP_CODE_MAP.put("OP_IF", OP_IF);
        OP_CODE_MAP.put("OP_NOTIF", OP_NOTIF);
        OP_CODE_MAP.put("OP_VERIF", OP_VERIF);
        OP_CODE_MAP.put("OP_VERNOTIF", OP_VERNOTIF);
        OP_CODE_MAP.put("OP_ELSE", OP_ELSE);
        OP_CODE_MAP.put("OP_ENDIF", OP_ENDIF);
        OP_CODE_MAP.put("OP_VERIFY", OP_VERIFY);
        OP_CODE_MAP.put("OP_RETURN", OP_RETURN);
        OP_CODE_MAP.put("OP_TOALTSTACK", OP_TOALTSTACK);
        OP_CODE_MAP.put("OP_FROMALTSTACK", OP_FROMALTSTACK);
        OP_CODE_MAP.put("OP_2DROP", OP_2DROP);
        OP_CODE_MAP.put("OP_2DUP", OP_2DUP);
        OP_CODE_MAP.put("OP_3DUP", OP_3DUP);
        OP_CODE_MAP.put("OP_2OVER", OP_2OVER);
        OP_CODE_MAP.put("OP_2ROT", OP_2ROT);
        OP_CODE_MAP.put("OP_2SWAP", OP_2SWAP);
        OP_CODE_MAP.put("OP_IFDUP", OP_IFDUP);
        OP_CODE_MAP.put("OP_DEPTH", OP_DEPTH);
        OP_CODE_MAP.put("OP_DROP", OP_DROP);
        OP_CODE_MAP.put("OP_DUP", OP_DUP);
        OP_CODE_MAP.put("OP_NIP", OP_NIP);
        OP_CODE_MAP.put("OP_OVER", OP_OVER);
        OP_CODE_MAP.put("OP_PICK", OP_PICK);
        OP_CODE_MAP.put("OP_ROLL", OP_ROLL);
        OP_CODE_MAP.put("OP_ROT", OP_ROT);
        OP_CODE_MAP.put("OP_SWAP", OP_SWAP);
        OP_CODE_MAP.put("OP_TUCK", OP_TUCK);
        OP_CODE_MAP.put("OP_CAT", OP_CAT);
        OP_CODE_MAP.put("OP_SUBSTR", OP_SUBSTR);
        OP_CODE_MAP.put("OP_LEFT", OP_LEFT);
        OP_CODE_MAP.put("OP_RIGHT", OP_RIGHT);
        OP_CODE_MAP.put("OP_SIZE", OP_SIZE);
        OP_CODE_MAP.put("OP_INVERT", OP_INVERT);
        OP_CODE_MAP.put("OP_AND", OP_AND);
        OP_CODE_MAP.put("OP_OR", OP_OR);
        OP_CODE_MAP.put("OP_XOR", OP_XOR);
        OP_CODE_MAP.put("OP_EQUAL", OP_EQUAL);
        OP_CODE_MAP.put("OP_EQUALVERIFY", OP_EQUALVERIFY);
        OP_CODE_MAP.put("OP_RESERVED1", OP_RESERVED1);
        OP_CODE_MAP.put("OP_RESERVED2", OP_RESERVED2);
        OP_CODE_MAP.put("OP_1ADD", OP_1ADD);
        OP_CODE_MAP.put("OP_1SUB", OP_1SUB);
        OP_CODE_MAP.put("OP_2MUL", OP_2MUL);
        OP_CODE_MAP.put("OP_2DIV", OP_2DIV);
        OP_CODE_MAP.put("OP_NEGATE", OP_NEGATE);
        OP_CODE_MAP.put("OP_ABS", OP_ABS);
        OP_CODE_MAP.put("OP_NOT", OP_NOT);
        OP_CODE_MAP.put("OP_0NOTEQUAL", OP_0NOTEQUAL);
        OP_CODE_MAP.put("OP_ADD", OP_ADD);
        OP_CODE_MAP.put("OP_SUB", OP_SUB);
        OP_CODE_MAP.put("OP_MUL", OP_MUL);
        OP_CODE_MAP.put("OP_DIV", OP_DIV);
        OP_CODE_MAP.put("OP_MOD", OP_MOD);
        OP_CODE_MAP.put("OP_LSHIFT", OP_LSHIFT);
        OP_CODE_MAP.put("OP_RSHIFT", OP_RSHIFT);
        OP_CODE_MAP.put("OP_BOOLAND", OP_BOOLAND);
        OP_CODE_MAP.put("OP_BOOLOR", OP_BOOLOR);
        OP_CODE_MAP.put("OP_NUMEQUAL", OP_NUMEQUAL);
        OP_CODE_MAP.put("OP_NUMEQUALVERIFY", OP_NUMEQUALVERIFY);
        OP_CODE_MAP.put("OP_NUMNOTEQUAL", OP_NUMNOTEQUAL);
        OP_CODE_MAP.put("OP_LESSTHAN", OP_LESSTHAN);
        OP_CODE_MAP.put("OP_GREATERTHAN", OP_GREATERTHAN);
        OP_CODE_MAP.put("OP_LESSTHANOREQUAL", OP_LESSTHANOREQUAL);
        OP_CODE_MAP.put("OP_GREATERTHANOREQUAL", OP_GREATERTHANOREQUAL);
        OP_CODE_MAP.put("OP_MIN", OP_MIN);
        OP_CODE_MAP.put("OP_MAX", OP_MAX);
        OP_CODE_MAP.put("OP_WITHIN", OP_WITHIN);
        OP_CODE_MAP.put("OP_RIPEMD160", OP_RIPEMD160);
        OP_CODE_MAP.put("OP_SHA1", OP_SHA1);
        OP_CODE_MAP.put("OP_SHA256", OP_SHA256);
        OP_CODE_MAP.put("OP_HASH160", OP_HASH160);
        OP_CODE_MAP.put("OP_HASH256", OP_HASH256);
        OP_CODE_MAP.put("OP_CODESEPARATOR", OP_CODESEPARATOR);
        OP_CODE_MAP.put("OP_CHECKSIG", OP_CHECKSIG);
        OP_CODE_MAP.put("OP_CHECKSIGVERIFY", OP_CHECKSIGVERIFY);
        OP_CODE_MAP.put("OP_CHECKMULTISIG", OP_CHECKMULTISIG);
        OP_CODE_MAP.put("OP_CHECKMULTISIGVERIFY", OP_CHECKMULTISIGVERIFY);
        OP_CODE_MAP.put("OP_NOP1", OP_NOP1);
        OP_CODE_MAP.put("OP_NOP2", OP_NOP2);
        OP_CODE_MAP.put("OP_NOP3", OP_NOP3);
        OP_CODE_MAP.put("OP_NOP4", OP_NOP4);
        OP_CODE_MAP.put("OP_NOP5", OP_NOP5);
        OP_CODE_MAP.put("OP_NOP6", OP_NOP6);
        OP_CODE_MAP.put("OP_NOP7", OP_NOP7);
        OP_CODE_MAP.put("OP_NOP8", OP_NOP8);
        OP_CODE_MAP.put("OP_NOP9", OP_NOP9);
        OP_CODE_MAP.put("OP_NOP10", OP_NOP10);
        OP_CODE_MAP.put("OP_PUBKEYHASH", OP_PUBKEYHASH);
        OP_CODE_MAP.put("OP_PUBKEY", OP_PUBKEY);
        OP_CODE_MAP.put("OP_INVALIDOPCODE", OP_INVALIDOPCODE);
    }

    public int value = -1;

    public Opcode(String value) {
        try {
            this.value = OP_CODE_MAP.get(value);
        } catch (Exception e) {
            System.out.println("I was unable to find a OP CODE for " + value + ", leaving value unfilled...");
        }
    }

    public Opcode(int value) {
        this.value = value;
    }

    public Opcode() {

    }

    public boolean isSmallIntOp() {
        return ((value == OP_CODE_MAP.get("OP_0")) || ((value >= OP_CODE_MAP.get("OP_1")) && (value <= OP_CODE_MAP.get("OP_16"))));
    }

    public boolean isUndefined() {
        return !(value >= 0);
    }

    public String toString() {
       for (Map.Entry<String, Integer> entry : OP_CODE_MAP.entrySet()) {
           if (entry.getValue().equals( this.value )) {
               return entry.getKey();
           }
       }
       return String.valueOf(this.value);
    }

    public static Opcode smallInt(int n) throws Exception {
        if (n >= 0 && n <= 16) {
            if (n == 0) {
                return new Opcode(OP_0);
            }
            return new Opcode(OP_1 + n - 1);
        } else {
            throw new Exception("Invalid Argument: n must be between 0 and 16");
        }
    }
}
