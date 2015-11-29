package com.bushidowallet.core.bitcoin.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class CompactInt {

   public static long fromByteBuffer(ByteBuffer buf) {
      if (buf.remaining() < 1) {
         return -1;
      }
      long first = 0x00000000000000FFL & ((long) buf.get());
      long value;
      if (first < 253) {
         value = 0x00000000000000FFL & ((long) first);
      } else if (first == 253) {
         if (buf.remaining() < 2) {
            return -1;
         }
         buf.order(ByteOrder.LITTLE_ENDIAN);
         value = 0x0000000000FFFFL & ((long) buf.getShort());
      } else if (first == 254) {
         if (buf.remaining() < 4) {
            return -1;
         }
         buf.order(ByteOrder.LITTLE_ENDIAN);
         value = 0x00000000FFFFFFFF & ((long) buf.getInt());
      } else {
         if (buf.remaining() < 8) {
            return -1;
         }
         buf.order(ByteOrder.LITTLE_ENDIAN);
         value = buf.getLong();
      }
      return value;
   }

   public static long fromByteReader(ByteReader reader) throws Exception {
      long first = 0x00000000000000FFL & ((long) reader.get());
      long value;
      if (first < 253) {
         value = 0x00000000000000FFL & ((long) first);
      } else if (first == 253) {
         value = 0x0000000000FFFFL & ((long) reader.getShortLE());
      } else if (first == 254) {
         value = 0x00000000FFFFFFFF & ((long) reader.getIntLE());
      } else {
         value = reader.getLongLE();
      }
      return value;
   }

   public static void toByteBuffer(long value, ByteBuffer buf) {
      buf.put(toBytes(value));
   }

   public static byte[] toBytes(long value) {
      if (isLessThan(value, 253)) {
         return new byte[] { (byte) value };
      } else if (isLessThan(value, 65536)) {
         return new byte[] { (byte) 253, (byte) (value), (byte) (value >> 8) };
      } else if (isLessThan(value, 4294967295L)) {
         byte[] bytes = new byte[5];
         bytes[0] = (byte) 254;
         IntegerUtil.uint32ToByteArrayLE(value, bytes, 1);
         return bytes;
      } else {
         byte[] bytes = new byte[9];
         bytes[0] = (byte) 255;
         IntegerUtil.uint32ToByteArrayLE(value, bytes, 1);
         IntegerUtil.uint32ToByteArrayLE(value >>> 32, bytes, 5);
         return bytes;
      }
   }

   private static boolean isLessThan(long n1, long n2) {
      return (n1 < n2) ^ ((n1 < 0) != (n2 < 0));
   }
}
