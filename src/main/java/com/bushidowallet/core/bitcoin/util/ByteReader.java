package com.bushidowallet.core.bitcoin.util;

import java.nio.charset.Charset;

/**
 * Created by Jesion on 2015-01-19.
 */
public class ByteReader {

   private static final Charset UTF8_CHARSET = Charset.forName("UTF8");
   
   private byte[] buffer;
   private int index;

   public ByteReader(byte[] buffer) {
      this.buffer = buffer;
      this.index = 0;
   }

   public ByteReader(byte[] buffer, int index) {
      this.buffer = buffer;
      this.index = index;
   }

   public byte get() throws Exception {
      checkAvailable(1);
      return buffer[index++];
   }

   public int getShortLE() throws Exception {
      checkAvailable(2);
      return (((buffer[index++] & 0xFF) << 0) | ((buffer[index++] & 0xFF) << 8)) & 0xFFFF;
   }

   public int getIntLE() throws Exception {
      checkAvailable(4);
      return ((buffer[index++] & 0xFF) << 0) | ((buffer[index++] & 0xFF) << 8) | ((buffer[index++] & 0xFF) << 16)
            | ((buffer[index++] & 0xFF) << 24);
   }

   public long getLongLE() throws Exception {
      checkAvailable(8);
      return ((buffer[index++] & 0xFFL) << 0) | ((buffer[index++] & 0xFFL) << 8) | ((buffer[index++] & 0xFFL) << 16)
            | ((buffer[index++] & 0xFFL) << 24) | ((buffer[index++] & 0xFFL) << 32) | ((buffer[index++] & 0xFFL) << 40)
            | ((buffer[index++] & 0xFFL) << 48) | ((buffer[index++] & 0xFFL) << 56);
   }

   public long getUInt32() throws Exception {
      checkAvailable(4);
      byte[] intBytes = getBytes(4);
      return byteAsULong(intBytes[0]) | (byteAsULong(intBytes[1]) << 8) | (byteAsULong(intBytes[2]) << 16) | (byteAsULong(intBytes[3]) << 24);
   }

   public int getUInt8() throws Exception {
      checkAvailable(1);
      return ((buffer[index++] & 0xFF) << 0);
   }

   public int getUInt16LE() throws Exception {
      checkAvailable(2);
      return ((buffer[index++] & 0xFF) << 0) | ((buffer[index++] & 0xFF) << 8);
   }

   public int getUInt32LE() throws Exception {
      checkAvailable(4);
      return ((buffer[index++] & 0xFF) << 0) | ((buffer[index++] & 0xFF) << 8) | ((buffer[index++] & 0xFF) << 16)
              | ((buffer[index++] & 0xFF) << 24);
   }

   private long byteAsULong(byte b) {
      return ((long) b) & 0x00000000000000FFL;
   }

   public byte[] getBytes(int size) throws Exception {
      checkAvailable(size);
      byte[] bytes = new byte[size];
      System.arraycopy(buffer, index, bytes, 0, size);
      index += size;
      return bytes;
   }

   public String getString() throws Exception {
      int length = getIntLE();
      byte[] bytes = getBytes(length);
      return new String(bytes, UTF8_CHARSET);
   }

   public void skip(int num) throws Exception {
      checkAvailable(num);
      index += num;
   }

   public void reset() {
      index = 0;
   }

   public long getCompactInt() throws Exception {
      return CompactInt.fromByteReader(this);
   }

   public int getPosition() {
      return index;
   }

   public void setPosition(int index) {
      this.index = index;
   }

   public final int available() {
      return buffer.length - index;
   }

   private final void checkAvailable(int num) throws Exception {
      if (buffer.length - index < num) {
         throw new Exception();
      }
   }
}
