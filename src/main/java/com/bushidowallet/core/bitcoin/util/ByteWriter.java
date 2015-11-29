package com.bushidowallet.core.bitcoin.util;

import java.nio.charset.Charset;

/**
 * Created by Jesion on 2015-01-19.
 */
final public class ByteWriter {

   private static final Charset UTF8_CHARSET = Charset.forName("UTF8");

   private byte[] buffer;
   private int index;

   public ByteWriter(int capacity) {
      buffer = new byte[capacity];
      index = 0;
   }

   public ByteWriter(byte[] buffer) {
      buffer = buffer;
      index = buffer.length;
   }

   final private void ensureCapacity(int capacity) {
      if (buffer.length - index < capacity) {
         byte[] temp = new byte[buffer.length * 2 + capacity];
         System.arraycopy(buffer, 0, temp, 0, index);
         buffer = temp;
      }
   }

   public void put(byte b) {
      ensureCapacity(1);
      buffer[index++] = b;
   }

   public void putShortLE(short value) {
      ensureCapacity(2);
      buffer[index++] = (byte) (0xFF & (value >> 0));
      buffer[index++] = (byte) (0xFF & (value >> 8));
   }

   public void putUInt8(int value) {
      ensureCapacity(1);
      buffer[index++] = (byte) (0xFF & (value >> 0));
   }

   public void putUInt16LE(int value) throws Exception {
      throw new Exception("UInt16LE writer not implemented");
   }

   public void putUInt32LE(int value) throws Exception {
      ensureCapacity(4);
      buffer[index++] = (byte) (0xFF & (value >> 0));
      buffer[index++] = (byte) (0xFF & (value >> 8));
      buffer[index++] = (byte) (0xFF & (value >> 16));
      buffer[index++] = (byte) (0xFF & (value >> 24));
   }

   public void putIntLE(int value) {
      ensureCapacity(4);
      buffer[index++] = (byte) (0xFF & (value >> 0));
      buffer[index++] = (byte) (0xFF & (value >> 8));
      buffer[index++] = (byte) (0xFF & (value >> 16));
      buffer[index++] = (byte) (0xFF & (value >> 24));
   }

   public void putLongLE(long value) {
      ensureCapacity(8);
      buffer[index++] = (byte) (0xFFL & (value >> 0));
      buffer[index++] = (byte) (0xFFL & (value >> 8));
      buffer[index++] = (byte) (0xFFL & (value >> 16));
      buffer[index++] = (byte) (0xFFL & (value >> 24));
      buffer[index++] = (byte) (0xFFL & (value >> 32));
      buffer[index++] = (byte) (0xFFL & (value >> 40));
      buffer[index++] = (byte) (0xFFL & (value >> 48));
      buffer[index++] = (byte) (0xFFL & (value >> 56));
   }

   public void putUInt32(long value) {
      ensureCapacity(4);
      buffer[index++] = (byte) (0xFFL & (value >> 0));
      buffer[index++] = (byte) (0xFFL & (value >> 8));
      buffer[index++] = (byte) (0xFFL & (value >> 16));
      buffer[index++] = (byte) (0xFFL & (value >> 24));
   }

   public void putBytes(byte[] value) {
      ensureCapacity(value.length);
      System.arraycopy(value, 0, buffer, index, value.length);
      index += value.length;
   }

   public void putBytes(byte[] value, int offset, int length) {
      ensureCapacity(length);
      System.arraycopy(value, offset, buffer, index, length);
      index += length;
   }

   public void putCompactInt(long value) {
      putBytes(CompactInt.toBytes(value));
   }

   public void putString(String s) {
      byte[] bytes = s.getBytes(UTF8_CHARSET);
      putIntLE(bytes.length);
      putBytes(bytes);
   }

   public byte[] toBytes() {
      byte[] bytes = new byte[index];
      System.arraycopy(buffer, 0, bytes, 0, index);
      return bytes;
   }

   public int length() {
      return index;
   }
}
