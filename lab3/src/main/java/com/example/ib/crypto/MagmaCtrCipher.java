package com.example.ib.crypto;

import org.springframework.stereotype.Component;

import java.util.Arrays;

/**
 * Режим гаммирования (CTR) для блочного шифра «Магма»
 * согласно ГОСТ Р 34.13-2018, раздел «Режим гаммирования».
 * Гамма формируется шифрованием последовательных значений счётчика,
 * увеличиваемого по модулю 2^64.
 */
@Component
public class MagmaCtrCipher {

    private final MagmaCipher magmaCipher = new MagmaCipher();

    /**
     * Шифрование/расшифрование потока байт.
     *
     * @param data          открытый текст или шифртекст
     * @param key           256-битный ключ (32 байта)
     * @param initialCounter начальное значение счётчика (64 бита)
     * @return результат XOR данных и гаммы
     */
    public byte[] process(byte[] data, byte[] key, long initialCounter) {
        if (data == null) {
            return new byte[0];
        }

        int[] roundKeys = magmaCipher.expandKey(key);
        byte[] out = new byte[data.length];
        byte[] counterBlock = new byte[MagmaCipher.BLOCK_SIZE];
        byte[] gamma = new byte[MagmaCipher.BLOCK_SIZE];

        long counter = initialCounter;
        int offset = 0;
        while (offset < data.length) {
            packCounter(counter, counterBlock);
            magmaCipher.encryptBlock(counterBlock, 0, gamma, 0, roundKeys);

            int blockSize = Math.min(MagmaCipher.BLOCK_SIZE, data.length - offset);
            xorBlock(data, offset, gamma, out, offset, blockSize);

            counter = (counter + 1) & 0xFFFFFFFFFFFFFFFFL; // инкремент по модулю 2^64
            offset += blockSize;
        }
        Arrays.fill(gamma, (byte) 0);
        Arrays.fill(counterBlock, (byte) 0);
        return out;
    }

    private void packCounter(long counter, byte[] buffer) {
        for (int i = 0; i < MagmaCipher.BLOCK_SIZE; i++) {
            buffer[7 - i] = (byte) (counter >>> (8 * i)); // big-endian представление
        }
    }

    private void xorBlock(byte[] in, int inOff, byte[] gamma, byte[] out, int outOff, int length) {
        for (int i = 0; i < length; i++) {
            out[outOff + i] = (byte) (in[inOff + i] ^ gamma[i]);
        }
    }
}
