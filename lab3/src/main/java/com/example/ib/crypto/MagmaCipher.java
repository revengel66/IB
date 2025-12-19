package com.example.ib.crypto;

/**
 * Реализация блочного шифра «Магма» согласно ГОСТ 34.12-2018.
 * Длина блока — 64 бита, длина ключа — 256 бит (8 подключей по 32 бита).
 */
public final class MagmaCipher {

    /** Размер блока в байтах (ГОСТ 34.12-2018, п. 5.1). */
    public static final int BLOCK_SIZE = 8;
    /** Размер ключа в байтах (ГОСТ 34.12-2018, п. 5.1). */
    public static final int KEY_SIZE = 32;

    /**
     * S-блоки из ГОСТ 34.12-2018, Таблица 1 (официальный набор для «Магмы»).
     * Каждый подмассив соответствует Si, i = 1..8, значения идут в десятичном виде.
     */
    private static final int[][] S_BOX = {
        {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
        {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
        {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
        {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
        {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
        {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
        {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
        {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2},
    };

    /**
     * Формирует 32 раундовых ключа из 256-битного ключа.
     * Первые 24 раунда используют ключи K1..K8 три раза подряд,
     * затем 8 раундов используют ключи в обратном порядке K8..K1
     * (ГОСТ 34.12-2018, п. 5.2).
     *
     * @param masterKey исходный ключ длиной 32 байта
     * @return массив из 32 раундовых ключей
     */
    public int[] expandKey(byte[] masterKey) {
        if (masterKey == null || masterKey.length != KEY_SIZE) {
            throw new IllegalArgumentException("Ключ должен содержать ровно 256 бит (32 байта).");
        }

        int[] keyWords = new int[8];
        for (int i = 0; i < 8; i++) {
            keyWords[i] = bytesToInt(masterKey, i * 4);
        }

        int[] roundKeys = new int[32];
        for (int i = 0; i < 24; i++) { // 3 полных цикла K1..K8
            roundKeys[i] = keyWords[i % 8];
        }
        for (int i = 24; i < 32; i++) { // заключительные 8 раундов K8..K1
            roundKeys[i] = keyWords[7 - (i % 8)];
        }
        return roundKeys;
    }

    /**
     * Шифрует один 64-битный блок в соответствии с 32-раундовой схемой Фейстеля.
     *
     * @param in        входной массив
     * @param inOff     смещение во входном массиве
     * @param out       выходной массив
     * @param outOff    смещение в выходном массиве
     * @param roundKeys раундовые ключи из {@link #expandKey(byte[])}
     */
    public void encryptBlock(byte[] in, int inOff, byte[] out, int outOff, int[] roundKeys) {
        if (roundKeys == null || roundKeys.length != 32) {
            throw new IllegalArgumentException("Ожидалось 32 раундовых ключа.");
        }

        int n1 = bytesToInt(in, inOff);
        int n2 = bytesToInt(in, inOff + 4);

        for (int round = 0; round < 31; round++) {
            int temp = n1;
            n1 = n2;
            n2 = temp ^ gFunction(roundKeys[round], n2);
        }
        n1 = n1 ^ gFunction(roundKeys[31], n2); // последний раунд без финальной перестановки

        intToBytes(n1, out, outOff);
        intToBytes(n2, out, outOff + 4);
    }

    /**
     * Раундовая функция g(k, a): сложение по модулю 2^32, подстановка по S-блокам,
     * циклический сдвиг влево на 11 бит (ГОСТ 34.12-2018, п. 5.1.2).
     */
    private int gFunction(int k, int a) {
        int sum = a + k; // сложение по модулю 2^32 за счёт переполнения int
        int substituted = applySBox(sum);
        return Integer.rotateLeft(substituted, 11);
    }

    /** Подстановка восьми 4-битных тетрад по S-блокам (биты 31..0). */
    private int applySBox(int value) {
        int result = 0;
        for (int i = 0; i < 8; i++) {
            int nibble = (value >>> (28 - 4 * i)) & 0x0F; // старший тетрад — S1
            int substituted = S_BOX[i][nibble];
            result |= substituted << (28 - 4 * i);
        }
        return result;
    }

    private int bytesToInt(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }

    private void intToBytes(int value, byte[] out, int offset) {
        out[offset] = (byte) (value >>> 24);
        out[offset + 1] = (byte) (value >>> 16);
        out[offset + 2] = (byte) (value >>> 8);
        out[offset + 3] = (byte) value;
    }
}
