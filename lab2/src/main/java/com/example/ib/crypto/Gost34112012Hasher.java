package com.example.ib.crypto;

import org.springframework.stereotype.Component;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Locale;

@Component
public class Gost34112012Hasher {
    private static final int BLOCK_SIZE = 64;
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();
    private static final String[] C_HEX = {
        "B1085BDA1ECADAE9EBCB2F81C0657C1F2F6A76432E45D016714EB88D7585C4FC4B7CE09192676901A2422A08A460D31505767436CC744D23DD806559F2A64507",
        "6FA3B58AA99D2F1A4FE39D460F70B5D7F3FEEA720A232B9861D55E0F16B501319AB5176B12D699585CB561C2DB0AA7CA55DDA21BD7CBCD56E679047021B19BB7",
        "F574DCAC2BCE2FC70A39FC286A3D843506F15E5F529C1F8BF2EA7514B1297B7BD3E20FE490359EB1C1C93A376062DB09C2B6F443867ADB31991E96F50ABA0AB2",
        "EF1FDFB3E81566D2F948E1A05D71E4DD488E857E335C3C7D9D721CAD685E353FA9D72C82ED03D675D8B71333935203BE3453EAA193E837F1220CBEBC84E3D12E",
        "4BEA6BACAD4747999A3F410C6CA923637F151C1F1686104A359E35D7800FFFBDBFCD1747253AF5A3DFFF00B723271A167A56A27EA9EA63F5601758FD7C6CFE57",
        "AE4FAEAE1D3AD3D96FA4C33B7A3039C02D66C4F95142A46C187F9AB49AF08EC6CFFAA6B71C9AB7B40AF21F66C2BEC6B6BF71C57236904F35FA68407A46647D6E",
        "F4C70E16EEAAC5EC51AC86FEBF240954399EC6C7E6BF87C9D3473E33197A93C90992ABC52D822C3706476983284A05043517454CA23C4AF38886564D3A14D493",
        "9B1F5B424D93C9A703E7AA020C6E41414EB7F8719C36DE1E89B4443B4DDBC49AF4892BCB929B069069D18D2BD1A5C42F36ACC2355951A8D9A47F0DD4BF02E71E",
        "378F5A541631229B944C9AD8EC165FDE3A7D3A1B258942243CD955B7E00D0984800A440BDBB2CEB17B2B8A9AA6079C540E38DC92CB1F2A607261445183235ADB",
        "ABBEDEA680056F52382AE548B2E4F3F38941E71CFF8A78DB1FFFE18A1B3361039FE76702AF69334B7A1E6C303B7652F43698FAD1153BB6C374B4C7FB98459CED",
        "7BCD9ED0EFC889FB3002C6CD635AFE94D8FA6BBBEBAB076120018021148466798A1D71EFEA48B9CAEFBACD1D7D476E98DEA2594AC06FD85D6BCAA4CD81F32D1B",
        "378EE767F11631BAD21380B00449B17ACDA43C32BCDF1D77F82012D430219F9B5D80EF9D1891CC86E71DA4AA88E12852FAF417D5D9B21B9948BC924AF11BD720",
    };
    private static final byte[][] C = initIterationConstants();
    private static final int[] SBOX_DECIMAL = {
        252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
        233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
        249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
        5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
        235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
        181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
        21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
        50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
        223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
        224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
        167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
        173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
        7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
        225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
        32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
        89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
    };
    private static final byte[] SBOX = initSBox();
    private static final byte[] TAU = {
        0, 8, 16, 24, 32, 40, 48, 56, 1, 9, 17, 25, 33, 41, 49, 57,
        2, 10, 18, 26, 34, 42, 50, 58, 3, 11, 19, 27, 35, 43, 51, 59,
        4, 12, 20, 28, 36, 44, 52, 60, 5, 13, 21, 29, 37, 45, 53, 61,
        6, 14, 22, 30, 38, 46, 54, 62, 7, 15, 23, 31, 39, 47, 55, 63,
    };

    private static final long[] LINEAR_MATRIX = {
        0x8E20FAA72BA0B470L, 0x47107DDD9B505A38L, 0xAD08B0E0C3282D1CL, 0xD8045870EF14980EL,
        0x6C022C38F90A4C07L, 0x3601161CF205268DL, 0x1B8E0B0E798C13C8L, 0x83478B07B2468764L,
        0xA011D380818E8F40L, 0x5086E740CE47C920L, 0x2843FD2067ADEA10L, 0x14AFF010BDD87508L,
        0x0AD97808D06CB404L, 0x05E23C0468365A02L, 0x8C711E02341B2D01L, 0x46B60F011A83988EL,
        0x90DAB52A387AE76FL, 0x486DD4151C3DFDB9L, 0x24B86A840E90F0D2L, 0x125C354207487869L,
        0x092E94218D243CBAL, 0x8A174A9EC8121E5DL, 0x4585254F64090FA0L, 0xACCC9CA9328A8950L,
        0x9D4DF05D5F661451L, 0xC0A878A0A1330AA6L, 0x60543C50DE970553L, 0x302A1E286FC58CA7L,
        0x18150F14B9EC46DDL, 0x0C84890AD27623E0L, 0x0642CA05693B9F70L, 0x0321658CBA93C138L,
        0x86275DF09CE8AAA8L, 0x439DA0784E745554L, 0xAFC0503C273AA42AL, 0xD960281E9D1D5215L,
        0xE230140FC0802984L, 0x71180A8960409A42L, 0xB60C05CA30204D21L, 0x5B068C651810A89EL,
        0x456C34887A3805B9L, 0xAC361A443D1C8CD2L, 0x561B0D22900E4669L, 0x2B838811480723BAL,
        0x9BCF4486248D9F5DL, 0xC3E9224312C8C1A0L, 0xEFFA11AF0964EE50L, 0xF97D86D98A327728L,
        0xE4FA2054A80B329CL, 0x727D102A548B194EL, 0x39B008152ACB8227L, 0x9258048415EB419DL,
        0x492C024284FBAEC0L, 0xAA16012142F35760L, 0x550B8E9E21F7A530L, 0xA48B474F9EF5DC18L,
        0x70A6A56E2440598EL, 0x3853DC371220A247L, 0x1CA76E95091051ADL, 0x0EDD37C48A08A6D8L,
        0x07E095624504536CL, 0x8D70C431AC02A736L, 0xC83862965601DD1BL, 0x641C314B2B8EE083L,
    };

    private static final long[][] T = initTransformationTables();

    private static final byte[] IV = new byte[BLOCK_SIZE];

    public byte[] digest(InputStream inputStream) throws IOException {
        DigestState state = new DigestState();
        byte[] buffer = new byte[BLOCK_SIZE];
        int read;
        while ((read = inputStream.read(buffer)) != -1) {
            state.update(buffer, 0, read);
        }
        byte[] out = new byte[BLOCK_SIZE];
        state.doFinal(out, 0);
        return out;
    }

    public String digestHex(InputStream inputStream) throws IOException {
        byte[] hash = digest(inputStream);
        StringBuilder sb = new StringBuilder(hash.length * 2);
        for (byte b : hash) {
            sb.append(HEX[(b >>> 4) & 0x0F]).append(HEX[b & 0x0F]);
        }
        return sb.toString();
    }

    public static final class DigestState {
        private final byte[] h = new byte[BLOCK_SIZE];
        private final byte[] N = new byte[BLOCK_SIZE];
        private final byte[] Sigma = new byte[BLOCK_SIZE];
        private final byte[] block = new byte[BLOCK_SIZE];
        private final byte[] tmp = new byte[BLOCK_SIZE];
        private final byte[] m = new byte[BLOCK_SIZE];
        private final byte[] Ki = new byte[BLOCK_SIZE];
        private final byte[] ZERO = new byte[BLOCK_SIZE];
        private int bOff = BLOCK_SIZE;

        public DigestState() {
            reset();
        }

        private void reset() {
            bOff = BLOCK_SIZE;
            Arrays.fill(N, (byte) 0);
            Arrays.fill(Sigma, (byte) 0);
            System.arraycopy(IV, 0, h, 0, BLOCK_SIZE);
            Arrays.fill(block, (byte) 0);
        }

        public void update(byte[] data, int off, int len) {
            while (bOff != BLOCK_SIZE && len > 0) {
                update(data[off++]);
                len--;
            }
            while (len >= BLOCK_SIZE) {
                System.arraycopy(data, off, tmp, 0, BLOCK_SIZE);
                reverse(tmp, block);
                gFunction(h, N, block);
                addMod512(N, 512);
                addMod512(Sigma, block);
                off += BLOCK_SIZE;
                len -= BLOCK_SIZE;
            }
            while (len-- > 0) {
                update(data[off++]);
            }
        }

        private void update(byte b) {
            block[--bOff] = b;
            if (bOff == 0) {
                gFunction(h, N, block);
                addMod512(N, 512);
                addMod512(Sigma, block);
                bOff = BLOCK_SIZE;
            }
        }

        int doFinal(byte[] out, int outOff) {
            int gap = BLOCK_SIZE - bOff;
            Arrays.fill(m, 0, BLOCK_SIZE - gap, (byte) 0);
            m[BLOCK_SIZE - 1 - gap] = 1;
            if (bOff != BLOCK_SIZE) {
                System.arraycopy(block, bOff, m, BLOCK_SIZE - gap, gap);
            }
            gFunction(h, N, m);
            addMod512(N, gap * 8);
            addMod512(Sigma, m);
            gFunction(h, ZERO, N);
            gFunction(h, ZERO, Sigma);
            reverse(h, tmp);
            System.arraycopy(tmp, 0, out, outOff, BLOCK_SIZE);
            reset();
            return BLOCK_SIZE;
        }

        private void gFunction(byte[] h, byte[] n, byte[] mVal) {
            System.arraycopy(h, 0, tmp, 0, BLOCK_SIZE);
            xor512(h, n);
            applyF(h);
            encrypt(h, mVal);
            xor512(h, tmp);
            xor512(h, mVal);
        }

        private void encrypt(byte[] state, byte[] blockVal) {
            System.arraycopy(state, 0, Ki, 0, BLOCK_SIZE);
            xor512(state, blockVal);
            applyF(state);
            for (int round = 0; round < 11; round++) {
                xor512(Ki, C[round]);
                applyF(Ki);
                xor512(state, Ki);
                applyF(state);
            }
            xor512(Ki, C[11]);
            applyF(Ki);
            xor512(state, Ki);
        }

        private void applyF(byte[] state) {
            long[] accumulators = new long[8];
            for (int i = 0; i < 8; i++) {
                accumulators[i] = T[0][state[56 + i] & 0xFF]
                        ^ T[1][state[48 + i] & 0xFF]
                        ^ T[2][state[40 + i] & 0xFF]
                        ^ T[3][state[32 + i] & 0xFF]
                        ^ T[4][state[24 + i] & 0xFF]
                        ^ T[5][state[16 + i] & 0xFF]
                        ^ T[6][state[8 + i] & 0xFF]
                        ^ T[7][state[i] & 0xFF];
            }
            for (int i = 0; i < 8; i++) {
                long value = accumulators[i];
                int offset = i * 8;
                state[offset + 7] = (byte) (value >>> 56);
                state[offset + 6] = (byte) (value >>> 48);
                state[offset + 5] = (byte) (value >>> 40);
                state[offset + 4] = (byte) (value >>> 32);
                state[offset + 3] = (byte) (value >>> 24);
                state[offset + 2] = (byte) (value >>> 16);
                state[offset + 1] = (byte) (value >>> 8);
                state[offset] = (byte) value;
            }
        }

        private void xor512(byte[] left, byte[] right) {
            for (int i = 0; i < BLOCK_SIZE; i++) {
                left[i] ^= right[i];
            }
        }

        private void addMod512(byte[] value, int bits) {
            int sum = (value[BLOCK_SIZE - 1] & 0xFF) + (bits & 0xFF);
            value[BLOCK_SIZE - 1] = (byte) sum;
            int carry = sum >>> 8;

            sum = (value[BLOCK_SIZE - 2] & 0xFF) + ((bits >>> 8) & 0xFF) + carry;
            value[BLOCK_SIZE - 2] = (byte) sum;
            carry = sum >>> 8;

            for (int i = BLOCK_SIZE - 3; i >= 0 && carry > 0; i--) {
                sum = (value[i] & 0xFF) + carry;
                value[i] = (byte) sum;
                carry = sum >>> 8;
            }
        }

        private void addMod512(byte[] value, byte[] blockVal) {
            int carry = 0;
            for (int i = BLOCK_SIZE - 1; i >= 0; i--) {
                int sum = (value[i] & 0xFF) + (blockVal[i] & 0xFF) + carry;
                value[i] = (byte) sum;
                carry = sum >>> 8;
            }
        }

        private void reverse(byte[] input, byte[] output) {
            for (int i = 0; i < BLOCK_SIZE; i++) {
                output[i] = input[BLOCK_SIZE - 1 - i];
            }
        }

    }

    private static byte[][] initIterationConstants() {
        byte[][] constants = new byte[C_HEX.length][];
        for (int i = 0; i < C_HEX.length; i++) {
            constants[i] = hexToBytes(C_HEX[i]);
        }
        return constants;
    }

    private static byte[] initSBox() {
        byte[] sbox = new byte[SBOX_DECIMAL.length];
        for (int i = 0; i < SBOX_DECIMAL.length; i++) {
            int decimalValue = SBOX_DECIMAL[i];
            if (decimalValue < 0 || decimalValue > 255) {
                throw new IllegalArgumentException("S-box value out of range: " + decimalValue);
            }
            String hex = String.format(Locale.ROOT, "%02X", decimalValue);
            sbox[i] = (byte) Integer.parseInt(hex, 16);
        }
        return sbox;
    }

    private static byte[] hexToBytes(String hex) {
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            result[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return result;
    }

    private static long[][] initTransformationTables() {
        long[][] tables = new long[8][256];
        byte[] block = new byte[BLOCK_SIZE];
        byte[] spec = new byte[BLOCK_SIZE];
        byte[] buffer = new byte[BLOCK_SIZE];
        for (int table = 0; table < 8; table++) {
            int index = (7 - table) * 8;
            for (int value = 0; value < 256; value++) {
                Arrays.fill(block, (byte) 0);
                block[index] = SBOX[value];
                toSpecOrder(block, spec);
                pTransform(spec, buffer);
                lTransform(spec);
                fromSpecOrder(spec, block);
                tables[7 - table][value] = readBigEndianLong(block, 0);
            }
        }
        return tables;
    }

    private static void lpsTransform(byte[] block, byte[] buffer) {
        byte[] spec = new byte[BLOCK_SIZE];
        byte[] perm = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            block[i] = SBOX[block[i] & 0xFF];
        }
        toSpecOrder(block, spec);
        pTransform(spec, perm);
        lTransform(spec);
        fromSpecOrder(spec, block);
    }

    private static void pTransform(byte[] block, byte[] buffer) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            buffer[i] = block[TAU[i]];
        }
        System.arraycopy(buffer, 0, block, 0, BLOCK_SIZE);
    }

    private static void lTransform(byte[] block) {
        for (int chunk = 0; chunk < 8; chunk++) {
            int offset = chunk * 8;
            long value = 0L;
            for (int i = 0; i < 8; i++) {
                value = (value << 8) | (block[offset + i] & 0xFFL);
            }
            long transformed = mapWithA(value);
            for (int i = 0; i < 8; i++) {
                block[offset + i] = (byte) (transformed >>> (56 - 8 * i));
            }
        }
    }

    private static long mapWithA(long value) {
        long result = 0L;
        for (int bit = 0; bit < 64; bit++) {
            if (((value >>> bit) & 1L) != 0) {
                result ^= LINEAR_MATRIX[63 - bit];
            }
        }
        return result;
    }

    private static long readBigEndianLong(byte[] block, int offset) {
        long value = 0L;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (block[offset + i] & 0xFFL);
        }
        return value;
    }

    private static void toSpecOrder(byte[] source, byte[] target) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            target[i] = source[BLOCK_SIZE - 1 - i];
        }
    }

    private static void fromSpecOrder(byte[] source, byte[] target) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            target[i] = source[BLOCK_SIZE - 1 - i];
        }
    }

}
