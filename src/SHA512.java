import com.sun.security.jgss.GSSUtil;

import java.math.BigInteger;

public class SHA512 {
    private String message;
    private String blockReady;
    private String[] blocks;
    private long[] bufferVal;
    private final int A = 0;
    private final int B = 1;
    private final int C = 2;
    private final int D = 3;
    private final int E = 4;
    private final int F = 5;
    private final int G = 6;
    private final int H = 7;

    long[] keyVal = new long[]{
            0x428A2F98D728AE22L, 0x7137449123EF65CDL, 0xB5C0FBCFEC4D3B2FL, 0xE9B5DBA58189DBBCL, 0x3956C25BF348B538L,
            0x59F111F1B605D019L, 0x923F82A4AF194F9BL, 0xAB1C5ED5DA6D8118L, 0xD807AA98A3030242L, 0x12835B0145706FBEL,
            0x243185BE4EE4B28CL, 0x550C7DC3D5FFB4E2L, 0x72BE5D74F27B896FL, 0x80DEB1FE3B1696B1L, 0x9BDC06A725C71235L,
            0xC19BF174CF692694L, 0xE49B69C19EF14AD2L, 0xEFBE4786384F25E3L, 0x0FC19DC68B8CD5B5L, 0x240CA1CC77AC9C65L,
            0x2DE92C6F592B0275L, 0x4A7484AA6EA6E483L, 0x5CB0A9DCBD41FBD4L, 0x76F988DA831153B5L, 0x983E5152EE66DFABL,
            0xA831C66D2DB43210L, 0xB00327C898FB213FL, 0xBF597FC7BEEF0EE4L, 0xC6E00BF33DA88FC2L, 0xD5A79147930AA725L,
            0x06CA6351E003826FL, 0x142929670A0E6E70L, 0x27B70A8546D22FFCL, 0x2E1B21385C26C926L, 0x4D2C6DFC5AC42AEDL,
            0x53380D139D95B3DFL, 0x650A73548BAF63DEL, 0x766A0ABB3C77B2A8L, 0x81C2C92E47EDAEE6L, 0x92722C851482353BL,
            0xA2BFE8A14CF10364L, 0xA81A664BBC423001L, 0xC24B8B70D0F89791L, 0xC76C51A30654BE30L, 0xD192E819D6EF5218L,
            0xD69906245565A910L, 0xF40E35855771202AL, 0x106AA07032BBD1B8L, 0x19A4C116B8D2D0C8L, 0x1E376C085141AB53L,
            0x2748774CDF8EEB99L, 0x34B0BCB5E19B48A8L, 0x391C0CB3C5C95A63L, 0x4ED8AA4AE3418ACBL, 0x5B9CCA4F7763E373L,
            0x682E6FF3D6B2B8A3L, 0x748F82EE5DEFB2FCL, 0x78A5636F43172F60L, 0x84C87814A1F0AB72L, 0x8CC702081A6439ECL,
            0x90BEFFFA23631E28L, 0xA4506CEBDE82BDE9L, 0xBEF9A3F7B2C67915L, 0xC67178F2E372532BL, 0xCA273ECEEA26619CL,
            0xD186B8C721C0C207L, 0xEADA7DD6CDE0EB1EL, 0xF57D4F7FEE6ED178L, 0x06F067AA72176FBAL, 0x0A637DC5A2C898A6L,
            0x113F9804BEF90DAEL, 0x1B710B35131C471BL, 0x28DB77F523047D84L, 0x32CAAB7B40C72493L, 0x3C9EBE0A15C9BEBCL,
            0x431D67C49C100D4CL, 0x4CC5D4BECB3E42B6L, 0x597F299CFC657E2AL, 0x5FCB6FAB3AD6FAECL, 0x6C44198C4A475817L
    };


    public SHA512(String message) {
        this.message = message;
        initiateBuffers();
        preprocess();
        createBlocks();
        processBlocks();
        String hash = compileHash();
        System.out.println(hash);
    }

    private void initiateBuffers() {
        bufferVal = new long[8];
        bufferVal[0] = 0x6A09E667F3BCC908L;
        bufferVal[1] = 0xBB67AE8584CAA73BL;
        bufferVal[2] = 0x3C6EF372FE94F82BL;
        bufferVal[3] = 0xA54FF53A5F1D36F1L;
        bufferVal[4] = 0x510E527FADE682D1L;
        bufferVal[5] = 0x9B05688C2B3E6C1FL;
        bufferVal[6] = 0x1F83D9ABFB41BD6BL;
        bufferVal[7] = 0x5BE0CD19137E2179L;
    }


    public void preprocess() {
        StringBuilder result = new StringBuilder();
        char[] chars = message.toCharArray();
        for (char aChar : chars) {
            result.append(String.format("%8s", Integer.toBinaryString(aChar)).replaceAll(" ", "0"));
        }
        String leftBlock = Long.toBinaryString(result.length());
        leftBlock = String.format("%128s", leftBlock).replaceAll(" ", "0");
        int currentLen = result.length() + 1 + 128;
        int zeros = 1024 - (currentLen % 1024);
        result.append('1');
        result.append("0".repeat(zeros));
        result.append(leftBlock);
        blockReady = result.toString();
    }

    private void createBlocks() {
        int noOfBlocks = blockReady.length() / 1024;
        blocks = new String[noOfBlocks];
        int startString = 0;
        int endString = 1024;
        for (int i = 0; i < blocks.length; i++) {
            blocks[i] = blockReady.substring(startString, endString);
            startString = startString + 1024;
            endString = endString + 1024;
        }
    }

    private long[] createWords(int index) {
        String[] words = new String[80];
        long[] wordVal = new long[80];
        int startString = 0;
        int endString = 64;
        for (int i = 0; i < 80; i++) {
            if (i < 16) {
                words[i] = blocks[index].substring(startString, endString);
                BigInteger val = new BigInteger(words[i], 2);
                wordVal[i] = val.longValue();
                startString = startString + 64;
                endString = endString + 64;
            } else {
                long value = sigma1512(wordVal[i - 2]) + wordVal[i - 7] + sigma0512(wordVal[i - 15]) + wordVal[i - 16];
                wordVal[i] = value;
            }
        }
        return wordVal;
    }

    public long rotate(long key, int shift) {
        return (key >>> shift) | (key << (Long.SIZE - shift));
    }

    private long sigma0512(long word) {
        long val0 = rotate(word, 1);
        long val1 = rotate(word, 8);
        long val2 = word >>> 7;
        return val0 ^ val1 ^ val2;
    }

    private long sigma1512(long word) {
        long val0 = rotate(word, 19);
        long val1 = rotate(word, 61);
        long val2 = word >>> 6;
        return val0 ^ val1 ^ val2;
    }

    private long[] saveValues() {
        long[] values = new long[8];
        System.arraycopy(bufferVal, 0, values, 0, bufferVal.length);
        return values;
    }

    private void processBlocks() {
        long[] words;
        for (int i = 0; i < blocks.length; i++) {
            words = createWords(i);
            long[] prev = saveValues();
            for (int j = 0; j < 80; j++) {
                long t1 = calculateT1(words[j], keyVal[j]);
                long t2 = calculateT2();
                bufferVal[H] = bufferVal[G];
                bufferVal[G] = bufferVal[F];
                bufferVal[F] = bufferVal[E];
                bufferVal[E] = calculateE(t1);
                bufferVal[D] = bufferVal[C];
                bufferVal[C] = bufferVal[B];
                bufferVal[B] = bufferVal[A];
                bufferVal[A] = calculateA(t1, t2);
                System.out.println("t:" + j + " " + Long.toHexString(bufferVal[0]) + " " + Long.toHexString(bufferVal[1]) + " " + Long.toHexString(bufferVal[2]) + " " + Long.toHexString(bufferVal[3]));
                System.out.println("t:" + j + " " + Long.toHexString(bufferVal[4]) + " " + Long.toHexString(bufferVal[5]) + " " + Long.toHexString(bufferVal[6]) + " " + Long.toHexString(bufferVal[7]));
            }
            long[] recent = saveValues();
            System.out.println("prev\t\t\t\t\t\trecent\t\t\t\t\t\tresult");
            for (int j = 0; j < 8; j++) {
                bufferVal[j] = prev[j] + recent[j];
                System.out.println(Long.toHexString(prev[j]) + "\t+\t" + Long.toHexString(recent[j]) + "\t=\t" + Long.toHexString(bufferVal[j]));
            }
            System.out.println();
        }
    }

    private String compileHash() {
        StringBuilder hash = new StringBuilder();
        hash.append("hash: ");
        for (long buffer : bufferVal) {
            hash.append(Long.toHexString(buffer));
        }
        return hash.toString();
    }

    private long calculateA(long t1, long t2) {
        return t1 + t2;
    }

    private long calculateE(long t1) {
        return t1 + bufferVal[D];
    }

    private long calculateT1(long word, long key) {
        return bufferVal[H] + ch() + sig1512() + word + key;
    }

    private long calculateT2() {
        return sig0512() + maj();
    }

    private long sig0512() {
        long value = bufferVal[A];
        return rotate(value, 28) ^ rotate(value, 34) ^ rotate(value, 39);
    }

    private long sig1512() {
        long value = bufferVal[E];
        return rotate(value, 14) ^ rotate(value, 18) ^ rotate(value, 41);
    }

    private long ch() {
        return (bufferVal[E] & bufferVal[F]) ^ (~bufferVal[E] & bufferVal[G]);
    }

    private long maj() {
        return (bufferVal[A] & bufferVal[B]) ^ (bufferVal[B] & bufferVal[C]) ^ (bufferVal[C] & bufferVal[A]);
    }


    public static void main(String[] args) {
        String bit24 = "abc";
        String empty = "";
        String bit448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        String bit896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        System.out.println("Hash for empty string " + "\"\"");
        SHA512 s1 = new SHA512(empty);
        System.out.println("Hash for 24 bit string: " + bit24);
        SHA512 s0 = new SHA512(bit24);
        System.out.println("Hash for 448 bit string " + bit448);
        SHA512 s2 = new SHA512(bit448);
        System.out.println("Hash for 896 bit string " + bit896);
        SHA512 s3 = new SHA512(bit896);

    }
}
