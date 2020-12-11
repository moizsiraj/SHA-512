import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.Arrays;

public class SHA512 {
    private String message;
    private String[] blocks;
    private String[] buffers;
    private String[] keys;
    private final int A = 0;
    private final int B = 1;
    private final int C = 2;
    private final int D = 3;
    private final int E = 4;
    private final int F = 5;
    private final int G = 6;
    private final int H = 7;

    String keyString = "0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538," +
            "              0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe," +
            "              0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235," +
            "              0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65," +
            "              0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab," +
            "              0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725," +
            "              0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed," +
            "              0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b," +
            "              0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218," +
            "              0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53," +
            "              0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373," +
            "              0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec," +
            "              0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c," +
            "              0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6," +
            "              0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc," +
            "              0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817";


    public SHA512(String message) {
        this.message = message;
        buffers = new String[8];
        buffers[0] = "6A09E667F3BCC908";
        buffers[1] = "BB67AE8584CAA73B";
        buffers[2] = "3C6EF372FE94F82B";
        buffers[3] = "A54FF53A5F1D36F1";
        buffers[4] = "510E527FADE682D1";
        buffers[5] = "9B05688C2B3E6C1F";
        buffers[6] = "1F83D9ABFB41BD6B";
        buffers[7] = "5BE0CD19137E2179";
        readyKeys();

    }

    private void readyKeys() {
        keys = keyString.split(",");
        for (int i = 0; i < keys.length; i++) {
            keys[i] = keys[i].trim().substring(2);
        }
    }


    public String preprocess(String input) {
        StringBuilder result = new StringBuilder();
        char[] chars = input.toCharArray();
        for (char aChar : chars) {
            result.append(String.format("%8s", Integer.toBinaryString(aChar)).replaceAll(" ", "0"));
        }
        String leftBlock = Integer.toBinaryString(result.length());
        leftBlock = String.format("%128s", leftBlock).replaceAll(" ", "0");
        int currentLen = result.length() + 1 + 128;
        int zeros = 1024 - (currentLen % 1024);
        result.append('1');
        result.append("0".repeat(zeros));
        result.append(leftBlock);
        System.out.println(result.length());
        String hexString = new BigInteger(result.toString(), 2).toString(16);
        return hexString;
    }

    private void createBlocks(String message) {
        String blockReady = preprocess(message);
        int noOfBlocks = message.length() / 1024;
        blocks = new String[noOfBlocks];
        int startString = 0;
        int endString = 1024;
        for (int i = 0; i < blocks.length; i++) {
            blocks[i] = blockReady.substring(startString, endString);
            startString = startString + 1024;
            endString = endString + 1024;
        }
    }

    private String[] createWords(int index) {
        String[] words = new String[80];
        int startString = 0;
        int endString = 64;
        for (int i = 0; i < blocks.length; i++) {
            if (i < 16) {
                words[i] = blocks[index].substring(startString, endString);
                startString = startString + 64;
                endString = endString + 64;
            } else {
                long value = sigma1512(words[i - 2]) ^ Integer.valueOf(words[i - 7], 2)
                        ^ sigma0512(words[i - 15]) ^ Integer.valueOf(words[i - 16], 2);
                words[i] = Long.toBinaryString(value);
            }
        }
        return words;
    }

    private String leftShift(String key, int shift) {
        return key.substring(shift) + "0".repeat(shift);
    }

    private String rightShift(String key, int shift) {
        int shiftIndex = key.length() - shift;
        return key.substring(shiftIndex) + key.substring(0, shiftIndex);
    }

    private long sigma0512(String binary) {
        long val0 = Long.valueOf(rightShift(binary, 1), 2);
        long val1 = Long.valueOf(rightShift(binary, 8), 2);
        long val2 = Long.valueOf(leftShift(binary, 7), 2);
        return (long) ((val0 + val1 + val2) % Math.pow(2, 64));
    }

    private long sigma1512(String binary) {
        long val0 = Long.valueOf(rightShift(binary, 19), 2);
        long val1 = Long.valueOf(rightShift(binary, 61), 2);
        long val2 = Long.valueOf(leftShift(binary, 9), 2);
        return (long) ((val0 + val1 + val2) % Math.pow(2, 64));
    }

    private void processBlocks() {
        String[] words;
        for (int i = 0; i < blocks.length; i++) {
            words = createWords(i);
            for (int j = 0; j < 80; j++) {
                String t1 = calculateT1(words[j], keys[j]);
                String t2 = calculateT2();
                buffers[H] = buffers[G];
                buffers[G] = buffers[F];
                buffers[F] = buffers[E];
                buffers[E] = calculateE(t1);
                buffers[D] = buffers[C];
                buffers[C] = buffers[B];
                buffers[B] = buffers[A];
                buffers[A] = calculateA(t1, t2);
            }
        }
    }

    private String calculateA(String t1, String t2) {
        long val0 = Long.valueOf(t1, 2);
        long val1 = Long.valueOf(t2, 2);
        long value = (long) ((val0 + val1) % Math.pow(2, 64));
        return Long.toBinaryString(value);
    }

    private String calculateE(String t1) {
        long val0 = Long.valueOf(t1, 2);
        String binary = hexToBinary(buffers[D]);
        long val1 = Long.valueOf(binary, 2);
        long value = (long) ((val0 + val1) % Math.pow(2, 64));
        return Long.toBinaryString(value);
    }

    private String calculateT1(String word, String key) {
        long h = Long.valueOf(hexToBinary(buffers[H]), 2);
        long keyVal = Long.valueOf(hexToBinary(key), 2);
        long wordVal = Long.valueOf(word, 2);
        long value = (long) ((h + ch() + sig1512(E) + wordVal + keyVal) % Math.pow(2, 64));
        return Long.toBinaryString(value);
    }

    private String calculateT2() {
        long value = (long) ((sig0512(A) + maj()) % Math.pow(2, 64));
        return Long.toBinaryString(value);

    }

    private long sig0512(int buffer) {
        return 0;
    }

    private long sig1512(int buffer) {
        return 0;
    }

    private long ch() {
        return 0;
    }

    private long maj() {
        return 0;
    }

    static String hexToBinary(String hex) {
        StringBuilder binary = new StringBuilder();
        for (int i = 0; i < hex.length(); i++) {
            String char_temp = String.valueOf(hex.charAt(i));
            String bin_temp = new BigInteger(char_temp, 16).toString(2);
            switch (bin_temp.length()) {
                case 1:
                    bin_temp = "000" + bin_temp;
                    binary.append(bin_temp);
                    break;
                case 2:
                    bin_temp = "00" + bin_temp;
                    binary.append(bin_temp);
                    break;
                case 3:
                    bin_temp = "0" + bin_temp;
                    binary.append(bin_temp);
                    break;
                case 4:
                    binary.append(bin_temp);
                    break;
            }
        }
        return binary.toString();
    }

    public static void main(String[] args) {
        SHA512 s = new SHA512("One advanced diverted domestic sex repeated bringing you old. Possible procured her trifling laughter thoughts property she met way. Companions shy had solicitude favourable own. Which could saw guest man now heard but. Lasted my coming uneasy marked so should. Gravity letters it amongst herself dearest an windows by. Wooded ladies she basket season age her uneasy saw. Discourse unwilling am no described dejection incommode no listening of. Before nature his parish boy. \n" +
                "\n" +
                "Folly words widow one downs few age every seven. If miss part by fact he park just shew. Discovered had get considered projection who favourable. Necessary up knowledge it tolerably. Unwilling departure education is be dashwoods or an. Use off agreeable law unwilling sir deficient curiosity instantly. Easy mind life fact with see has bore ten. Parish any chatty can elinor direct for former. Up as meant widow equal an share least. \n" +
                "\n" +
                "Another journey chamber way yet females man. Way extensive and dejection get delivered deficient sincerity gentleman age. Too end instrument possession contrasted motionless. Calling offence six joy feeling. Coming merits and was talent enough far. Sir joy northward sportsmen education. Discovery incommode earnestly no he commanded if. Put still any about manor heard. \n" +
                "\n" +
                "Village did removed enjoyed explain nor ham saw calling talking. Securing as informed declared or margaret. Joy horrible moreover man feelings own shy. Request norland neither mistake for yet. Between the for morning assured country believe. On even feet time have an no at. Relation so in confined smallest children unpacked delicate. Why sir end believe uncivil respect. Always get adieus nature day course for common. My little garret repair to desire he esteem. ");
//        System.out.println(s.preprocess("abc"));
    }
}
