import java.math.BigInteger;

public class SHA512 {
    private String message;
    private String[] blocks;
    private String[] buffers;
    private final int A = 0;
    private final int B = 1;
    private final int C = 2;
    private final int D = 3;
    private final int E = 4;
    private final int F = 5;
    private final int G = 6;
    private final int H = 7;


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

    private void processRounds() {
        String[] words;
        for (int i = 0; i < blocks.length; i++) {
            words = createWords(i);
            for (int j = 0; j < 80; j++) {

            }
        }
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
