import org.bouncycastle.crypto.digests.GOST3411_2012Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import com.example.ib.crypto.Gost34112012Hasher;

import java.lang.reflect.Field;
import java.util.HexFormat;

public class DebugCompareUpdate {
    private static byte[] getField(Object obj, Class<?> owner, String name) throws Exception {
        Field f = owner.getDeclaredField(name);
        f.setAccessible(true);
        return (byte[]) f.get(obj);
    }
    private static int getFieldInt(Object obj, Class<?> owner, String name) throws Exception {
        Field f = owner.getDeclaredField(name);
        f.setAccessible(true);
        return f.getInt(obj);
    }

    private static void printState(String label, byte[] h, byte[] n, byte[] sigma, int bOff) {
        HexFormat hf = HexFormat.of().withUpperCase();
        System.out.println(label + " h=" + hf.formatHex(h));
        System.out.println("       N=" + hf.formatHex(n));
        System.out.println("       Sigma=" + hf.formatHex(sigma));
        System.out.println("       bOff=" + bOff);
    }

    public static void main(String[] args) throws Exception {
        byte[] data = new byte[64];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }

        GOST3411_2012_512Digest bc = new GOST3411_2012_512Digest();
        bc.update(data, 0, data.length);
        Class<?> superCls = GOST34112012Hasher.class.getSuperclass();
        superCls = GOST3411_2012Digest.class;
        byte[] bcH = getField(bc, superCls, "h");
        byte[] bcN = getField(bc, superCls, "N");
        byte[] bcSigma = getField(bc, superCls, "Sigma");
        int bcBOff = getFieldInt(bc, superCls, "bOff");

        Gost34112012Hasher.DigestState ours = new Gost34112012Hasher.DigestState();
        ours.update(data, 0, data.length);
        Field hField = Gost34112012Hasher.DigestState.class.getDeclaredField("h");
        hField.setAccessible(true);
        byte[] ourH = (byte[]) hField.get(ours);
        Field nField = Gost34112012Hasher.DigestState.class.getDeclaredField("N");
        nField.setAccessible(true);
        byte[] ourN = (byte[]) nField.get(ours);
        Field sigmaField = Gost34112012Hasher.DigestState.class.getDeclaredField("Sigma");
        sigmaField.setAccessible(true);
        byte[] ourSigma = (byte[]) sigmaField.get(ours);
        Field bOffField = Gost34112012Hasher.DigestState.class.getDeclaredField("bOff");
        bOffField.setAccessible(true);
        int ourBOff = bOffField.getInt(ours);

        printState("BC", bcH.clone(), bcN.clone(), bcSigma.clone(), bcBOff);
        printState("Ours", ourH.clone(), ourN.clone(), ourSigma.clone(), ourBOff);
    }
}
