package trabe.lw14;

import it.unisa.dia.gas.jpbc.Element;
import trabe.AbeDecryptionException;
import trabe.AbePrivateKey;
import trabe.AbePublicKey;
import trabe.policyparser.ParseException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Lw14MockBlackBox extends Lw14DecryptionBlackBox {

    private final List<AbePrivateKey> userKeys;
    private final AbePublicKey publicKey;

    public Lw14MockBlackBox(final List<AbePrivateKey> userKeys, final AbePublicKey publicKey) {
        this.userKeys = userKeys;
        this.publicKey = publicKey;
    }

    public Lw14MockBlackBox(final AbePrivateKey[] userKeys, final AbePublicKey publicKey) {
        this.userKeys = new ArrayList<AbePrivateKey>(userKeys.length);
        Collections.addAll(this.userKeys, userKeys);
        this.publicKey = publicKey;
    }

    /**
     * Determine if the given cipher text can be decrypted using this black box.
     *
     * @param ct Cipher text
     * @return is decryptable
     */
    @Override
    public Element decrypt(final CipherText ct) {
        for(final AbePrivateKey key : userKeys) {
            try {
                if (Lw14.canDecrypt(key, ct)) {
                    return Lw14.decrypt(key, ct);
                }
            } catch (ParseException e) {
                System.err.println("Decrypting with key with index " + userKeys.indexOf(key) + " failed");
                e.printStackTrace();
            } catch (AbeDecryptionException e) {
                e.printStackTrace();
            }
        }
        return null;
    }
}
