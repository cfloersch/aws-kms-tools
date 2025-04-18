package xpertss.crypto.kms;

import software.amazon.awssdk.services.kms.KmsClient;
import xpertss.crypto.kms.crt.SelfSignedCrtGenerator;
import xpertss.crypto.kms.csr.CsrGenerator;
import xpertss.crypto.kms.csr.CsrInfo;
import xpertss.crypto.kms.provider.KmsProvider;
import xpertss.crypto.kms.provider.rsa.KmsRSAKeyFactory;
import xpertss.crypto.kms.provider.signature.KmsSigningAlgorithm;

import java.security.KeyPair;
import java.security.Security;

public class Generator {

    String SIGN_RSA = "20a2af5d-f5e0-4063-a7cd-c06853311513";


    public static void main(String[] args) throws Exception {

        if(args.length != 1 && args.length != 3) {
            System.out.println("Usage: Generator [-dname x500Name] <keyId>");
            System.exit(1);
        }

        String keyId = args[args.length - 1];
        if(args.length > 1) {

        }

        // EMAILADDRESS=siteops@manheim.com, CN="Cox Automotive, Inc", O="Cox Automotive, Inc", L=Atlanta, ST=Georgia, C=US
        /*
            #6: ObjectId: 2.5.29.37 Criticality=false
            ExtendedKeyUsages [
                codeSigning
            ]

            #7: ObjectId: 2.5.29.15 Criticality=true
            KeyUsage [
                DigitalSignature
            ]
         */
        KmsClient kmsClient = KmsClient.builder().build();
        Security.addProvider(new KmsProvider(kmsClient));

        KeyPair keyPair = KmsRSAKeyFactory.getKeyPair(kmsClient, keyId);
        KmsSigningAlgorithm kmsSigningAlgorithm = KmsSigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_256;

        // TODO Add an interactive builder for this or maybe require it passed in?
        CsrInfo csrInfo = CsrInfo.builder()
                .cn("Cox Automotive, Inc")
                //.ou("AWS")
                .o("Cox Automotive, Inc")
                .l("Atlanta")
                .st("Georgia")
                .c("US")
                .mail("siteops@manheim.com")
                .build();

        System.out.println("CSR Info: " + csrInfo.toString());
        System.out.println();

        String csr = CsrGenerator.generate(keyPair, csrInfo, kmsSigningAlgorithm);
        System.out.println("CSR:");
        System.out.println(csr);

        String crt = SelfSignedCrtGenerator.generate(keyPair, csr, kmsSigningAlgorithm, 365);
        System.out.println("CRT:");
        System.out.println(crt);
    }


}
