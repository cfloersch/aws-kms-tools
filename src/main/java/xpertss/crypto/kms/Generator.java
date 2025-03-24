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

        if(args.length < 1) {
            System.out.println("Usage: Generator <keyId>");
            System.exit(1);
        }

        String keyId = args[0];

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
                .cn("kms.aws.amazon.com")
                .ou("AWS")
                .o("Amazon")
                .l("Sao Paulo")
                .st("Sao Paulo")
                .c("BR")
                .mail("kms@amazon.com")
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
