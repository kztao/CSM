import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import javax.security.auth.x500.X500Principal;

public class GenCrt {
    /** 指定加密算法为RSA */
    private static final String ALGORITHM = "RSA";
    /** 密钥长度，用来初始化 */
    private static final int KEYSIZE = 2048;
    /** 指定公钥存放文件 */
    private static String PUBLIC_KEY_FILE = "PublicKey";
    /** 指定私钥存放文件 */
    private static String PRIVATE_KEY_FILE = "PrivateKey";

    private String apkPath = "";
    private String certPath = "";
    private String apkPackageName = "";
    private byte[] finger = null;

    public GenCrt(String apkPath){
        this.apkPath = apkPath;
        certPath = String.format("%s%s",apkPath.substring(0,apkPath.lastIndexOf("/")),"/csm.cer");
        File file = new File(certPath);
        if(file.exists()){
            file.delete();
        }
    }

    private void getApkRSACert(){
        try {

            ZipFile zipFile = new ZipFile(apkPath);
            InputStream inputStream = new FileInputStream(apkPath);
            ZipInputStream zipInputStream = new ZipInputStream(inputStream);
            ZipEntry zipEntry;
            File file = null;

            while ((zipEntry = zipInputStream.getNextEntry()) != null){
                if(zipEntry.getName().equals("META-INF/CERT.RSA")){
                    file = new File(String.format("%s%s",apkPath.substring(0,apkPath.lastIndexOf("/")),"/CERT.RSA"));
                    if(!file.exists()){
                        file.createNewFile();
                    }

                    InputStream stream = zipFile.getInputStream(zipEntry);
                    OutputStream outputStream = new FileOutputStream(file);

                    int c = 0;
                    while ((c= stream.read()) != -1){
                        outputStream.write(c);
                    }

                    stream.close();
                    outputStream.close();
                    break;
                }
            }

            zipInputStream.close();
            inputStream.close();

            finger = getApkSha256(String.format("%s%s",apkPath.substring(0,apkPath.lastIndexOf("/")),"/CERT.RSA"));
            if(file != null){
                file.delete();
            }

        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("zipFile is error");
        }
    }


    private byte[] getApkSha256(String cert){
        String cmd = "keytool -printcert -file "+cert;
        Runtime runtime = Runtime.getRuntime();
        try {
            Process process = runtime.exec(cmd);
            BufferedInputStream in = new BufferedInputStream(process.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
            String lineStr;
            while ((lineStr = inBr.readLine()) != null)
                //获得命令执行后在控制台的输出信息
                if(lineStr.contains("SHA256: ")){
                    String Sha256 = lineStr.substring(lineStr.indexOf("SHA256: ") + "SHA256: ".length());
                    if(Sha256.length() == 95){
                        System.out.println(Sha256);
                        byte[] out = new byte[32];

                        for(int i = 0;i<out.length;i++){
                            out[i] = (byte) (Integer.parseInt(Sha256.substring(3*i,3*i+2),16));
                        }

                        return out;
                    }

                    System.out.println(Sha256.length());
                }

            //检查命令是否执行失败。
            if (process.waitFor() != 0) {
                if (process.exitValue() == 1)//p.exitValue()==0表示正常结束，1：非正常结束
                    System.err.println("命令执行失败!");
            }
            inBr.close();
            in.close();
        }catch (Exception e){

        }

        return null;

    }


    private String getApkPackageName() {
        Runtime runtime = Runtime.getRuntime();
        String cmd = String.format("%s%s", "aapt dump badging ", apkPath);
        String out = "";
        try {
            Process process = runtime.exec(cmd);
            BufferedInputStream in = new BufferedInputStream(process.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
            String lineStr;
            while ((lineStr = inBr.readLine()) != null)
                //获得命令执行后在控制台的输出信息
                if(lineStr.contains("package: name='")){
                    String head = lineStr.substring(lineStr.indexOf("=") + 2);
                    out = head.substring(0,head.indexOf("'"));
                    System.out.println(out);
                    break;
                }
            //检查命令是否执行失败。
            if (process.waitFor() != 0) {
                if (process.exitValue() == 1)//p.exitValue()==0表示正常结束，1：非正常结束
                    System.err.println("命令执行失败!");
            }
            inBr.close();
            in.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return out;
    }


    public void genApkCert()throws Exception{
        apkPackageName = getApkPackageName();
        getApkRSACert();
        genPair();
    }


    private void genPair()throws Exception{
        SecureRandom secureRandom = new SecureRandom();
        /*KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEYSIZE,secureRandom);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        ObjectOutputStream puk = new ObjectOutputStream(new FileOutputStream("puk"));
        puk.writeObject(publicKey);
        puk.close();

        ObjectOutputStream pri = new ObjectOutputStream(new FileOutputStream("pri"));
        pri.writeObject(privateKey);
        pri.close();*/


        ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("puk"));
        PublicKey key = (PublicKey) inputStream.readObject();
        inputStream.close();


        inputStream = new ObjectInputStream(new FileInputStream("pri"));
        PrivateKey key1 = (PrivateKey)inputStream.readObject();
        inputStream.close();


        /*MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update("hello".getBytes());
        byte[] hash = messageDigest.digest();

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key1);
        signature.update(hash);
        byte[] sign = signature.sign();

        Signature signature1 = Signature.getInstance("SHA256withRSA");
        signature1.initVerify(key);
        signature1.update(hash);
        boolean b = signature1.verify(sign);

        System.out.println("sign is "+ b);




        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE,key);
        byte[] bytes = cipher.doFinal(new byte[]{1,2,3,4});

        System.out.println("cipher is " + Arrays.toString(bytes));

        Cipher cipher1 = Cipher.getInstance(ALGORITHM);
        cipher1.init(Cipher.DECRYPT_MODE,key1);
        byte[] bytes1 = cipher1.doFinal(bytes);

        System.out.println("plain is "+Arrays.toString(bytes1));


        System.out.println("puk result is "+publicKey.equals(key));
        System.out.println("pri result is "+privateKey.equals(key1));*/

        if(finger != null){
            X509V3CertificateGenerator x509V3CertificateGenerator = new X509V3CertificateGenerator();
            x509V3CertificateGenerator.setPublicKey(key);
            x509V3CertificateGenerator.setSignatureAlgorithm("SHA256withRSA");
            x509V3CertificateGenerator.setSerialNumber(BigInteger.ONE);
            x509V3CertificateGenerator.setIssuerDN(new X500Principal("C=CN,ST=SC,L=CD,O=WESTONE,OU=YDHLW,CN=ADMIN"));
            x509V3CertificateGenerator.setSubjectDN(new X500Principal("C=CN,ST=SC,L=CD,O=WESTONE,OU=YDHLW,CN=" + apkPackageName));

            x509V3CertificateGenerator.setNotBefore(new Date());
            Calendar calendar = Calendar.getInstance();
            calendar.set(Calendar.YEAR,calendar.get(Calendar.YEAR) + 100);
            x509V3CertificateGenerator.setNotAfter(calendar.getTime());
            x509V3CertificateGenerator.addExtension("1.3.5",false,finger);

            X509Certificate x509Certificate = x509V3CertificateGenerator.generate(key1,secureRandom);

            FileOutputStream crtOut = new FileOutputStream(certPath);
            crtOut.write(x509Certificate.getEncoded());
            crtOut.close();

            InputStream stream = new FileInputStream(certPath);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate =(X509Certificate) certificateFactory.generateCertificate(stream);
            stream.close();

            System.out.println("puk is "+certificate.getPublicKey().equals(key));
        }
    }


    public static void main(String[] args){
        GenCrt crt = new GenCrt("./app-release.apk");
        try {
            crt.genApkCert();
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
