package com.westone.csm;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

class CertVerifyImp implements CertVerify {
    private PackageManager packageManager = null;

    public CertVerifyImp(Context context){
        packageManager = context.getPackageManager();
    }

 /*   private String GetPackageName(){
        return null;
    }*/
    @Override
    public boolean verify(String packageName,byte[] fingerPrint) {
        Log.i("csm_verify","verify packageName = " + packageName + ",finger = " + Arrays.toString(fingerPrint));
        LogUtils.i("csm_"+CertVerifyImp.class.toString(),"IN");
        if(packageName.isEmpty() || fingerPrint.length < 32){
            LogUtils.i("csm_"+CertVerifyImp.class.toString(),
                    "packageName = " + packageName+",fingerPrint.length = "+fingerPrint.length);
            return false;
        }

        PackageInfo packageInfo = null;

        LogUtils.i("csm_"+CertVerifyImp.class.toString(),"Begin find " + packageName + ",getPackageInfo");
        try{
            packageInfo = packageManager.getPackageInfo(packageName,PackageManager.GET_SIGNATURES);
        }catch (Exception e){
            e.printStackTrace();
            return false;
        }
        if(packageInfo == null || packageInfo.signatures == null){
            if(packageInfo == null){
                LogUtils.i("csm_"+CertVerifyImp.class.toString(),"packageInfo = null");
                return false;
            }

            if(packageInfo.signatures == null){
                LogUtils.i("csm_"+CertVerifyImp.class.toString(),"packageInfo.signatures = null");
                return false;
            }
        }

        LogUtils.i("csm_"+CertVerifyImp.class.toString(),"sign num = "+ packageInfo.signatures.length);
        for (int i = 0; i < packageInfo.signatures.length;i++){
            try {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                X509Certificate certificate = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(packageInfo.signatures[i].toByteArray()));
                certificate.verify(certificate.getPublicKey());

                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                messageDigest.update(certificate.getEncoded());

                if(Arrays.equals(fingerPrint,messageDigest.digest())){
                    LogUtils.i("csm_"+CertVerifyImp.class.toString(),"digest is success");
                    return true;
                }else {
                    LogUtils.i("csm_"+CertVerifyImp.class.toString(),"digest is failed");
                }

            }catch (Exception e){
                e.printStackTrace();
                return false;
            }
        }
     //   LogUtils.i("csm_"+CertVerifyImp.class.toString(),"OUT");
        return false;
    }
}
