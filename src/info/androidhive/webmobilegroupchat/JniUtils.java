package info.androidhive.webmobilegroupchat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Map;

public class JniUtils {
    private static final String PUBLIC_KEY = "publicKeyAS.txt";
    private static final String SECRET_KEY = "secretKeyAS.txt";
    private static final String RELINEARIZATION_KEY = "relinearizeKeyAS.txt";
    private static String mFileStorageDirectory;

    static {
        System.loadLibrary("jni_CKKS");//jni规范的so库
    }
    /*****************************************************************CKKS 同态加密部分的接口*********************************************************************/

    /**
     * The native code handle used to encrypt and decrypt data
     */
    private static long mCryptoContext;

    //创建CryptoContext
    public static long createCryptoContext(String fileStorageDirectory, int polyModulus, int scale) throws Exception {
        mFileStorageDirectory = fileStorageDirectory + "/";
        mCryptoContext = nativeCreateCryptoContext(mFileStorageDirectory, polyModulus, scale);
        return mCryptoContext;
    }
    //释放CryptoContext
    public static void releaseCryptoContext() {
        nativeReleaseCryptoContext(mCryptoContext);
    }

    //加载本地密钥
    public static boolean loadLocalKeys(String fileStorageDirectory){
        mFileStorageDirectory = fileStorageDirectory + "/";
        return nativeLoadLocalKeys(mCryptoContext, mFileStorageDirectory + PUBLIC_KEY, mFileStorageDirectory + SECRET_KEY);
    }

    //加载密文
    public static String loadCiphertext(String fileStorageDirectory, String cipherPath){
        mFileStorageDirectory = fileStorageDirectory + "/";
        return nativeLoadCiphertext(mCryptoContext, mFileStorageDirectory + cipherPath);
    }
    
    //加密
    public static String encrypt(double[] values,String ciphertextPath) {
        return nativeEncrypt(mCryptoContext, values, ciphertextPath);
    }
    //解密
    public static double[] decrypt(String base64Input) {
        return nativeDecrypt(mCryptoContext, base64Input);
    }

    //////////////////////////////////////////////////Native 方法//////////////////////////////////////////////////////////////

    /**
     * A native method that is implemented by the 'cryptoadapter' native library,
     * which is packaged with this application.
     */
    public native static long nativeCreateCryptoContext(String fileStorageDirectory, int polyModulus, int scale);

    public native static void nativeReleaseCryptoContext(long cryptoContext);

    public native static String nativeEncrypt(long cryptoContext, double[] values, String ciphertextPath);

    public native static double[] nativeDecrypt(long cryptoContext, String input);

    public native static boolean nativeLoadLocalKeys(long cryptoContext, String publicKeyPath, String secretKeyPath);
    
    public native static String nativeLoadCiphertext(long cryptoContext, String ciphertextPath);
    
    public static double sum(double[] feature) {
    	double sum = 0;
    	for(int i=0; i<512; i++) {
    		sum += feature[i];
    	}
    	return sum;
    }
    
    public static String[] getFilesName(String dir) {
    	File file = new File(dir);
    	String test[];
    	test=file.list();
    	return test;
    }
    
    
    public static String FR(String basicDir, String basicPath)
   	{
        String[] fileNames = getFilesName(basicPath+"\\");
        System.out.println(fileNames.length);
        
   	    try {
           JniUtils.createCryptoContext(basicDir, 8192, 40);
           JniUtils.loadLocalKeys(basicDir); 
           
           //(Alice_0)-double
           Map<String,Double> file2double = new HashMap<String, Double>();
         
           for(int i=0; i<fileNames.length; i++){
               //System.out.println(fileNames[i]);
        	   String  encodedCipher = JniUtils.loadCiphertext(basicPath, fileNames[i]);
               String[] fileNameSplit = fileNames[i].split("\\."); //特殊字符要进行转义
               double[] decryptedCipher = JniUtils.decrypt(encodedCipher);
        	   double sum= sum (decryptedCipher);
        	   double sqrt = Math.sqrt(sum);
        	   file2double.put(fileNameSplit[0], sqrt);  
           }
           JniUtils.releaseCryptoContext();

           //Ali_0 -----1.29 
    	   //Bob_0 -----0.29
    	   //Ali_1 -----0.39
    	   //Bob_1 -----1.37
           Map<String,Double> feature0 = new HashMap<String, Double>();  //Ali_0 -----1.29, Bob_0 -----0.29
           Map<String,Double> feature1 = new HashMap<String, Double>();  //Ali_1 -----0.39, Bob_1 -----1.37
           for(String name:  file2double.keySet()) {
        	   System.out.println(name + " : " +  file2double.get(name));
        	   if(name.contains("0")) {
        		   feature0.put(name, file2double.get(name));
        	   }else if(name.contains("1")) {
        		   feature1.put(name, file2double.get(name));
        	   }
           }
           StringBuilder sb = new StringBuilder();
           for(String name: feature0.keySet()) {
        	   if(feature0.get(name) < 1.1) {
        		   String[] splits = name.split("_");
        		   sb.append(splits[1] + ":" + splits[0] + ";");
        	   }
           }
           
           for(String name: feature1.keySet()) {
        	   if(feature1.get(name) < 1.1) {
        		   String[] splits = name.split("_");
        		   sb.append(splits[1] + ":" + splits[0]);
        	   }
           }

          return sb.toString();
       } catch (Exception e) {
           e.printStackTrace();
       }   
   	    return "";
   	}
    
    
    /**********************************************主程序*******************************************************/
    public static void main(String[] args)
   	{
   		String basicDir = "D:\\Development\\apache-tomcat-7.0.94\\webapps\\images";
        String basicPath = "D:\\Development\\apache-tomcat-7.0.94\\webapps\\images\\CKKS";
        String[] fileNames = getFilesName(basicPath+"\\");
        
   	    try {
           JniUtils.createCryptoContext(basicDir, 8192, 40);
           JniUtils.loadLocalKeys(basicDir); 
           
           //(Alice_0)-double
           Map<String,Double> file2double = new HashMap<String, Double>();
           for(int i=0; i<fileNames.length; i++){
               //System.out.println(fileNames[i]);
        	   String  encodedCipher = JniUtils.loadCiphertext(basicPath, fileNames[i]);
               String[] fileNameSplit = fileNames[i].split("\\."); //特殊字符要进行转义
               double[] decryptedCipher = JniUtils.decrypt(encodedCipher);
        	   double sum= sum (decryptedCipher);
        	   double sqrt = Math.sqrt(sum);
        	   file2double.put(fileNameSplit[0], sqrt);  
           }
           JniUtils.releaseCryptoContext();

           //Ali_0 -----1.29 
    	   //Bob_0 -----0.29
    	   //Ali_1 -----0.39
    	   //Bob_1 -----1.37
           Map<String,Double> feature0 = new HashMap<String, Double>();  //Ali_0 -----1.29, Bob_0 -----0.29
           Map<String,Double> feature1 = new HashMap<String, Double>();  //Ali_1 -----0.39, Bob_1 -----1.37
           for(String name:  file2double.keySet()) {
        	   System.out.println(name + " : " +  file2double.get(name));
        	   if(name.contains("0")) {
        		   feature0.put(name, file2double.get(name));
        	   }else if(name.contains("1")) {
        		   feature1.put(name, file2double.get(name));
        	   }
           }
           StringBuilder sb = new StringBuilder();
           for(String name: feature0.keySet()) {
        	   if(feature0.get(name) < 1.1) {
        		   String[] splits = name.split("_");
        		   sb.append(splits[1] + ":" + splits[0] + ";");
        	   }
           }
           
           for(String name: feature1.keySet()) {
        	   if(feature1.get(name) < 1.1) {
        		   String[] splits = name.split("_");
        		   sb.append(splits[1] + ":" + splits[0]);
        	   }
           }
           
           String result = sb.toString();
           System.out.println("人脸识别结果：" + result);
          
       } catch (Exception e) {
           e.printStackTrace();
       }   
   	}

    
    
}


