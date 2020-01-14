package cn.edu.buaa.crypto.encryption.ibe.bf01b.test;

import java.io.IOException;

import org.bouncycastle.crypto.CipherParameters;
import org.junit.Assert;

import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.IBEBF01bEngine;
import cn.edu.buaa.crypto.utils.TestUtils;


public class IBEKeyGenTest {
	
    private static final String identity_1 = "Ali";
    private static final String identity_2 = "Bob";
    
	public static void main(String[] args) throws IOException, ClassNotFoundException {
		IBEKeyGen mIBEKeyGen = new IBEKeyGen();
		mIBEKeyGen.IBE01bKeyGen("IBE_PK.txt", "IBE_MK.txt", identity_1, "IBE_SK_Ali.txt");
		mIBEKeyGen.IBE01bKeyGen("IBE_PK.txt", "IBE_MK.txt", identity_2, "IBE_SK_Bob.txt");
	} 
}
