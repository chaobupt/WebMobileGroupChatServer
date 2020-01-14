package cn.edu.buaa.crypto.encryption.abe.cpabe.MHOO.test;

import java.io.IOException;

import org.bouncycastle.crypto.CipherParameters;
import org.junit.Assert;

import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.MHOO.CPABEMHOOEngine;
import cn.edu.buaa.crypto.utils.TestUtils;


public class MHOOKeyGenTest {
	static String[] Alice_S_satisfied = new String[]{"1", "acquaintance", "classmate", "scl=4", "ts=2019-09-30 08:10:30:360", "te=2020-01-01 08:10:30:360"};
	static String[] Bob_S_satisfied = new String[]{"1", "2", "acquaintance", "classmate", "friend", "scl=5", "ts=2019-09-10 08:10:30:360", "te=2020-01-01 08:10:30:360"};

	public static void main(String[] args) throws IOException, ClassNotFoundException {
		MHOOKeyGen mMHOOKeyGen = new MHOOKeyGen();
	    mMHOOKeyGen.CPABEMHOOKeyGen("MHOO_PK.txt", "MHOO_MK.txt", Alice_S_satisfied, "MHOO_SK_Ali.txt");
	    mMHOOKeyGen.CPABEMHOOKeyGen("MHOO_PK.txt", "MHOO_MK.txt", Bob_S_satisfied, "MHOO_SK_Bob.txt");
	} 
}
