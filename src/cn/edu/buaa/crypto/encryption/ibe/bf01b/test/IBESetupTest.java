package cn.edu.buaa.crypto.encryption.ibe.bf01b.test;
import java.io.IOException;

import junit.framework.TestCase;

import org.bouncycastle.crypto.CipherParameters;
import org.junit.Assert;

import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.CPABEEngine;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.IBEBF01bEngine;
import cn.edu.buaa.crypto.utils.TestUtils;

public class IBESetupTest extends TestCase{
	private static IBEBF01bEngine engine;
	
	public static void main(String[] args) throws IOException, ClassNotFoundException {	
		IBESetup IBESetup = new IBESetup();
		IBESetup.IBE01bSetup("IBE_PK.txt", "IBE_MK.txt");
	} 

}
