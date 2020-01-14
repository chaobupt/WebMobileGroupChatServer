package cn.edu.buaa.crypto.encryption.abe.cpabe.MHOO.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Hohenberger-Waters-14 OO-CP-ABE intermediate ciphertext parameter.
 */
public class CPABEMHOOIntermediateSerParameter2 extends PairingCipherSerParameter{
    private final int P;

    private transient Element si;
    private final byte[] byteArrayS;

    private transient Element[] fais;
    private final byte[][] byteArraysFais;

    private transient Element[] ts;
    private final byte[][] byteArraysTs;

    private transient Element[] xs;
    private final byte[][] byteArraysXs;
    
    private transient Element sessionKey;
    private final byte[] byteArraySessionKey;
    
    private transient Element C;
    private final byte[] byteArrayC;
    
    private transient Element C0;
    private final byte[] byteArrayC0;

    private transient Element[] C1s;
    private final byte[][] byteArraysC1s;

    private transient Element[] C2s;
    private final byte[][] byteArraysC2s;

    private transient Element[] C3s;
    private final byte[][] byteArraysC3s;

    public CPABEMHOOIntermediateSerParameter2(
            PairingParameters parameters, int P,
            Element si, Element[] fais, Element[] xs, Element[] ts, Element sessionKey, 
            Element C, Element C0, Element[] C1s, Element[] C2s, Element[] C3s) {
        super(parameters);
        this.P = P;

        this.si = si.getImmutable();
        this.byteArrayS = this.si.toBytes();

        this.fais = ElementUtils.cloneImmutable(fais);
        this.byteArraysFais = PairingUtils.GetElementArrayBytes(this.fais);

        this.ts = ElementUtils.cloneImmutable(ts);
        this.byteArraysTs = PairingUtils.GetElementArrayBytes(this.ts);

        this.xs = ElementUtils.cloneImmutable(xs);
        this.byteArraysXs = PairingUtils.GetElementArrayBytes(this.xs);

        this.sessionKey = sessionKey.getImmutable();
        this.byteArraySessionKey = this.sessionKey.toBytes();
        
        this.C = C.getImmutable();
        this.byteArrayC = this.C.toBytes();        

        this.C0 = C0.getImmutable();
        this.byteArrayC0 = this.C0.toBytes();

        this.C1s = ElementUtils.cloneImmutable(C1s);
        this.byteArraysC1s = PairingUtils.GetElementArrayBytes(this.C1s);

        this.C2s = ElementUtils.cloneImmutable(C2s);
        this.byteArraysC2s = PairingUtils.GetElementArrayBytes(this.C2s);

        this.C3s = ElementUtils.cloneImmutable(C3s);
        this.byteArraysC3s = PairingUtils.GetElementArrayBytes(this.C3s);
    }

    public int getP() { return this.P; }
    
    public Element getSi() { return this.si.duplicate(); }

    public Element[] getFais() { return ElementUtils.duplicate(fais); }

    public Element getFaisAt(int index) { return this.fais[index].duplicate(); }

    public Element[] getXs() { return ElementUtils.duplicate(this.xs); }

    public Element getXsAt(int index) { return this.xs[index].duplicate(); }
    
    public Element[] getTs() { return ElementUtils.duplicate(this.ts); }

    public Element getTsAt(int index) { return this.ts[index].duplicate(); }
    
    public Element getSessionKey() { return this.sessionKey.duplicate(); }
    
    
    public Element getC() { return this.C.duplicate(); }
    
    public Element getC0() { return this.C0.duplicate(); }

    public Element[] getC1s() { return ElementUtils.duplicate(this.C1s); }

    public Element getC1sAt(int index) { return this.C1s[index].duplicate(); }

    public Element[] getC2s() { return ElementUtils.duplicate(this.C2s); }

    public Element getC2sAt(int index) { return this.C2s[index].duplicate(); }

    public Element[] getC3s() { return ElementUtils.duplicate(this.C3s); }

    public Element getC3sAt(int index) { return this.C3s[index].duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABEMHOOIntermediateSerParameter2) {
            CPABEMHOOIntermediateSerParameter2 that = (CPABEMHOOIntermediateSerParameter2)anObject;
            //compare P
            if (this.P != that.P) {
                return false;
            }
            //compare si
            if (!PairingUtils.isEqualElement(this.si, that.si)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayS, that.byteArrayS)) {
                return false;
            }
            //compare fais
            if (!Arrays.equals(this.fais, that.fais)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysFais, that.byteArraysFais)) {
                return false;
            }
            //compare xs
            if (!Arrays.equals(this.xs, that.xs)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysXs, that.byteArraysXs)) {
                return false;
            }
            //compare ts
            if (!Arrays.equals(this.ts, that.ts)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysTs, that.byteArraysTs)) {
                return false;
            }
          //compare sessionKey
            if (!PairingUtils.isEqualElement(this.sessionKey, that.sessionKey)) {
                return false;
            }
            if (!Arrays.equals(this.byteArraySessionKey, that.byteArraySessionKey)) {
                return false;
            }
            
            //compare C
            if (!PairingUtils.isEqualElement(this.C, that.C)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC, that.byteArrayC)) {
                return false;
            }
            //compare C0
            if (!PairingUtils.isEqualElement(this.C0, that.C0)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC0, that.byteArrayC0)) {
                return false;
            }
            //compare C1s
            if (!Arrays.equals(this.C1s, that.C1s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC1s, that.byteArraysC1s)) {
                return false;
            }
            //compare C2s
            if (!Arrays.equals(this.C2s, that.C2s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC2s, that.byteArraysC2s)) {
                return false;
            }
            //compare C3s
            if (!Arrays.equals(this.C3s, that.C3s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC3s, that.byteArraysC3s)) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());      
        this.si = pairing.getZr().newElementFromBytes(this.byteArrayS).getImmutable();       
        this.fais = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysFais, PairingUtils.PairingGroupType.Zr);
        this.ts = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysTs, PairingUtils.PairingGroupType.Zr);
        this.xs = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysXs, PairingUtils.PairingGroupType.Zr);
        this.sessionKey = pairing.getGT().newElementFromBytes(this.byteArraySessionKey).getImmutable();
        
        this.C = pairing.getGT().newElementFromBytes(this.byteArrayC).getImmutable();
        this.C0 = pairing.getG1().newElementFromBytes(this.byteArrayC0).getImmutable();
        this.C1s = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysC1s, PairingUtils.PairingGroupType.G1);
        this.C2s = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysC2s, PairingUtils.PairingGroupType.G1);
        this.C3s = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysC3s, PairingUtils.PairingGroupType.G1);
    }
}
