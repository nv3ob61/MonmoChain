package org.monmo.entities;

import java.security.*;
import java.util.ArrayList;
import org.monmo.utils.StringUtil;
import org.monmo.monmoChain.MonmoChainMain;

public class Transaction {

  public String transactionId; //Contains a hash of transaction*
  public PublicKey sender; //Senders address/public key.
  public PublicKey reciepient; //Recipients address/public key.
  public float value; //Contains the amount we wish to send to the recipient.
  public byte[] signature; //This is to prevent anybody else from spending funds in our wallet.

  public ArrayList<TransactionInput> inputs = new ArrayList<>();
  public ArrayList<TransactionOutput> outputs = new ArrayList<>();

  private static int sequence = 0; //A rough count of how many transactions have been generated 

  // Constructor: 
  public Transaction(PublicKey from, PublicKey to, float value, ArrayList<TransactionInput> inputs) {
    this.sender = from;
    this.reciepient = to;
    this.value = value;
    this.inputs = inputs;
  }

  public boolean processTransaction() {

    if (verifySignature() == false) {
      System.out.println("#Transaction Signature failed to verify");
      return false;
    }

    //Gathers transaction inputs (Making sure they are unspent):
    inputs.forEach(i -> {
      i.UTXO = MonmoChainMain.UTXOs.get(i.transactionOutputId);
    });

    //Checks if transaction is valid:
    if (getInputsValue() < MonmoChainMain.MIN_TRANSACTION) {
      System.out.println("Transaction Inputs too small: " + getInputsValue());
      System.out.println("Please enter the amount greater than " + MonmoChainMain.MIN_TRANSACTION);
      return false;
    }

    //Generate transaction outputs:
    float leftOver = getInputsValue() - value; //get value of inputs then the left over change:
    transactionId = calulateHash();
    outputs.add(new TransactionOutput(this.reciepient, value, transactionId)); //send value to recipient
    outputs.add(new TransactionOutput(this.sender, leftOver, transactionId)); //send the left over 'change' back to sender		
    //Add outputs to Unspent list
    outputs.forEach(o -> {
      MonmoChainMain.UTXOs.put(o.id, o);
    });

    //Remove transaction inputs from UTXO lists as spent:
    inputs.stream().filter(i -> !(i.UTXO == null)).forEachOrdered(i -> {
      //if Transaction can't be found skip it
      MonmoChainMain.UTXOs.remove(i.UTXO.id);
    });

    return true;
  }

  public float getInputsValue() {
    float total = 0;
    total = inputs.stream().filter(i -> !(i.UTXO == null)).map(i -> i.UTXO.value).reduce(total, (accumulator, _item) -> accumulator + _item); //if Transaction can't be found skip it, This behavior may not be optimal.
    return total;
  }

  public void generateSignature(PrivateKey privateKey) {
    String data = StringUtil.getStringFromKey(sender) + StringUtil.getStringFromKey(reciepient) + Float.toString(value);
    signature = StringUtil.applyECDSASig(privateKey, data);
  }

  public boolean verifySignature() {
    String data = StringUtil.getStringFromKey(sender) + StringUtil.getStringFromKey(reciepient) + Float.toString(value);
    return StringUtil.verifyECDSASig(sender, data, signature);
  }

  public float getOutputsValue() {
    float total = 0;
    total = outputs.stream().map(o -> o.value).reduce(total, (accumulator, _item) -> accumulator + _item);
    return total;
  }

  private String calulateHash() {
    sequence++; //increase the sequence to avoid 2 identical transactions having the same hash
    return StringUtil.applySha256(
            StringUtil.getStringFromKey(sender)
            + StringUtil.getStringFromKey(reciepient)
            + Float.toString(value) + sequence
    );
  }
}
