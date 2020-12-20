package org.monmo.entities;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import org.monmo.monmoChain.MonmoChainMain;

public final class Wallet {

  public PrivateKey privateKey;
  public PublicKey publicKey;

  public HashMap<String, TransactionOutput> UTXOs = new HashMap<>();

  public Wallet() {
    generateKeyPair();
  }

  public void generateKeyPair() {
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
      SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
      ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime192v1");
      // Initialize the key generator and generate a KeyPair
      keyGen.initialize(ecSpec, random); //256 
      KeyPair keyPair = keyGen.generateKeyPair();
      // Set the public and private keys from the keyPair
      privateKey = keyPair.getPrivate();
      publicKey = keyPair.getPublic();

    } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new RuntimeException(e);
    }
  }

  public float getBalance() {
    float total = 0;
    total = MonmoChainMain.UTXOs.entrySet().stream().map(item -> item.getValue()).filter(UTXO -> (UTXO.isMine(publicKey))).map(UTXO -> {
      //if output belongs to me ( if coins belong to me )
      UTXOs.put(UTXO.id, UTXO); //add it to our list of unspent transactions.
      return UTXO;
    }).map(UTXO -> UTXO.value).reduce(total, (accumulator, _item) -> accumulator + _item);
    return total;
  }

  public Transaction sendFunds(PublicKey _recipient, float value) {
    if (getBalance() < value) {
      System.out.println("#Not Enough funds to send transaction. Transaction Discarded.");
      return null;
    }
    ArrayList<TransactionInput> inputs = new ArrayList<>();

    float total = 0;
    for (Map.Entry<String, TransactionOutput> item : UTXOs.entrySet()) {
      TransactionOutput UTXO = item.getValue();
      total += UTXO.value;
      inputs.add(new TransactionInput(UTXO.id));
      if (total > value) {
        break;
      }
    }

    Transaction newTransaction = new Transaction(publicKey, _recipient, value, inputs);
    newTransaction.generateSignature(privateKey);

    inputs.forEach(input -> {
      UTXOs.remove(input.transactionOutputId);
    });

    return newTransaction;
  }

}
