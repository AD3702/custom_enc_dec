import 'dart:async';
import 'dart:convert';
import 'package:basic_utils/basic_utils.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'encryption_extension.dart';
import 'package:pointycastle/export.dart';

class EncryptionHelper {
  // Private constructor for singleton pattern
  EncryptionHelper._();

  /// Singleton Instance for [EncryptionHelper] Class
  static EncryptionHelper instance = EncryptionHelper._();

  /// [PKCS1Encoder] for RSA Encryption
  PKCS1Encoding encrypter = PKCS1Encoding(RSAEngine());

  /// [PKCS1Encoder] for RSA Decryption
  PKCS1Encoding decrypter = PKCS1Encoding(RSAEngine());

  /// [RSAPublicKey] for Encryption
  RSAPublicKey? rsaPublicKey;

  /// [RSAPrivateKey] for Decryption
  RSAPrivateKey? rsaPrivateKey;

  /// Initialize [RSAPublicKey] for encryption
  void initRSAEncryptor(String publicKey) {
    rsaPublicKey = CryptoUtils.rsaPublicKeyFromPem(publicKey.publicKeyToPem);
    encrypter.init(true, PublicKeyParameter<RSAPublicKey>(rsaPublicKey!));
  }

  /// Initialize [RSAPrivateKey] for decryption
  void initRSADecrypt(String privateKey) {
    rsaPrivateKey = CryptoUtils.rsaPrivateKeyFromPem(privateKey.privateKeyToPem);
    decrypter.init(false, PrivateKeyParameter<RSAPrivateKey>(rsaPrivateKey!));
  }

  PaddedBlockCipherImpl encryptCipher = PaddedBlockCipherImpl(PKCS7Padding(), CBCBlockCipher(AESEngine())); // Cipher for AES encryption
  PaddedBlockCipherImpl decryptCipher = PaddedBlockCipherImpl(PKCS7Padding(), CBCBlockCipher(AESEngine())); // Cipher for AES decryption
  PBKDF2KeyDerivator pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64));

  /// Function to perform AES encryption with a given plain text
  String encryptAES(String plainText, {required String aesSecret, required String aesIv}) {
    if (plainText.isEmpty) {
      return plainText;
    }
    try {
      // Convert plain text to bytes
      final plainTextBytes = utf8.encode(plainText);
      final key = base64.decode(aesSecret); // Get the derived AES key
      final iv = base64.decode(aesIv); // Decode the salt to use as IV
      encryptCipher.init(true, PaddedBlockCipherParameters<ParametersWithIV<KeyParameter>, Null>(ParametersWithIV<KeyParameter>(KeyParameter(key), iv), null));
      // Encrypt the data
      final encryptedBytes = encryptCipher.process(Uint8List.fromList(plainTextBytes));

      // Convert the encrypted data to Base64 for easy readability
      String encryptedData = base64.encode(encryptedBytes);
      return encryptedData;
    } on Exception catch (e) {
      return e.toString();
    }
  }

  /// Function to perform AES decryption with a given encrypted text
  String decryptAES(String encryptedTextBase64, {required String aesSecret, required String aesIv}) {
    if (encryptedTextBase64.isEmpty) {
      return encryptedTextBase64;
    }
    try {
      // Decode the Base64 encrypted text to get bytes
      final encryptedBytes = base64.decode(encryptedTextBase64);
      // Decrypt the data
      final key = base64.decode(aesSecret); // Get the derived AES key
      final iv = base64.decode(aesIv); // Decode the salt to use as IV
      decryptCipher.init(false, PaddedBlockCipherParameters<ParametersWithIV<KeyParameter>, Null>(ParametersWithIV<KeyParameter>(KeyParameter(key), iv), null));
      final decryptedBytes = decryptCipher.process(Uint8List.fromList(encryptedBytes));
      // Convert decrypted bytes to string (UTF-8 format)
      String decryptedData = utf8.decode(decryptedBytes);
      return decryptedData;
    } catch (e) {
      return "Decryption failed: Exception: ${e.toString()}";
    }
  }

  /// Function to encrypt a string using RSA
  String encryptRSA(String value) {
    try {
      Uint8List output = encrypter.process(utf8.encode(value)); // Encrypt the input value
      return base64Encode(output);
    } on Exception catch (e) {
      return e.toString();
    }
  }

  /// Function to decrypt a string using RSA
  String decryptRSA(String value) {
    Uint8List? output;
    try {
      output = decrypter.process(base64Decode(value));
    } catch (e) {
      return "Decryption failed: Exception: ${e.toString()}";
    }

    // Decode and return the result
    return utf8.decode(output);
  }

  /// Function to generate RSA key pair and init RSA Encrypt/Decrypt
  Future<void> initRSAEncryptDecrypt(String publicKey, String privateKey) async {
    initRSAEncryptor(publicKey);
    initRSADecrypt(privateKey);
  }
}
