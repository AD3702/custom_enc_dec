import 'dart:convert';

import 'enc_dec.dart';

/// Extension methods for String to handle PEM keys and basic encryption/decryption
extension StringExtension on String {
  String get keyFromPem {
    String key = this;
    key = key.replaceAll(RegExp(r'-----BEGIN PUBLIC KEY-----'), '');
    key = key.replaceAll(RegExp(r'-----END PUBLIC KEY-----'), '');
    key = key.replaceAll(RegExp(r'-----BEGIN PRIVATE KEY-----'), '');
    key = key.replaceAll(RegExp(r'-----END PRIVATE KEY-----'), '');
    key = key.replaceAll(RegExp(r'\s+'), '');
    return key; // Return the cleaned key string
  }

  String get publicKeyToPem {
    return '-----BEGIN PUBLIC KEY-----\n$this\n-----END PUBLIC KEY-----';
  }

  String get privateKeyToPem {
    return '-----BEGIN PRIVATE KEY-----\n$this\n-----END PRIVATE KEY-----';
  }

  String get basicDecryption {
    return utf8.decode(base64Decode(this));
  }

  String get basicEncryption {
    return base64Encode(utf8.encode(this));
  }

  String encryptAES({required String aesSecret, required String aesSalt}) {
    return EncryptionHelper.instance.encryptAES(this, aesSecret: aesSecret, aesSalt: aesSalt);
  }

  String decryptAES({required String aesSecret, required String aesSalt}) {
    return EncryptionHelper.instance.decryptAES(this, aesSecret: aesSecret, aesSalt: aesSalt);
  }

  String get encryptRSA {
    return EncryptionHelper.instance.encryptRSA(this);
  }

  String get decryptRSA {
    return EncryptionHelper.instance.decryptRSA(this);
  }
}
