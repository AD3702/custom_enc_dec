import 'package:custom_enc_dec/enc_dec.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('EncryptionHelper', () {
    final helper = EncryptionHelper.instance;

    const String rsaPublicKey =
        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoa/AhNLCMtRhO50GUZB5QFrhSuC1/ypOyBrCoAwayzmoh/3PQZsfENmWrZuL/Z0m2sFqObdrc5fLUjq7AfigdFyZ15/pItvLoiL0udmQXrlEsjF85n0mhvAlIARCL7LBWui2ITJdlUgRsj01rBqyM/kzI9LbUBSvMuHcgdLSvSNcAWISc/ZrrsAmXuOMXE3QyMgscXQNWfRYrCZEg7VLarsTttbP65ZBrcnV/0pDTGzJWxyt69s45dU4OrClh/M6l7k8EBN+FrAcWNNxeqfc0veBPL1iAhZG2fcpU2ME+yGBy35h5KFcKIe1ThnC1W3PHJyw7EeP8oOl/2ryT/lIcwIDAQAB';
    const String rsaPrivateKey =
        'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQChr8CE0sIy1GE7nQZRkHlAWuFK4LX/Kk7IGsKgDBrLOaiH/c9Bmx8Q2Zatm4v9nSbawWo5t2tzl8tSOrsB+KB0XJnXn+ki28uiIvS52ZBeuUSyMXzmfSaG8CUgBEIvssFa6LYhMl2VSBGyPTWsGrIz+TMj0ttQFK8y4dyB0tK9I1wBYhJz9muuwCZe44xcTdDIyCxxdA1Z9FisJkSDtUtquxO21s/rlkGtydX/SkNMbMlbHK3r2zjl1Tg6sKWH8zqXuTwQE34WsBxY03F6p9zS94E8vWICFkbZ9ylTYwT7IYHLfmHkoVwoh7VOGcLVbc8cnLDsR4/yg6X/avJP+UhzAgMBAAECggEACe+TnxXshSnJR9vgatwRTMPI8HcFTXGQzHnd1+6mft1DiV0u1/3rrMy867I7/2Z24B6JTpQCRbo1mQ9ZipzNZMPZWFzP+3+88HEWz4zvyEJjrFJKNfJ0OaVBmB7ANSTWU6XVULjtnfeDJDbgDibIff/PBWE3GkwLGs9dDkVMWf8HP+2N3+irsDC+dMEOeMyRLUdGSIEgW7Kw9m+A97C/0SjWYJLhS0A9lij+p0pKjAKWXJ9MM7oP0y4XNW06uFeWQG4UQ4F3tREHQuhdB1qnVSB47rPVjmAJkgR2u6mHWXyvnV7FAo/twigsccdW1KEMlX38GejSmGhSraVZWM8mAQKBgQDEfrV5jDjkm5EjxdGT8P542kpmD38rP9cnScwOAfHjjUeDCfy9pfvedsDJOo2KL3vYKcfAf7tW9pXGU/3TsVZLIVfg1fYjma8Tx5sVmUUbsbU3Q/FZzlRP+M1dbWxkmO5NfbhOq5CZfbjjWWjtIYrjG46gpzwWN63CCcaw8Fe0gQKBgQDSpoQ5drp1sB7zVOqb4HV8ARvI2sTQrMyXkYfkF6Bu/X1BreqFqAhCr7A32Q9+89kaQ5NWv8KYwVEBt6HRMAJZMTMp4lOPuOu9RGoSPzqUZMcuA1eww9K/ySz4LKG5JumGeCs0fTDG8R2lSxyEw7Nh57g7wVzkZkb34PW5zJfy8wKBgCiij4L4ZZeZOFWuhh3TG70AX5xlngXiqOreDw3ihxRo1h4aRaMunTyvUEUND9JA6ZqVYVLE14gvbF/cZMSPiun0lkjP1pwcHyG3CLJZxPnqMTCho1rQGY2ERWwJwf23xqhN1HyobDnhzwdtKQ7I/gDjZQaCLyHlF9Dl1qomueyBAoGBAJSJHkt20NwTqH9krVnk2HLsRS9IM+gBMPLfh7bqghJBZIVfoTNF3S1IvTVkNW0LfVbrt4VACnO0PO69Eblz5PQHoVAza0C44GHBUBo1w5THyztC2B6otn7N2IvWzOLF8X0EV1LXxAFEG+dmI2HqrR6oSly4aEwVYo1/b0XoYmzJAoGATNLTahxbwqO6DrcCf6giXHw1IVlmb6EvGzk9agrNgZAFTtR7ppsnZt4MuK69IdUsg5OBgH66kgy+LWMjv1igKh8i5MJnLE+ctc1NvG6WiX7bpu+6gxV/sVJcZars9cV/vZF468DQGNKm9jUQcOw0oI8H+xFjU4oIaW1ix01eE2I=';
    String aesSecret = '';
    String aesPassword = '';
    const String aesSalt = '';
    const String sampleText = 'Hello, Flutter!';

    setUpAll(() async {
      // Initialize RSA and AES keys before tests
      helper.initRSAEncryptor(rsaPublicKey);
      helper.initRSADecrypt(rsaPrivateKey);
    });

    test('RSA Encryption & Decryption', () async {
      // Encrypt the sample text using RSA
      final encryptedText = helper.encryptRSA(sampleText);
      expect(encryptedText, isNotNull);

      //Decrypt the text back
      final decryptedText = helper.decryptRSA(encryptedText);
      expect(decryptedText, equals(sampleText));
    });

    test('AES Encryption & Decryption', () {
      // Encrypt the sample text using AES
      final encryptedText = helper.encryptAES(sampleText, aesSecret: aesPassword, aesIv: aesSalt);
      expect(encryptedText, isNotNull);

      // Decrypt the text back
      final decryptedText = helper.decryptAES(encryptedText, aesSecret: aesPassword, aesIv: aesSalt);
      expect(decryptedText, equals(sampleText));
    });

    test('Invalid AES Decryption should throw error', () {
      const invalidText = 'InvalidEncryptedData';
      final decryptedText = helper.decryptAES(invalidText, aesSecret: aesPassword, aesIv: aesSalt);
      expect(decryptedText.contains('Exception'), isTrue);
    });

    test('Invalid RSA Decryption should throw error', () async {
      const invalidText = 'InvalidEncryptedData';
      final decryptedText = helper.decryptRSA(invalidText);
      expect(decryptedText.contains('Exception'), isTrue);
    });
  });
}
