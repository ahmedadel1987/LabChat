import 'dart:convert';

import 'package:cryptography/cryptography.dart';

/// Authenticated message envelope suitable for storing as ciphertext fields.
class EncryptedMessage {
  const EncryptedMessage({
    required this.version,
    required this.nonce,
    required this.ciphertext,
    required this.tag,
  });

  final int version;
  final String nonce;
  final String ciphertext;
  final String tag;

  Map<String, Object> toJson() => {
    'version': version,
    'nonce': nonce,
    'ciphertext': ciphertext,
    'tag': tag,
  };

  factory EncryptedMessage.fromJson(Map<String, Object?> json) {
    final version = json['version'];
    final nonce = json['nonce'];
    final ciphertext = json['ciphertext'];
    final tag = json['tag'];
    if (version != 1 ||
        nonce is! String ||
        ciphertext is! String ||
        tag is! String) {
      throw const FormatException(
        'Unsupported or malformed encrypted message.',
      );
    }
    return EncryptedMessage(
      version: 1,
      nonce: nonce,
      ciphertext: ciphertext,
      tag: tag,
    );
  }
}

/// V1 cryptographic building blocks: X25519, HKDF-SHA-256, AES-256-GCM.
/// V1 uses a static device key, so it does not provide forward secrecy or
/// post-compromise recovery. Do not enable production messaging until pairing
/// verifies both public-key fingerprints and a ratcheting protocol is selected.
class MessageCipher {
  static final _x25519 = X25519();
  static final _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  static final _aead = AesGcm.with256bits();

  Future<SecretKey> deriveConversationKey({
    required SimpleKeyPair localKeyPair,
    required List<int> peerPublicKeyBytes,
    required String conversationId,
  }) async {
    if (peerPublicKeyBytes.length != 32 || conversationId.isEmpty) {
      throw const FormatException('Invalid peer key or conversation ID.');
    }
    final localPublic = (await localKeyPair.extractPublicKey()).bytes;
    final peerPublic = SimplePublicKey(
      peerPublicKeyBytes,
      type: KeyPairType.x25519,
    );
    final sharedSecret = await _x25519.sharedSecretKey(
      keyPair: localKeyPair,
      remotePublicKey: peerPublic,
    );

    // Both peers produce the same context by ordering the public keys.
    final publicKeys = [localPublic, peerPublicKeyBytes]..sort(_compareBytes);
    final context = utf8.encode(
      'labchat/message/v1|$conversationId|'
      '${base64UrlEncode(publicKeys[0])}|${base64UrlEncode(publicKeys[1])}',
    );
    final salt = (await Sha256().hash(
      utf8.encode('labchat/hkdf-salt/v1|$conversationId'),
    )).bytes;
    return _hkdf.deriveKey(secretKey: sharedSecret, nonce: salt, info: context);
  }

  Future<EncryptedMessage> encrypt({
    required String plaintext,
    required SecretKey conversationKey,
    required String conversationId,
    required String senderId,
  }) async {
    if (plaintext.isEmpty || conversationId.isEmpty || senderId.isEmpty) {
      throw const FormatException(
        'Message and context fields must not be empty.',
      );
    }
    final box = await _aead.encrypt(
      utf8.encode(plaintext),
      secretKey: conversationKey,
      aad: _associatedData(conversationId, senderId),
    );
    return EncryptedMessage(
      version: 1,
      nonce: _encode(box.nonce),
      ciphertext: _encode(box.cipherText),
      tag: _encode(box.mac.bytes),
    );
  }

  Future<String> decrypt({
    required EncryptedMessage message,
    required SecretKey conversationKey,
    required String conversationId,
    required String senderId,
  }) async {
    if (message.version != 1) {
      throw const FormatException('Unsupported message encryption version.');
    }
    final box = SecretBox(
      _decode(message.ciphertext),
      nonce: _decode(message.nonce),
      mac: Mac(_decode(message.tag)),
    );
    final clearText = await _aead.decrypt(
      box,
      secretKey: conversationKey,
      aad: _associatedData(conversationId, senderId),
    );
    return utf8.decode(clearText);
  }

  static List<int> _associatedData(String conversationId, String senderId) =>
      utf8.encode('labchat/message/v1|$conversationId|$senderId');

  static String _encode(List<int> bytes) =>
      base64UrlEncode(bytes).replaceAll('=', '');

  static List<int> _decode(String value) =>
      base64Url.decode(base64Url.normalize(value));

  static int _compareBytes(List<int> left, List<int> right) {
    for (var i = 0; i < left.length && i < right.length; i++) {
      final difference = left[i].compareTo(right[i]);
      if (difference != 0) return difference;
    }
    return left.length.compareTo(right.length);
  }
}
