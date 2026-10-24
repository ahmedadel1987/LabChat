import 'dart:async';
import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

import 'device_identity_store.dart';
import 'message_cipher.dart';
import 'pairing_service.dart';

class DecryptedMessage {
  const DecryptedMessage({
    required this.id,
    required this.senderId,
    required this.createdAt,
    required this.text,
    this.couldNotDecrypt = false,
  });

  final String id;
  final String senderId;
  final DateTime createdAt;
  final String text;
  final bool couldNotDecrypt;
}

/// Supabase stores only ciphertext, nonce, tag, sender, and timestamp.
/// Cleartext is created on the device after fingerprint verification.
class EncryptedMessageRepository {
  EncryptedMessageRepository({
    SupabaseClient? client,
    PairingService? pairing,
    DeviceIdentityStore? identities,
    MessageCipher? cipher,
  }) : _client = client ?? Supabase.instance.client,
       _pairing = pairing ?? PairingService(client: client),
       _identities = identities ?? DeviceIdentityStore(),
       _cipher = cipher ?? MessageCipher();

  final SupabaseClient _client;
  final PairingService _pairing;
  final DeviceIdentityStore _identities;
  final MessageCipher _cipher;

  Future<String> send({
    required String conversationId,
    required String peerUserId,
    required String text,
  }) async {
    final senderId = _client.auth.currentUser?.id;
    if (senderId == null) throw StateError('This device is not signed in.');
    if (text.trim().isEmpty) throw ArgumentError.value(text, 'text');

    final peer = await _pairing.getTrustedPeerKey(
      conversationId: conversationId,
      peerUserId: peerUserId,
    );
    final pairKey = await _identities.loadOrCreate();
    final conversationKey = await _conversationKey(
      pairKey,
      peer,
      conversationId,
    );
    final envelope = await _cipher.encrypt(
      plaintext: text,
      conversationKey: conversationKey,
      conversationId: conversationId,
      senderId: senderId,
    );

    final inserted = await _client
        .from('messages')
        .insert({
          'conversation_id': conversationId,
          'sender_id': senderId,
          'cipher_version': envelope.version,
          'ciphertext': _toBytea(_decode(envelope.ciphertext)),
          'nonce': _toBytea(_decode(envelope.nonce)),
          'auth_tag': _toBytea(_decode(envelope.tag)),
        })
        .select('id')
        .single();
    return inserted['id'] as String;
  }

  Stream<List<DecryptedMessage>> watch({required String conversationId}) =>
      _client
          .from('messages')
          .stream(primaryKey: ['id'])
          .eq('conversation_id', conversationId)
          .order('created_at')
          .asyncMap((rows) async {
            final messages = <DecryptedMessage>[];
            for (final row in rows) {
              try {
                messages.add(await _decryptRow(row));
              } catch (_) {
                messages.add(_lockedMessage(row));
              }
            }
            return messages;
          });

  Future<DecryptedMessage> _decryptRow(Map<String, dynamic> row) async {
    final id = row['id'] as String;
    final conversationId = row['conversation_id'] as String;
    final senderId = row['sender_id'] as String;
    final peer = await _pairing.getOtherPeer(conversationId);
    final trustedPeerKey = await _pairing.getTrustedPeerKey(
      conversationId: conversationId,
      peerUserId: peer.userId,
    );
    if (!_sameBytes(peer.publicKey, trustedPeerKey)) {
      throw StateError('The verified peer key changed.');
    }

    final pairKey = await _identities.loadOrCreate();
    final conversationKey = await _conversationKey(
      pairKey,
      trustedPeerKey,
      conversationId,
    );
    final envelope = EncryptedMessage(
      version: row['cipher_version'] as int,
      ciphertext: _encode(_fromBytea(row['ciphertext'])),
      nonce: _encode(_fromBytea(row['nonce'])),
      tag: _encode(_fromBytea(row['auth_tag'])),
    );
    final clearText = await _cipher.decrypt(
      message: envelope,
      conversationKey: conversationKey,
      conversationId: conversationId,
      senderId: senderId,
    );
    return DecryptedMessage(
      id: id,
      senderId: senderId,
      createdAt: DateTime.parse(row['created_at'] as String).toLocal(),
      text: clearText,
    );
  }

  Future<SecretKey> _conversationKey(
    SimpleKeyPair local,
    List<int> peer,
    String conversationId,
  ) => _cipher.deriveConversationKey(
    localKeyPair: local,
    peerPublicKeyBytes: peer,
    conversationId: conversationId,
  );

  static DecryptedMessage _lockedMessage(Map<String, dynamic> row) =>
      DecryptedMessage(
        id: row['id'] as String? ?? 'unknown',
        senderId: row['sender_id'] as String? ?? 'unknown',
        createdAt:
            DateTime.tryParse(row['created_at'] as String? ?? '')?.toLocal() ??
            DateTime.fromMillisecondsSinceEpoch(0),
        text: 'Unable to decrypt this message',
        couldNotDecrypt: true,
      );

  static String _toBytea(List<int> bytes) =>
      r'\x' + bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  static List<int> _fromBytea(Object? value) {
    if (value is! String || !value.startsWith(r'\x') || value.length.isOdd) {
      throw const FormatException('Invalid encrypted field encoding.');
    }
    final hex = value.substring(2);
    return [
      for (var i = 0; i < hex.length; i += 2)
        int.parse(hex.substring(i, i + 2), radix: 16),
    ];
  }

  static String _encode(List<int> bytes) =>
      base64UrlEncode(bytes).replaceAll('=', '');

  static List<int> _decode(String value) =>
      base64Url.decode(base64Url.normalize(value));

  static bool _sameBytes(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    var different = 0;
    for (var i = 0; i < left.length; i++) {
      different |= left[i] ^ right[i];
    }
    return different == 0;
  }
}
