import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

import 'device_identity_store.dart';

String _encode(List<int> bytes) => base64UrlEncode(bytes).replaceAll('=', '');

List<int> _decode(String value) => base64Url.decode(base64Url.normalize(value));

class PairingInvite {
  const PairingInvite({
    required this.conversationId,
    required this.inviteCode,
    required this.hostPublicKey,
    required this.hostFingerprint,
  });

  final String conversationId;
  final String inviteCode;
  final List<int> hostPublicKey;
  final String hostFingerprint;

  /// Share this short-lived payload only with the intended recipient.
  String toQrPayload() => jsonEncode({
    'version': 1,
    'conversationId': conversationId,
    'inviteCode': inviteCode,
    'hostPublicKey': _encode(hostPublicKey),
    'hostFingerprint': hostFingerprint,
  });

  factory PairingInvite.fromQrPayload(String payload) {
    final decoded = jsonDecode(payload);
    if (decoded is! Map<String, dynamic> ||
        decoded['version'] != 1 ||
        decoded['conversationId'] is! String ||
        decoded['inviteCode'] is! String ||
        decoded['hostPublicKey'] is! String ||
        decoded['hostFingerprint'] is! String) {
      throw const FormatException('This is not a valid LabChat invite.');
    }
    final inviteCode = decoded['inviteCode'] as String;
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(inviteCode)) {
      throw const FormatException('The LabChat invite code is invalid.');
    }
    final publicKey = _decode(decoded['hostPublicKey'] as String);
    if (publicKey.length != 32) {
      throw const FormatException('The invite contains an invalid device key.');
    }
    return PairingInvite(
      conversationId: decoded['conversationId'] as String,
      inviteCode: inviteCode,
      hostPublicKey: publicKey,
      hostFingerprint: decoded['hostFingerprint'] as String,
    );
  }
}

class PairingPeer {
  const PairingPeer({
    required this.userId,
    required this.publicKey,
    required this.fingerprint,
  });

  final String userId;
  final List<int> publicKey;
  final String fingerprint;
}

/// Backend pairing operations and locally stored, manually verified peer keys.
/// Never call trustPeer before the user compares the fingerprint through a
/// separate trusted channel (for example, in person or on a voice call).
class PairingService {
  PairingService({
    SupabaseClient? client,
    DeviceIdentityStore? identities,
    FlutterSecureStorage? storage,
  }) : _client = client ?? Supabase.instance.client,
       _identities = identities ?? DeviceIdentityStore(),
       _storage = storage ?? const FlutterSecureStorage();

  static final _sha256 = Sha256();
  final SupabaseClient _client;
  final DeviceIdentityStore _identities;
  final FlutterSecureStorage _storage;

  Future<PairingInvite> createInvite() async {
    final keyPair = await _identities.loadOrCreate();
    final publicKey = await _identities.publicKey(keyPair);
    final fingerprint = await _fingerprint(publicKey);
    final result = await _client.rpc(
      'create_private_invite',
      params: {'p_device_public_key': _toBytea(publicKey)},
    );
    if (result is! List || result.isEmpty || result.first is! Map) {
      throw const FormatException('Supabase returned an invalid invite.');
    }
    final row = Map<String, dynamic>.from(result.first as Map);
    final id = row['conversation_id'];
    final code = row['invite_code'];
    if (id is! String || code is! String) {
      throw const FormatException('Supabase returned an incomplete invite.');
    }
    return PairingInvite(
      conversationId: id,
      inviteCode: code,
      hostPublicKey: publicKey,
      hostFingerprint: fingerprint,
    );
  }

  Future<PairingInvite> joinInvite(String qrPayload) async {
    final invite = PairingInvite.fromQrPayload(qrPayload);
    final calculatedFingerprint = await _fingerprint(invite.hostPublicKey);
    if (calculatedFingerprint != invite.hostFingerprint) {
      throw const FormatException(
        'The invite fingerprint does not match its key.',
      );
    }

    final keyPair = await _identities.loadOrCreate();
    final publicKey = await _identities.publicKey(keyPair);
    await _client.rpc(
      'join_private_invite',
      params: {
        'p_conversation_id': invite.conversationId,
        'p_invite_code': invite.inviteCode,
        'p_device_public_key': _toBytea(publicKey),
      },
    );
    final publishedHost = await getOtherPeer(invite.conversationId);
    if (!_sameBytes(publishedHost.publicKey, invite.hostPublicKey)) {
      throw const FormatException(
        'The project returned a different host key than the invite. Do not continue.',
      );
    }
    return invite;
  }

  Future<PairingPeer> getOtherPeer(String conversationId) async {
    final userId = _client.auth.currentUser?.id;
    if (userId == null) throw StateError('This device is not signed in.');
    final rows = await _client
        .from('conversation_members')
        .select('user_id, device_public_key, key_fingerprint')
        .eq('conversation_id', conversationId)
        .neq('user_id', userId);
    if (rows.length != 1) {
      throw StateError(
        'The other device has not joined this conversation yet.',
      );
    }
    final row = rows.first;
    final publicKey = _fromBytea(row['device_public_key']);
    if (publicKey.length != 32) {
      throw const FormatException('The other device published an invalid key.');
    }
    final fingerprint = await _fingerprint(publicKey);
    if (row['key_fingerprint'] != fingerprint) {
      throw const FormatException(
        'The other device key fingerprint is invalid.',
      );
    }
    return PairingPeer(
      userId: row['user_id'] as String,
      publicKey: publicKey,
      fingerprint: fingerprint,
    );
  }

  Future<void> trustPeerAfterManualVerification({
    required String conversationId,
    required PairingPeer peer,
    required String fingerprintReadBack,
  }) async {
    if (fingerprintReadBack.replaceAll(RegExp(r'\s+'), '').toLowerCase() !=
        peer.fingerprint) {
      throw const FormatException('The fingerprints do not match.');
    }
    final key = 'labchat.peer.$conversationId.${peer.userId}.v1';
    await _storage.write(
      key: key,
      value: jsonEncode({
        'publicKey': _encode(peer.publicKey),
        'fingerprint': peer.fingerprint,
      }),
    );
  }

  Future<List<int>> getTrustedPeerKey({
    required String conversationId,
    required String peerUserId,
  }) async {
    final key = 'labchat.peer.$conversationId.$peerUserId.v1';
    final stored = await _storage.read(key: key);
    if (stored == null) {
      throw StateError('Verify the other device fingerprint before messaging.');
    }
    final data = jsonDecode(stored);
    if (data is! Map<String, dynamic> || data['publicKey'] is! String) {
      throw const FormatException('Stored peer identity is invalid.');
    }
    final publicKey = _decode(data['publicKey'] as String);
    if (publicKey.length != 32 ||
        await _fingerprint(publicKey) != data['fingerprint']) {
      throw const FormatException('Stored peer identity failed verification.');
    }
    return publicKey;
  }

  Future<String> _fingerprint(List<int> publicKey) async {
    final hash = await _sha256.hash(publicKey);
    return hash.bytes
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join();
  }

  static bool _sameBytes(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    var different = 0;
    for (var i = 0; i < left.length; i++) {
      different |= left[i] ^ right[i];
    }
    return different == 0;
  }

  static String _toBytea(List<int> bytes) =>
      r'\x' + bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  static List<int> _fromBytea(Object? value) {
    if (value is! String || !value.startsWith(r'\x') || value.length != 66) {
      throw const FormatException('Invalid public-key encoding from Supabase.');
    }
    final hex = value.substring(2);
    return [
      for (var i = 0; i < hex.length; i += 2)
        int.parse(hex.substring(i, i + 2), radix: 16),
    ];
  }
}
