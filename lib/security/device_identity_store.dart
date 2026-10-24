import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Stores one long-lived X25519 identity seed in Android-backed secure storage.
/// The seed is never sent to Supabase. Pairing must still verify the peer key.
class DeviceIdentityStore {
  DeviceIdentityStore({FlutterSecureStorage? storage})
    : _storage = storage ?? const FlutterSecureStorage();

  static const _privateSeedKey = 'labchat.device.x25519.seed.v1';
  static final _x25519 = X25519();
  final FlutterSecureStorage _storage;

  Future<SimpleKeyPair> loadOrCreate() async {
    final stored = await _storage.read(key: _privateSeedKey);
    if (stored != null) {
      final seed = base64Url.decode(base64Url.normalize(stored));
      if (seed.length != 32) {
        throw const FormatException(
          'Stored device identity has invalid length.',
        );
      }
      return _x25519.newKeyPairFromSeed(seed);
    }

    final pair = await _x25519.newKeyPair();
    final seed = await pair.extractPrivateKeyBytes();
    await _storage.write(
      key: _privateSeedKey,
      value: base64UrlEncode(seed).replaceAll('=', ''),
    );
    return pair;
  }

  Future<List<int>> publicKey(SimpleKeyPair pair) async =>
      (await pair.extractPublicKey()).bytes;

  Future<String> fingerprint(SimpleKeyPair pair) async {
    final publicBytes = await publicKey(pair);
    final digest = await Sha256().hash(publicBytes);
    return digest.bytes
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join();
  }
}
