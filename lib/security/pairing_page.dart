import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'pairing_service.dart';

const _dark = Color(0xFF17211F);
const _subtle = Color(0xFF7D8983);

class PairedSession {
  const PairedSession({
    required this.conversationId,
    required this.peerUserId,
    required this.peerFingerprint,
  });
  final String conversationId;
  final String peerUserId;
  final String peerFingerprint;
}

/// Temporary text invite pairing. QR and camera support are not implemented.
class PairingPage extends StatefulWidget {
  const PairingPage({super.key});
  @override
  State<PairingPage> createState() => _PairingPageState();
}

class _PairingPageState extends State<PairingPage> {
  final _service = PairingService();
  final _inviteController = TextEditingController();
  final _fingerprintController = TextEditingController();
  PairingInvite? _invite;
  PairingPeer? _peer;
  bool _joining = false;
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _inviteController.dispose();
    _fingerprintController.dispose();
    super.dispose();
  }

  Future<void> _create() async {
    await _run(() async {
      _invite = await _service.createInvite();
      _joining = false;
    });
  }

  Future<void> _join() async {
    await _run(() async {
      _invite = await _service.joinInvite(_inviteController.text.trim());
      _joining = true;
      _peer = await _service.getOtherPeer(_invite!.conversationId);
    });
  }

  Future<void> _loadPeer() async {
    if (_invite == null) return;
    await _run(() async {
      _peer = await _service.getOtherPeer(_invite!.conversationId);
    });
  }

  Future<void> _trust() async {
    final invite = _invite;
    final peer = _peer;
    if (invite == null || peer == null) return;
    await _run(() async {
      await _service.trustPeerAfterManualVerification(
        conversationId: invite.conversationId,
        peer: peer,
        fingerprintReadBack: _fingerprintController.text,
      );
      if (!mounted) return;
      Navigator.of(context).pop(
        PairedSession(
          conversationId: invite.conversationId,
          peerUserId: peer.userId.isEmpty
              ? (await _service.getOtherPeer(invite.conversationId)).userId
              : peer.userId,
          peerFingerprint: peer.fingerprint,
        ),
      );
    });
  }

  Future<void> _run(Future<void> Function() action) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await action();
    } catch (e) {
      _error = _friendly(e);
    }
    if (mounted) setState(() => _busy = false);
  }

  String _friendly(Object error) {
    final text = error.toString();
    if (text.contains('other device has not joined')) {
      return 'Waiting for the other person to join. Ask them to paste your invite, then check again.';
    }
    if (text.contains('fingerprints do not match')) {
      return 'Those fingerprints do not match. Compare them again before continuing.';
    }
    if (text.contains('FormatException'))
      return text.replaceFirst('FormatException: ', '');
    return 'Pairing failed. Check your connection, invite, and Supabase setup, then try again.';
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('Pair a private chat')),
    body: SafeArea(
      child: ListView(
        padding: const EdgeInsets.all(22),
        children: [
          const Text(
            'Connect two devices',
            style: TextStyle(
              fontSize: 25,
              fontWeight: FontWeight.w800,
              color: _dark,
            ),
          ),
          const SizedBox(height: 8),
          const Text(
            'Create an invite on one phone. The other person pastes it on theirs. Then compare the full fingerprints over a separate trusted channel, such as a call or in person.',
            style: TextStyle(color: _subtle, height: 1.45),
          ),
          const SizedBox(height: 22),
          if (_invite == null) ...[
            FilledButton.icon(
              onPressed: _busy ? null : _create,
              icon: const Icon(Icons.add_link_rounded),
              label: const Text('Create one-time invite'),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _inviteController,
              minLines: 3,
              maxLines: 6,
              decoration: const InputDecoration(
                labelText: 'Paste invite text',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 10),
            OutlinedButton.icon(
              onPressed: _busy ? null : _join,
              icon: const Icon(Icons.content_paste_rounded),
              label: const Text('Join with invite'),
            ),
          ] else ...[
            if (!_joining) ...[
              const Text(
                'Share this invite text privately. It expires in 10 minutes and works once.',
                style: TextStyle(color: _subtle),
              ),
              const SizedBox(height: 8),
              SelectableText(
                _invite!.toQrPayload(),
                style: const TextStyle(fontSize: 12, color: _dark),
              ),
              TextButton.icon(
                onPressed: () async {
                  await Clipboard.setData(
                    ClipboardData(text: _invite!.toQrPayload()),
                  );
                  if (mounted)
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Invite copied')),
                    );
                },
                icon: const Icon(Icons.copy_rounded),
                label: const Text('Copy invite'),
              ),
              OutlinedButton.icon(
                onPressed: _busy ? null : _loadPeer,
                icon: const Icon(Icons.refresh_rounded),
                label: const Text('Check whether they joined'),
              ),
            ],
            if (_peer != null) ...[
              const SizedBox(height: 12),
              const Text(
                'Compare this 64-character fingerprint with the other person. Do not verify it using this invite chat.',
                style: TextStyle(color: _subtle, height: 1.4),
              ),
              const SizedBox(height: 8),
              SelectableText(
                _peer!.fingerprint,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontWeight: FontWeight.w700,
                  color: _dark,
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _fingerprintController,
                decoration: const InputDecoration(
                  labelText: 'Type the fingerprint they read back',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 10),
              FilledButton.icon(
                onPressed: _busy ? null : _trust,
                icon: const Icon(Icons.verified_user_outlined),
                label: const Text('Verify and open chat'),
              ),
            ],
            TextButton(
              onPressed: _busy
                  ? null
                  : () => setState(() {
                      _invite = null;
                      _peer = null;
                      _error = null;
                    }),
              child: const Text('Cancel pairing'),
            ),
          ],
          if (_busy)
            const Padding(
              padding: EdgeInsets.all(18),
              child: Center(child: CircularProgressIndicator()),
            ),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Text(_error!, style: const TextStyle(color: Colors.red)),
            ),
          const SizedBox(height: 20),
          const Text(
            'Security note: this first version uses long-lived device keys. It does not yet provide forward secrecy or recovery after a device key is compromised.',
            style: TextStyle(fontSize: 12, color: _subtle, height: 1.4),
          ),
        ],
      ),
    ),
  );
}
