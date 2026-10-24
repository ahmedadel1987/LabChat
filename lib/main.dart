import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:image_picker/image_picker.dart';
import 'package:record/record.dart';
import 'package:audioplayers/audioplayers.dart';
import 'package:path_provider/path_provider.dart';
import 'package:cryptography/cryptography.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

const supabaseUrl = String.fromEnvironment('SUPABASE_URL');
const supabasePublishableKey =
String.fromEnvironment('SUPABASE_PUBLISHABLE_KEY');

const green = Color(0xFF1C5B4B);
const background = Color(0xFFF6F7F2);

// Learning prototype only: this shared passphrase is embedded in the app.
// Anyone who extracts the APK may be able to recover it.
const String _sharedPassphrase = 'ahmed';
const String _keyDerivationSalt = 'LabChat-demo-key-salt-v1';


Future<String> _inboxMessagePreview(Map<String, dynamic> message) async {
  final type = message['message_type']?.toString() ?? 'text';
  if (type == 'image') return '📷 Image';
  if (type == 'audio') return '🎤 Voice message';

  final body = message['body']?.toString() ?? '';
  if (message['encrypted'] != true) return body;

  final nonceText = message['encryption_nonce']?.toString();
  if (nonceText == null || nonceText.isEmpty) return '🔒 Encrypted message';

  try {
    final combined = base64Decode(body);
    if (combined.length < 16) return '🔒 Encrypted message';
    final cipherText = combined.sublist(0, combined.length - 16);
    final macBytes = combined.sublist(combined.length - 16);
    final box = SecretBox(
      cipherText,
      nonce: base64Decode(nonceText),
      mac: Mac(macBytes),
    );
    final kdf = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: 100000,
      bits: 256,
    );
    final key = await kdf.deriveKeyFromPassword(
      password: _sharedPassphrase,
      nonce: utf8.encode(_keyDerivationSalt),
    );
    final plain = await AesGcm.with256bits().decrypt(box, secretKey: key);
    return utf8.decode(plain);
  } catch (_) {
    return '🔒 Encrypted message';
  }
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  if (supabaseUrl.isEmpty || supabasePublishableKey.isEmpty) {
    runApp(const LabChatApp(configured: false));
    return;
  }

  try {
    await Supabase.initialize(
      url: supabaseUrl,
      publishableKey: supabasePublishableKey,
    );

    final client = Supabase.instance.client;

    if (client.auth.currentSession == null) {
      await client.auth.signInAnonymously();
    }

    runApp(const LabChatApp(configured: true));
  } catch (e) {
    runApp(LabChatApp(configured: false, error: e.toString()));
  }
}

class LabChatApp extends StatelessWidget {
  final bool configured;
  final String? error;

  const LabChatApp({
    super.key,
    required this.configured,
    this.error,
  });

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'LabChat',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(seedColor: green),
        scaffoldBackgroundColor: background,
        appBarTheme: const AppBarTheme(
          backgroundColor: background,
        ),
      ),
      home: configured ? const HomePage() : SetupPage(error: error),
    );
  }
}

class SetupPage extends StatelessWidget {
  final String? error;

  const SetupPage({super.key, this.error});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text(
            error ?? 'Supabase configuration is missing.',
            textAlign: TextAlign.center,
          ),
        ),
      ),
    );
  }
}

// ============================================================
// HOME: REGISTER NEW USERS, OPEN INBOX FOR RETURNING USERS
// ============================================================

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final client = Supabase.instance.client;

  bool loading = true;
  String? error;

  @override
  void initState() {
    super.initState();
    checkProfile();
  }

  Future<void> checkProfile() async {
    try {
      final user = client.auth.currentUser!;

      final profile = await client
          .from('profiles')
          .select('username')
          .eq('id', user.id)
          .maybeSingle();

      if (!mounted) return;

      if (profile == null) {
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(
            builder: (_) => const RegisterPage(),
          ),
        );
        return;
      }

      Navigator.of(context).pushReplacement(
        MaterialPageRoute(
          builder: (_) => InboxPage(
            username: profile['username'].toString(),
          ),
        ),
      );
    } catch (e) {
      error = 'Could not load profile: $e';
      if (mounted) {
        setState(() => loading = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    if (loading) {
      return const Scaffold(
        body: Center(
          child: CircularProgressIndicator(),
        ),
      );
    }

    return Scaffold(
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text(
            error ?? 'Could not open LabChat.',
            textAlign: TextAlign.center,
          ),
        ),
      ),
    );
  }
}

// ============================================================
// REGISTER
// ============================================================

class RegisterPage extends StatefulWidget {
  const RegisterPage({super.key});

  @override
  State<RegisterPage> createState() => _RegisterPageState();
}

class _RegisterPageState extends State<RegisterPage> {
  final controller = TextEditingController();

  bool saving = false;
  String? error;

  Future<void> saveName() async {
    final name = controller.text.trim().toLowerCase();

    if (!RegExp(r'^[a-z0-9_]{3,24}$').hasMatch(name)) {
      setState(() {
        error = 'Use 3–24 letters, numbers, or underscores.';
      });
      return;
    }

    setState(() {
      saving = true;
      error = null;
    });

    try {
      final client = Supabase.instance.client;
      final user = client.auth.currentUser!;

      await client.from('profiles').insert({
        'id': user.id,
        'username': name,
      });

      if (!mounted) return;

      Navigator.of(context).pushReplacement(
        MaterialPageRoute(
          builder: (_) => InboxPage(username: name),
        ),
      );
    } on PostgrestException catch (e) {
      if (!mounted) return;

      setState(() {
        error = e.code == '23505'
            ? 'That username is already taken.'
            : e.message;
        saving = false;
      });
    } catch (e) {
      if (!mounted) return;

      setState(() {
        error = 'Could not save username: $e';
        saving = false;
      });
    }
  }

  @override
  void dispose() {
    controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Welcome to LabChat'),
      ),
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(28),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Icon(
                  Icons.forum_rounded,
                  size: 54,
                  color: green,
                ),
                const SizedBox(height: 24),
                const Text(
                  'Choose your username',
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    fontSize: 25,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 24),
                TextField(
                  controller: controller,
                  autocorrect: false,
                  decoration: const InputDecoration(
                    hintText: 'Username',
                    border: OutlineInputBorder(),
                  ),
                ),
                const SizedBox(height: 12),
                FilledButton(
                  onPressed: saving ? null : saveName,
                  child: Text(
                    saving ? 'Saving...' : 'Continue',
                  ),
                ),
                if (error != null) ...[
                  const SizedBox(height: 12),
                  Text(
                    error!,
                    style: const TextStyle(color: Colors.red),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}

// ============================================================
// INBOX
// ============================================================

class InboxPage extends StatefulWidget {
  final String username;

  const InboxPage({
    super.key,
    required this.username,
  });

  @override
  State<InboxPage> createState() => _InboxPageState();
}

class _InboxPageState extends State<InboxPage> {
  final client = Supabase.instance.client;

  List<Map<String, dynamic>> conversations = [];

  bool loading = true;
  String? error;

  StreamSubscription<List<Map<String, dynamic>>>? messageSubscription;

  @override
  void initState() {
    super.initState();

    loadConversations();

    messageSubscription = client
        .from('direct_messages')
        .stream(primaryKey: ['id'])
        .listen(
          (_) => loadConversations(),
      onError: (Object e) {
        if (mounted) {
          setState(() {
            error = 'Inbox refresh failed: $e';
          });
        }
      },
    );
  }

  Future<void> loadConversations() async {
    try {
      final myId = client.auth.currentUser!.id;

      final rows = await client
          .from('direct_conversations')
          .select('id, user_one, user_two')
          .or('user_one.eq.$myId,user_two.eq.$myId');

      final result = <Map<String, dynamic>>[];

      for (final raw in rows) {
        final row = Map<String, dynamic>.from(raw);

        final conversationId = row['id'].toString();

        final otherId = row['user_one'].toString() == myId
            ? row['user_two'].toString()
            : row['user_one'].toString();

        final profile = await client
            .from('profiles')
            .select('username')
            .eq('id', otherId)
            .maybeSingle();

        if (profile == null) continue;

        final readRow = await client
            .from('direct_conversation_reads')
            .select('last_read_at')
            .eq('conversation_id', conversationId)
            .eq('user_id', myId)
            .maybeSingle();

        final incoming = await client
            .from('direct_messages')
            .select('id, body, created_at, sender_id')
            .eq('conversation_id', conversationId)
            .neq('sender_id', myId)
            .order('created_at', ascending: false);

        DateTime? lastRead;

        if (readRow != null && readRow['last_read_at'] != null) {
          lastRead = DateTime.tryParse(
            readRow['last_read_at'].toString(),
          )?.toUtc();
        }

        var unread = false;

        for (final message in incoming) {
          final createdAt = DateTime.tryParse(
            message['created_at'].toString(),
          )?.toUtc();

          if (createdAt != null &&
              (lastRead == null || createdAt.isAfter(lastRead))) {
            unread = true;
            break;
          }
        }

        final lastMessages = await client
            .from('direct_messages')
            .select('body, created_at, sender_id, message_type, encrypted, encryption_nonce')
            .eq('conversation_id', conversationId)
            .order('created_at', ascending: false)
            .limit(1);

        final lastMessagePreview = lastMessages.isEmpty
            ? 'Start a conversation'
            : await _inboxMessagePreview(
          Map<String, dynamic>.from(lastMessages.first),
        );

        result.add({
          'id': conversationId,
          'other_id': otherId,
          'username': profile['username'].toString(),
          'unread': unread,
          'last_message': lastMessagePreview,
          'last_time': lastMessages.isEmpty
              ? ''
              : lastMessages.first['created_at'].toString(),
        });
      }

      result.sort((a, b) {
        final aTime = DateTime.tryParse(a['last_time'].toString());
        final bTime = DateTime.tryParse(b['last_time'].toString());

        if (aTime == null && bTime == null) return 0;
        if (aTime == null) return 1;
        if (bTime == null) return -1;

        return bTime.compareTo(aTime);
      });

      if (!mounted) return;

      setState(() {
        conversations = result;
        loading = false;
        error = null;
      });
    } catch (e) {
      if (!mounted) return;

      setState(() {
        error = 'Could not load conversations: $e';
        loading = false;
      });
    }
  }

  String formatTime(String value) {
    final date = DateTime.tryParse(value);

    if (date == null) return '';

    final local = date.toLocal();
    final now = DateTime.now();

    if (local.year == now.year &&
        local.month == now.month &&
        local.day == now.day) {
      final hour = local.hour % 12 == 0 ? 12 : local.hour % 12;
      final minute = local.minute.toString().padLeft(2, '0');
      final period = local.hour >= 12 ? 'PM' : 'AM';

      return '$hour:$minute $period';
    }

    return '${local.day}/${local.month}/${local.year}';
  }

  Future<void> openPeople() async {
    await Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => PeoplePage(username: widget.username),
      ),
    );

    if (mounted) {
      await loadConversations();
    }
  }

  Future<void> openChat(Map<String, dynamic> conversation) async {
    await Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => DirectChatPage(
          username: conversation['username'].toString(),
          otherUserId: conversation['other_id'].toString(),
        ),
      ),
    );

    if (mounted) {
      await loadConversations();
    }
  }

  @override
  void dispose() {
    messageSubscription?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text(
          'LabChat',
          style: TextStyle(
            fontWeight: FontWeight.bold,
          ),
        ),
        actions: [
          IconButton(
            tooltip: 'New conversation',
            onPressed: openPeople,
            icon: const Icon(Icons.add),
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: loadConversations,
        child: loading
            ? ListView(
          children: const [
            SizedBox(height: 250),
            Center(child: CircularProgressIndicator()),
          ],
        )
            : error != null
            ? ListView(
          padding: const EdgeInsets.all(24),
          children: [
            Text(
              error!,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 12),
            Center(
              child: FilledButton(
                onPressed: loadConversations,
                child: const Text('Retry'),
              ),
            ),
          ],
        )
            : conversations.isEmpty
            ? ListView(
          padding: const EdgeInsets.all(24),
          children: [
            const SizedBox(height: 100),
            const Icon(
              Icons.forum_outlined,
              size: 70,
              color: green,
            ),
            const SizedBox(height: 20),
            const Text(
              'No conversations yet',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 21,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 8),
            const Text(
              'Tap + to find someone and start chatting.',
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 20),
            Center(
              child: FilledButton.icon(
                onPressed: openPeople,
                icon: const Icon(Icons.add),
                label: const Text('New conversation'),
              ),
            ),
          ],
        )
            : ListView.separated(
          itemCount: conversations.length,
          separatorBuilder: (_, __) => const Divider(
            height: 1,
            indent: 76,
          ),
          itemBuilder: (context, index) {
            final conversation = conversations[index];

            final username =
            conversation['username'].toString();

            final unread = conversation['unread'] == true;

            final lastMessage =
            conversation['last_message'].toString();

            return ListTile(
              contentPadding: const EdgeInsets.symmetric(
                horizontal: 16,
                vertical: 5,
              ),
              leading: CircleAvatar(
                backgroundColor: green.withValues(alpha: 0.12),
                child: Text(
                  username.isNotEmpty
                      ? username[0].toUpperCase()
                      : '?',
                  style: const TextStyle(
                    color: green,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
              title: Text(
                '@$username',
                style: TextStyle(
                  fontWeight: unread
                      ? FontWeight.bold
                      : FontWeight.w600,
                ),
              ),
              subtitle: Text(
                lastMessage,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  color: unread
                      ? Colors.black87
                      : Colors.black54,
                  fontWeight: unread
                      ? FontWeight.w600
                      : FontWeight.normal,
                ),
              ),
              trailing: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (conversation['last_time']
                      .toString()
                      .isNotEmpty)
                    Text(
                      formatTime(
                        conversation['last_time'].toString(),
                      ),
                      style: const TextStyle(
                        fontSize: 11,
                        color: Colors.black54,
                      ),
                    ),
                  if (unread) ...[
                    const SizedBox(width: 10),
                    Container(
                      width: 9,
                      height: 9,
                      decoration: const BoxDecoration(
                        color: Colors.red,
                        shape: BoxShape.circle,
                      ),
                    ),
                  ],
                ],
              ),
              onTap: () => openChat(conversation),
            );
          },
        ),
      ),
    );
  }
}

// ============================================================
// PEOPLE: + BUTTON OPENS THIS PAGE
// ============================================================

class PeoplePage extends StatefulWidget {
  final String username;

  const PeoplePage({
    super.key,
    required this.username,
  });

  @override
  State<PeoplePage> createState() => _PeoplePageState();
}

class _PeoplePageState extends State<PeoplePage> {
  final client = Supabase.instance.client;

  List<Map<String, dynamic>> people = [];

  bool loading = true;
  String? error;

  @override
  void initState() {
    super.initState();
    loadPeople();
  }

  Future<void> loadPeople() async {
    try {
      final myId = client.auth.currentUser!.id;

      final rows = await client
          .from('profiles')
          .select('id, username')
          .neq('id', myId)
          .order('username');

      if (!mounted) return;

      setState(() {
        people = List<Map<String, dynamic>>.from(rows);
        loading = false;
        error = null;
      });
    } catch (e) {
      if (!mounted) return;

      setState(() {
        error = 'Could not load users: $e';
        loading = false;
      });
    }
  }

  Future<void> openPerson(Map<String, dynamic> person) async {
    await Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => DirectChatPage(
          username: person['username'].toString(),
          otherUserId: person['id'].toString(),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('New conversation'),
      ),
      body: loading
          ? const Center(child: CircularProgressIndicator())
          : error != null
          ? Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                error!,
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 12),
              FilledButton(
                onPressed: loadPeople,
                child: const Text('Retry'),
              ),
            ],
          ),
        ),
      )
          : people.isEmpty
          ? const Center(
        child: Text('No other registered users found.'),
      )
          : ListView.separated(
        itemCount: people.length,
        separatorBuilder: (_, __) => const Divider(
          height: 1,
          indent: 76,
        ),
        itemBuilder: (context, index) {
          final person = people[index];
          final username = person['username'].toString();

          return ListTile(
            leading: CircleAvatar(
              backgroundColor: green.withValues(alpha: 0.12),
              child: Text(
                username.isNotEmpty
                    ? username[0].toUpperCase()
                    : '?',
                style: const TextStyle(
                  color: green,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
            title: Text('@$username'),
            trailing: const Icon(
              Icons.chat_bubble_outline,
              color: green,
            ),
            onTap: () => openPerson(person),
          );
        },
      ),
    );
  }
}

// ============================================================
// DIRECT CHAT
// ============================================================

class DirectChatPage extends StatefulWidget {
  final String username;
  final String otherUserId;

  const DirectChatPage({
    super.key,
    required this.username,
    required this.otherUserId,
  });

  @override
  State<DirectChatPage> createState() => _DirectChatPageState();
}

class _DirectChatPageState extends State<DirectChatPage> {
  final client = Supabase.instance.client;
  final controller = TextEditingController();
  final ImagePicker imagePicker = ImagePicker();
  final AudioRecorder audioRecorder = AudioRecorder();
  final AudioPlayer audioPlayer = AudioPlayer();

  bool uploadingImage = false;
  bool isRecording = false;
  bool uploadingAudio = false;
  bool clearingChat = false;
  String? playingAudioPath;

  String? conversationId;
  String? error;

  bool opening = true;
  bool sending = false;

  String? lastMarkedMessageId;

  final AesGcm _aes = AesGcm.with256bits();
  final Pbkdf2 _kdf = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: 100000,
    bits: 256,
  );

  Future<SecretKey> _encryptionSecretKey() {
    return _kdf.deriveKeyFromPassword(
      password: _sharedPassphrase,
      nonce: utf8.encode(_keyDerivationSalt),
    );
  }

  Future<Map<String, String>> _encryptBytes(List<int> plainBytes) async {
    final nonce = _aes.newNonce();
    final box = await _aes.encrypt(
      plainBytes,
      secretKey: await _encryptionSecretKey(),
      nonce: nonce,
    );
    final combined = <int>[...box.cipherText, ...box.mac.bytes];
    return {
      'data': base64Encode(combined),
      'nonce': base64Encode(nonce),
    };
  }

  Future<Uint8List> _decryptBytes(String encryptedData, String nonceText) async {
    final combined = base64Decode(encryptedData);
    if (combined.length < 16) {
      throw const FormatException('Encrypted data is incomplete.');
    }
    final cipherText = combined.sublist(0, combined.length - 16);
    final macBytes = combined.sublist(combined.length - 16);
    final box = SecretBox(
      cipherText,
      nonce: base64Decode(nonceText),
      mac: Mac(macBytes),
    );
    final plain = await _aes.decrypt(
      box,
      secretKey: await _encryptionSecretKey(),
    );
    return Uint8List.fromList(plain);
  }

  Future<Map<String, String>> _encryptText(String plainText) =>
      _encryptBytes(utf8.encode(plainText));

  Future<String> _decryptText(Map<String, dynamic> message) async {
    if (message['encrypted'] != true) return message['body']?.toString() ?? '';
    final nonce = message['encryption_nonce']?.toString();
    if (nonce == null || nonce.isEmpty) return '[Missing encryption nonce]';
    try {
      final bytes = await _decryptBytes(message['body'].toString(), nonce);
      return utf8.decode(bytes);
    } catch (_) {
      return '[Could not decrypt message]';
    }
  }

  @override
  void initState() {
    super.initState();
    openConversation();
  }

  Future<void> markRead({String? latestIncomingId}) async {
    final id = conversationId;

    if (id == null) return;

    if (latestIncomingId != null &&
        latestIncomingId == lastMarkedMessageId) {
      return;
    }

    final now = DateTime.now().toUtc().toIso8601String();

    try {
      await client.from('direct_conversation_reads').upsert(
        {
          'conversation_id': id,
          'user_id': client.auth.currentUser!.id,
          'last_read_at': now,
        },
        onConflict: 'conversation_id,user_id',
      );

      if (latestIncomingId != null) {
        lastMarkedMessageId = latestIncomingId;
      }
    } catch (e) {
      // Read-status failures should not prevent chatting.
      debugPrint('Could not update read status: $e');
    }
  }

  Future<void> openConversation() async {
    try {
      final result = await client.rpc(
        'open_direct_conversation',
        params: {
          'target_user_id': widget.otherUserId,
        },
      );

      if (result == null) {
        throw Exception('No conversation ID was returned.');
      }

      conversationId = result.toString();

      // Opening a chat marks previous messages as read.
      await markRead();
    } catch (e) {
      error = 'Could not open conversation: $e';
    }

    if (mounted) {
      setState(() => opening = false);
    }
  }

  Future<void> sendMessage() async {
    final text = controller.text.trim();

    if (text.isEmpty || sending || conversationId == null) {
      return;
    }

    setState(() {
      sending = true;
      error = null;
    });

    try {
      final encrypted = await _encryptText(text);
      if (encrypted['data']!.length > 4000) {
        throw Exception('Message is too long after encryption.');
      }

      await client.from('direct_messages').insert({
        'conversation_id': conversationId,
        'sender_id': client.auth.currentUser!.id,
        'body': encrypted['data'],
        'encrypted': true,
        'encryption_nonce': encrypted['nonce'],
        'message_type': 'text',
      });

      controller.clear();
    } catch (e) {
      if (mounted) {
        setState(() {
          error = 'Message failed: $e';
        });
      }
    } finally {
      if (mounted) {
        setState(() => sending = false);
      }
    }
  }

  Future<void> sendImage() async {
    if (conversationId == null || uploadingImage || sending) return;

    try {
      final XFile? selected = await imagePicker.pickImage(
        source: ImageSource.gallery,
        imageQuality: 80,
      );

      if (selected == null || !mounted) return;

      setState(() {
        uploadingImage = true;
        error = null;
      });

      final userId = client.auth.currentUser!.id;
      final extension = selected.name.contains('.')
          ? selected.name.split('.').last.toLowerCase()
          : 'jpg';
      final safeExtension = RegExp(r'^[a-z0-9]{2,5}$').hasMatch(extension)
          ? extension
          : 'jpg';
      final fileName = '${DateTime.now().millisecondsSinceEpoch}.$safeExtension';
      final encrypted = await _encryptBytes(await File(selected.path).readAsBytes());
      final encryptedPath = '$conversationId/$userId/${fileName}.enc';
      await client.storage.from('chat-media').uploadBinary(
        encryptedPath,
        base64Decode(encrypted['data']!),
      );

      await client.from('direct_messages').insert({
        'conversation_id': conversationId,
        'sender_id': userId,
        'body': '',
        'message_type': 'image',
        'media_path': encryptedPath,
        'encrypted': true,
        'encryption_nonce': encrypted['nonce'],
      });
    } catch (e) {
      if (mounted) {
        setState(() => error = 'Could not send image: $e');
      }
    } finally {
      if (mounted) {
        setState(() => uploadingImage = false);
      }
    }
  }

  Future<Uint8List> getImageBytes(Map<String, dynamic> message) async {
    final path = message['media_path'].toString();
    final data = await client.storage.from('chat-media').download(path);
    if (message['encrypted'] != true) return data;
    final nonce = message['encryption_nonce']?.toString();
    if (nonce == null || nonce.isEmpty) {
      throw const FormatException('Missing image encryption nonce.');
    }
    // Storage holds ciphertext + authentication tag; nonce is in the row.
    return _decryptBytes(base64Encode(data), nonce);
  }

  Future<void> toggleRecording() async {
    if (conversationId == null || uploadingAudio || uploadingImage || sending) {
      return;
    }

    try {
      if (!isRecording) {
        final permitted = await audioRecorder.hasPermission();
        if (!permitted) {
          if (mounted) {
            setState(() => error = 'Microphone permission was not granted.');
          }
          return;
        }

        final directory = await getTemporaryDirectory();
        final path = '${directory.path}/voice_${DateTime.now().millisecondsSinceEpoch}.m4a';
        await audioRecorder.start(
          const RecordConfig(encoder: AudioEncoder.aacLc),
          path: path,
        );
        if (mounted) {
          setState(() {
            isRecording = true;
            error = null;
          });
        }
      } else {
        final path = await audioRecorder.stop();
        if (mounted) setState(() => isRecording = false);
        if (path == null) return;

        final file = File(path);
        if (!await file.exists() || await file.length() == 0) {
          if (mounted) setState(() => error = 'No audio was recorded. Please try again.');
          return;
        }

        if (mounted) {
          setState(() {
            uploadingAudio = true;
            error = null;
          });
        }

        final userId = client.auth.currentUser!.id;
        final fileName = 'voice_${DateTime.now().millisecondsSinceEpoch}.m4a';
        final storagePath = '$conversationId/$userId/$fileName';

        final encrypted = await _encryptBytes(await file.readAsBytes());
        final encryptedPath = '$conversationId/$userId/$fileName.enc';
        await client.storage.from('chat-media').uploadBinary(
          encryptedPath,
          base64Decode(encrypted['data']!),
        );
        await client.from('direct_messages').insert({
          'conversation_id': conversationId,
          'sender_id': userId,
          'body': '',
          'message_type': 'audio',
          'media_path': encryptedPath,
          'encrypted': true,
          'encryption_nonce': encrypted['nonce'],
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          isRecording = false;
          error = 'Could not record or send voice message: $e';
        });
      }
    } finally {
      if (mounted) setState(() => uploadingAudio = false);
    }
  }

  Future<void> playVoice(Map<String, dynamic> message) async {
    final path = message['media_path'].toString();
    try {
      final data = await client.storage.from('chat-media').download(path);
      Uint8List audioBytes = data;
      if (message['encrypted'] == true) {
        final nonce = message['encryption_nonce']?.toString();
        if (nonce == null || nonce.isEmpty) {
          throw const FormatException('Missing voice encryption nonce.');
        }
        audioBytes = await _decryptBytes(base64Encode(data), nonce);
      }
      setState(() => playingAudioPath = path);
      await audioPlayer.play(BytesSource(audioBytes));
      audioPlayer.onPlayerComplete.first.then((_) {
        if (mounted && playingAudioPath == path) {
          setState(() => playingAudioPath = null);
        }
      });
    } catch (e) {
      if (mounted) setState(() => error = 'Could not play voice message: $e');
    }
  }

  Future<void> clearConversation() async {
    if (conversationId == null || clearingChat) return;

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Clear this chat?'),
        content: const Text(
          'This permanently deletes all messages and attached images/voice files in this conversation for both participants. This cannot be undone.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: Colors.red),
            onPressed: () => Navigator.pop(dialogContext, true),
            child: const Text('Delete all'),
          ),
        ],
      ),
    );

    if (confirmed != true) return;
    setState(() {
      clearingChat = true;
      error = null;
    });

    try {
      final rows = await client
          .from('direct_messages')
          .select('media_path')
          .eq('conversation_id', conversationId!);
      final paths = rows
          .map((row) => row['media_path'])
          .whereType<String>()
          .where((path) => path.isNotEmpty)
          .toList();

      if (paths.isNotEmpty) {
        await client.storage.from('chat-media').remove(paths);
      }

      await client
          .from('direct_messages')
          .delete()
          .eq('conversation_id', conversationId!);

      await markRead();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Chat messages and media deleted.')),
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() => error = 'Could not clear chat: $e');
      }
    } finally {
      if (mounted) setState(() => clearingChat = false);
    }
  }

  @override
  void dispose() {
    controller.dispose();
    unawaited(audioRecorder.dispose());
    unawaited(audioPlayer.dispose());
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('@${widget.username}'),
        actions: [
          IconButton(
            tooltip: 'Clear chat',
            onPressed: clearingChat ? null : clearConversation,
            icon: clearingChat
                ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.delete_sweep_outlined, color: Colors.red),
          ),
        ],
      ),
      body: opening
          ? const Center(
        child: CircularProgressIndicator(),
      )
          : error != null && conversationId == null
          ? Center(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Text(
            error!,
            textAlign: TextAlign.center,
          ),
        ),
      )
          : Column(
        children: [
          Container(
            width: double.infinity,
            color: const Color(0xFFFFF1D6),
            padding: const EdgeInsets.all(9),
            child: const Text(
              'Prototype chat: messages are not end-to-end encrypted.',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 12),
            ),
          ),
          if (error != null)
            Padding(
              padding: const EdgeInsets.all(8),
              child: Text(
                error!,
                style: const TextStyle(color: Colors.red),
              ),
            ),
          Expanded(
            child: StreamBuilder<List<Map<String, dynamic>>>(
              stream: client
                  .from('direct_messages')
                  .stream(primaryKey: ['id'])
                  .eq('conversation_id', conversationId!)
                  .order('created_at'),
              builder: (context, snapshot) {
                if (snapshot.hasError) {
                  return Center(
                    child: Padding(
                      padding: const EdgeInsets.all(20),
                      child: Text(
                        'Could not load messages: ${snapshot.error}',
                        textAlign: TextAlign.center,
                      ),
                    ),
                  );
                }

                if (!snapshot.hasData) {
                  return const Center(
                    child: CircularProgressIndicator(),
                  );
                }

                final messages = snapshot.data!;
                final myId = client.auth.currentUser!.id;

                // Update read status for incoming messages while
                // this chat is open.
                final incoming = messages
                    .where((m) => m['sender_id'] != myId)
                    .toList();

                if (incoming.isNotEmpty) {
                  final newest = incoming.last;
                  final newestId = newest['id'].toString();

                  if (newestId != lastMarkedMessageId) {
                    WidgetsBinding.instance.addPostFrameCallback((_) {
                      if (mounted) {
                        markRead(
                          latestIncomingId: newestId,
                        );
                      }
                    });
                  }
                }

                if (messages.isEmpty) {
                  return const Center(
                    child: Text('Say hello!'),
                  );
                }

                return ListView.builder(
                  padding: const EdgeInsets.all(16),
                  itemCount: messages.length,
                  itemBuilder: (context, index) {
                    final message = messages[index];
                    final mine = message['sender_id'] == myId;

                    return Align(
                      alignment: mine
                          ? Alignment.centerRight
                          : Alignment.centerLeft,
                      child: Container(
                        margin: const EdgeInsets.only(
                          bottom: 10,
                        ),
                        padding: const EdgeInsets.symmetric(
                          horizontal: 14,
                          vertical: 10,
                        ),
                        constraints: BoxConstraints(
                          maxWidth:
                          MediaQuery.sizeOf(context).width * .78,
                        ),
                        decoration: BoxDecoration(
                          color: mine ? green : Colors.white,
                          borderRadius: BorderRadius.circular(16),
                        ),
                        child: message['message_type'] == 'audio' &&
                            message['media_path'] != null
                            ? SizedBox(
                          width: 190,
                          child: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              IconButton(
                                onPressed: () => playVoice(message),
                                icon: Icon(
                                  playingAudioPath == message['media_path']
                                      ? Icons.volume_up
                                      : Icons.play_circle_fill,
                                  color: mine ? Colors.white : green,
                                  size: 32,
                                ),
                              ),
                              Flexible(
                                child: Text(
                                  'Voice message',
                                  style: TextStyle(color: mine ? Colors.white : Colors.black87),
                                ),
                              ),
                            ],
                          ),
                        )
                            : message['message_type'] == 'image' &&
                            message['media_path'] != null
                            ? FutureBuilder<Uint8List>(
                          future: getImageBytes(message),
                          builder: (context, imageSnapshot) {
                            if (imageSnapshot.hasError) {
                              return const SizedBox(
                                width: 200,
                                child: Text('Could not load image'),
                              );
                            }

                            if (!imageSnapshot.hasData) {
                              return const SizedBox(
                                width: 200,
                                height: 150,
                                child: Center(
                                  child: CircularProgressIndicator(),
                                ),
                              );
                            }

                            return GestureDetector(
                              onTap: () {
                                showDialog<void>(
                                  context: context,
                                  builder: (_) => Dialog(
                                    child: InteractiveViewer(
                                      child: Image.memory(
                                        imageSnapshot.data!,
                                        fit: BoxFit.contain,
                                      ),
                                    ),
                                  ),
                                );
                              },
                              child: ClipRRect(
                                borderRadius: BorderRadius.circular(10),
                                child: Image.memory(
                                  imageSnapshot.data!,
                                  width: 220,
                                  fit: BoxFit.cover,
                                  errorBuilder: (_, __, ___) =>
                                  const SizedBox(
                                    width: 200,
                                    child: Text('Image unavailable'),
                                  ),
                                ),
                              ),
                            );
                          },
                        )
                            : FutureBuilder<String>(
                          future: _decryptText(message),
                          builder: (context, textSnapshot) => Text(
                            textSnapshot.data ?? 'Decrypting…',
                            style: TextStyle(
                              color: mine ? Colors.white : Colors.black87,
                            ),
                          ),
                        ),
                      ),
                    );
                  },
                );
              },
            ),
          ),
          SafeArea(
            top: false,
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: controller,
                      minLines: 1,
                      maxLines: 4,
                      textCapitalization:
                      TextCapitalization.sentences,
                      onSubmitted: (_) => sendMessage(),
                      decoration: const InputDecoration(
                        hintText: 'Message',
                        filled: true,
                        fillColor: Colors.white,
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.all(
                            Radius.circular(24),
                          ),
                        ),
                      ),
                    ),
                  ),
                  IconButton(
                    tooltip: 'Send image',
                    onPressed: uploadingImage || uploadingAudio || sending || isRecording ? null : sendImage,
                    icon: uploadingImage
                        ? const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                        : const Icon(Icons.image_outlined, color: green),
                  ),
                  IconButton(
                    tooltip: isRecording ? 'Stop and send voice' : 'Record voice',
                    onPressed: uploadingImage || uploadingAudio || sending ? null : toggleRecording,
                    icon: uploadingAudio
                        ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                        : Icon(isRecording ? Icons.stop_circle : Icons.mic, color: isRecording ? Colors.red : green),
                  ),
                  const SizedBox(width: 4),
                  IconButton.filled(
                    onPressed: sending ? null : sendMessage,
                    icon: sending
                        ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                      ),
                    )
                        : const Icon(Icons.send),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
