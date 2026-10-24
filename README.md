# LabChat 💬

### A Flutter-Based Private Messaging Application

LabChat is an Android-first private messaging application built with Flutter and Supabase. It provides a simple interface for direct conversations, real-time message delivery, media sharing, voice messages, and encrypted message storage.

The project explores mobile application development, backend integration, real-time communication, cloud storage, and cryptographic techniques in a practical messaging application.

> **Project status:** Prototype / Educational Project  
> **Platform:** Android  
> **Framework:** Flutter  
> **Backend:** Supabase

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Screens and User Experience](#screens-and-user-experience)
- [Technology Stack](#technology-stack)
- [System Architecture](#system-architecture)
- [Encryption and Data Protection](#encryption-and-data-protection)
- [Database Structure](#database-structure)
- [Media Storage](#media-storage)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation and Setup](#installation-and-setup)
- [Building the APK](#building-the-apk)
- [GitHub Setup](#github-setup)
- [Security Considerations](#security-considerations)
- [Limitations and Future Improvements](#limitations-and-future-improvements)
- [License](#license)

---

## Overview

LabChat is a mobile messaging prototype designed to demonstrate how a Flutter application can communicate with a cloud backend to support private, one-to-one conversations.

The application uses Supabase for authentication, database operations, real-time updates, and media storage. Messages and media can be encrypted before being stored, and the application decrypts supported content when displaying or playing it.

LabChat aims to combine a straightforward user experience with practical implementation of mobile messaging features and cryptographic concepts.

## Features

### 1. User Authentication and Profiles

- Anonymous authentication through Supabase.
- Username registration for first-time users.
- Persistent user identity through the authentication session.
- User discovery through registered profiles.

### 2. Direct Messaging

- One-to-one conversations between registered users.
- Create or open a direct conversation.
- Send and receive text messages.
- Real-time message updates through Supabase.
- Conversation inbox with latest-message previews.
- Display text previews for encrypted messages after decryption.
- Image and voice-message indicators in the inbox.

### 3. Unread Message Indicators

- Track the latest read message state for each user and conversation.
- Display an unread indicator in the conversation inbox.
- Keep read status separate for individual participants.

### 4. Image Sharing

- Select images using the device's image picker.
- Upload image files to private Supabase Storage.
- Encrypt supported image data before upload.
- Download and decrypt encrypted images for display inside conversations.

### 5. Voice Messages

- Record audio using the device microphone.
- Upload voice messages to Supabase Storage.
- Encrypt supported audio data before upload.
- Download, decrypt, and play audio messages.

The application requires microphone permission for audio recording.

### 6. Encrypted Message Storage

- Encrypt supported text messages before database insertion.
- Encrypt supported image and audio data before storage upload.
- Store encryption metadata alongside message records.
- Decrypt supported content when needed by the application.
- Retain compatibility with older messages marked as unencrypted.

### 7. Conversation Management

- Clear messages in a conversation.
- Remove associated media where supported by the configured storage policies.
- Maintain conversation and read-state information separately from message content.

### 8. Custom Android Launcher Icon

LabChat uses a custom speech-bubble icon to identify the application on Android devices.

---

## Screens and User Experience

The application includes the following primary user flows:

1. **First launch:** Authenticate through Supabase and register a username.
2. **Inbox:** View existing direct conversations, latest-message previews, and unread indicators.
3. **New conversation:** Select a registered user and open a direct conversation.
4. **Chat:** Exchange text messages and share images or voice recordings.
5. **Media playback:** Display received images and play received voice messages.
6. **Conversation management:** Clear a conversation's messages through the available chat controls.

The interface is designed around direct messaging and straightforward navigation rather than a complex social networking experience.

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Flutter | Cross-platform mobile application framework |
| Dart | Application programming language |
| Supabase | Backend services and database |
| Supabase Auth | User authentication |
| PostgreSQL | Persistent relational data storage |
| Supabase Realtime | Live message updates |
| Supabase Storage | Private image and audio file storage |
| `cryptography` | Cryptographic operations |
| `cryptography_flutter` | Flutter cryptography integration |
| `flutter_secure_storage` | Secure local storage capability |
| `image_picker` | Image selection |
| `record` | Audio recording |
| `audioplayers` | Audio playback |
| `path_provider` | Access to application file directories |

---

## System Architecture

LabChat follows a client-backend architecture.

```text
+-------------------------------+
|        Flutter Android App    |
|                               |
|  Authentication and Profiles  |
|  Conversation Inbox            |
|  Direct Messaging              |
|  Image and Audio Interfaces    |
|  Encryption and Decryption     |
+---------------+---------------+
                |
                v
+-------------------------------+
|          Supabase             |
|                               |
|  Authentication               |
|  PostgreSQL Database           |
|  Realtime Messaging            |
|  Private Object Storage        |
|  Row-Level Security Policies   |
+-------------------------------+
```

### Message flow

1. A user writes a message in the Flutter application.
2. The application encrypts the message using its configured cryptographic implementation.
3. The encrypted payload and required metadata are stored in Supabase.
4. The receiving client retrieves the message.
5. The client uses the corresponding cryptographic parameters to decrypt the payload.
6. The original text or media is presented to the user.

For media messages, the encrypted file is uploaded to private object storage, while the database record stores the associated message type and media path.

---

## Encryption and Data Protection

LabChat implements symmetric authenticated encryption using **AES-256-GCM**.

### Cryptographic components

| Component | Role |
|---|---|
| AES-256-GCM | Encrypts data and authenticates its integrity |
| PBKDF2-HMAC-SHA256 | Derives a 256-bit key from a configured passphrase |
| 100,000 iterations | Configured password-based key derivation work factor |
| Configured salt | Used during key derivation |
| Random nonce | Used for each encryption operation |
| Authentication tag | Allows the receiver to verify the encrypted payload |

### Key derivation

The prototype derives an AES key from a shared passphrase using PBKDF2-HMAC-SHA256. Both clients must use compatible key-derivation settings to derive the same key.

### Encryption workflow

```text
Original Text or Media
          |
          v
  Key Derivation
          |
          v
    AES-256-GCM
          |
          v
 Encrypted Payload
          |
          v
 Supabase Database
 or Private Storage
```

The receiving client retrieves the encrypted payload and nonce, then authenticates and decrypts the content.

### Important security limitations

This implementation is an educational prototype, not a production-ready end-to-end encrypted messaging system.

- The shared passphrase is embedded in the application source and can be extracted from a distributed application.
- The configured salt is static rather than unique per user or conversation.
- A secure key exchange and per-conversation key management system have not been established.
- A private Supabase Storage bucket and database access policies provide access controls, but do not by themselves guarantee end-to-end encryption.
- Key rotation, device enrollment, forward secrecy, and multi-device key management are not implemented.

For production use, the encryption design should be reviewed and upgraded to use a strong secret-management and key-establishment scheme.

---

## Database Structure

LabChat uses PostgreSQL tables managed by Supabase.

The direct-messaging implementation includes the following principal tables:

| Table | Purpose |
|---|---|
| `profiles` | Stores user profile information, including usernames |
| `direct_conversations` | Represents direct conversations |
| `direct_messages` | Stores direct-message content and metadata |
| `direct_conversation_reads` | Tracks per-user conversation read state |

A database function named `open_direct_conversation` is used to open or create a direct conversation with another user.

### Message metadata

Direct-message records can include:

- `conversation_id`: Conversation associated with the message.
- `sender_id`: User who sent the message.
- `body`: Text content or encoded encrypted text payload.
- `created_at`: Message creation timestamp.
- `message_type`: Text, image, or audio.
- `media_path`: Storage path for a media file, when applicable.
- `encrypted`: Indicates whether the content is encrypted.
- `encryption_nonce`: Nonce needed for supported decryption operations.

### Database security

The project uses Supabase access policies to control database and storage operations. The security of these policies depends on their actual configuration and testing.

---

## Media Storage

The application uses a private Supabase Storage bucket named `chat-media`.

Media paths follow this general structure:

```text
conversation_id/user_id/filename
```

Images and audio are uploaded as files. Encrypted media is stored in encrypted form and decrypted by the application when needed.

The bucket is intended to remain private. Access should be controlled by Storage policies that verify the authenticated user's authorization to access the relevant conversation and media.

---

## Project Structure

The main project files and directories include:

```text
LabChat/
├── android/
│   └── app/
│       └── src/
│           └── main/
├── assets/
│   └── icon/
│       └── labchat_icon.png
├── config/
│   └── supabase.local.json
├── lib/
│   └── main.dart
├── test/
├── .gitignore
├── analysis_options.yaml
├── pubspec.yaml
├── pubspec.lock
└── README.md
```

The exact contents may vary depending on your local development environment.

**Important:** `config/supabase.local.json` contains local configuration and should not be committed to a public or shared repository if it contains credentials.

---

## Requirements

To develop and build LabChat locally, you need:

- Windows, macOS, or Linux.
- Flutter SDK compatible with the project's Dart SDK constraint.
- Android SDK and Android build tools.
- Java Development Kit compatible with the Android Gradle configuration.
- A Supabase project.
- An Android device or emulator for testing.
- Git, if you want to manage the project through Git commands.

Android Studio is recommended for Android SDK management, emulator setup, and debugging.

---

## Installation and Setup

### 1. Clone the repository

If you have Git installed:

```bash
git clone https://github.com/YOUR-USERNAME/LabChat.git
cd LabChat
```

Alternatively, download the repository as a ZIP from GitHub and extract it.

### 2. Install Flutter dependencies

```bash
flutter pub get
```

### 3. Configure Supabase

Create a local configuration file at:

```text
config/supabase.local.json
```

The file should contain the Supabase project URL and a publishable client key, or the project's supported anonymous client key where applicable.

Example structure:

```json
{
  "SUPABASE_URL": "YOUR_SUPABASE_PROJECT_URL",
  "SUPABASE_ANON_KEY": "YOUR_SUPABASE_PUBLISHABLE_OR_ANON_KEY"
}
```

Use the exact variable names expected by the application's initialization code. Do not use a Supabase service-role key in the mobile application.

### 4. Configure the backend

Before running the application, ensure the Supabase project has the required tables, database function, Storage bucket, and access policies.

The backend schema and policies must match the application's implementation.

### 5. Run the application

```bash
flutter run --dart-define-from-file=config/supabase.local.json
```

Connect an Android device with USB debugging enabled or launch an Android emulator.

---

## Building the APK

To build a release APK for Android:

```bash
flutter pub get
flutter build apk --release --dart-define-from-file=config/supabase.local.json
```

After a successful build, the APK is normally generated at:

```text
build/app/outputs/flutter-apk/app-release.apk
```

You can copy this file to a compatible Android device and install it.

### Important release considerations

- Test the release build on a real device before distributing it.
- Configure Android release signing before publishing through an app store.
- Verify microphone permission and media playback on the target Android version.
- Keep local configuration files and signing credentials out of source control.
- Do not distribute the prototype as a secure messenger without a security review.

---

## GitHub Setup

The repository can be uploaded using Git or through GitHub's web interface.

Before uploading:

1. Exclude local Supabase configuration files.
2. Exclude signing keys and passwords.
3. Exclude generated folders such as `build/` and `.dart_tool/`.
4. Review the code for embedded secrets.
5. Include this README and the files needed to reproduce the project.

A private repository is recommended while the project is under development.

---

## Limitations and Future Improvements

Potential improvements include:

- Stronger cryptographic key management and secure key exchange.
- A security review of encryption and database access policies.
- Secure account registration and account recovery.
- Better error handling for uploads, downloads, and network failures.
- Message deletion and synchronization improvements.
- Image compression and media upload progress.
- Improved voice-message controls.
- Delivery and read receipts.
- Push notifications.
- Message search.
- Automated tests for encryption, authentication, and messaging.
- CI/CD workflows for automated Android builds.
- A polished adaptive Android launcher icon.
- Release signing and distribution preparation.

These are potential future improvements, not claims that they are already implemented.

---

## License

No license has been specified for this project yet.

If you intend to make the source code publicly reusable, select a license and add a corresponding `LICENSE` file. If you do not want to grant reuse rights yet, keep the repository private while deciding.

---

## Author

**LabChat — Private Messaging Prototype**

Built with Flutter, Dart, and Supabase.

This project is intended for learning, experimentation, and demonstrating the integration of mobile messaging, cloud backend services, media handling, and cryptographic operations.
