import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:logging/logging.dart';
import 'package:win32/win32.dart';

import './biometric_storage.dart';

final _logger = Logger('biometric_storage_win32');

class Win32BiometricStoragePlugin extends BiometricStorage {
  Win32BiometricStoragePlugin() : super.create();

  static const namePrefix = 'design.codeux.authpass.';

  /// Registers this class as the default instance of [PathProviderPlatform]
  static void registerWith() {
    BiometricStorage.instance = Win32BiometricStoragePlugin();
  }

  @override
  Future<CanAuthenticateResponse> canAuthenticate() async {
    return CanAuthenticateResponse.errorHwUnavailable;
  }

  @override
  Future<BiometricStorageFile> getStorage(
    String name, {
    StorageFileInitOptions? options,
    bool forceInit = false,
    PromptInfo promptInfo = PromptInfo.defaultValues,
  }) async {
    return BiometricStorageFile(this, namePrefix + name, promptInfo);
  }

  @override
  Future<bool> linuxCheckAppArmorError() async => false;

  @override
  Future<bool> delete(
    String name,
    PromptInfo promptInfo,
  ) async {
    return using((arena) {
      final targetName = arena.pcwstr(name);
      final Win32Result(:value, :error) =
          CredDelete(targetName, CRED_TYPE_GENERIC);
      if (!value) {
        if (error == ERROR_NOT_FOUND) {
          _logger.fine('Unable to find credential of name $name');
        } else {
          _logger.warning('Error: $error');
        }
        return false;
      }
      return true;
    });
  }

  @override
  Future<String?> read(
    String name,
    PromptInfo promptInfo,
  ) async {
    _logger.finer('read($name)');
    return using((arena) {
      final credPointer = arena<Pointer<CREDENTIAL>>();
      final targetName = arena.pcwstr(name);
      try {
        final result = CredRead(targetName, CRED_TYPE_GENERIC, credPointer);
        if (!result.value) {
          if (result.error == ERROR_NOT_FOUND) {
            _logger.fine('Unable to find credential of name $name');
          } else {
            _logger.warning(
              'Error: ${result.error} ',
              WindowsException(result.error.toHRESULT()),
            );
          }
          return null;
        }
        final cred = credPointer.value.ref;
        final blob = cred.CredentialBlob.asTypedList(cred.CredentialBlobSize);

        _logger.fine('CredFree()');
        CredFree(credPointer.value);

        return utf8.decode(blob);
      } finally {
        _logger.fine('read($name) done.');
      }
    });
  }

  @override
  Future<void> write(
    String name,
    String content,
    PromptInfo promptInfo,
  ) async {
    _logger.fine('write()');
    using((arena) {
      final examplePassword = utf8.encode(content);
      final Pointer<Uint8> blob = examplePassword.isEmpty
          ? nullptr
          : Uint8List.fromList(examplePassword).toNative(allocator: arena);
      final targetName = arena.pwstr(name);
      final userName = arena.pwstr('flutter.biometric_storage');

      final credential = arena<CREDENTIAL>();
      credential.ref
        ..Type = CRED_TYPE_GENERIC
        ..TargetName = targetName
        ..Persist = CRED_PERSIST_LOCAL_MACHINE
        ..UserName = userName
        ..CredentialBlob = blob
        ..CredentialBlobSize = examplePassword.length;

      final Win32Result(:value, :error) = CredWrite(credential, 0);
      if (!value) {
        throw BiometricStorageException(
            'Error writing credential $name: $error');
      }
    });
    _logger.fine('write done');
  }

  @override
  Future<void> dispose(String name) {
    // TODO: implement dispose
    throw UnimplementedError();
  }
}
