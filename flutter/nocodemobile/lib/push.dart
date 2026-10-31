import 'package:flutter/services.dart';
import 'app_properties.dart';

/// Push notifications through the native side (MainActivity.kt: FCM, AppDelegate.swift: APNs).
///
/// The web app drives it through the WebView's JS handlers (pushRegister, pushStatus,
/// pushToken in webview.dart) and registers the device with the notification service itself,
/// with its own sign-in: the native side never sees the user's token.
class Push {
  static const _channel = MethodChannel('modlix/push');
  static const _unsupported = {'status': 'unsupported'};

  static Future<Map<String, dynamic>> _call(String method, [Map<String, dynamic>? args]) async {
    if (!AppProperties.pushEnabled) return _unsupported;
    try {
      final r = await _channel.invokeMethod<Map<dynamic, dynamic>>(method, args);
      return r == null ? _unsupported : r.map((k, v) => MapEntry(k.toString(), v));
    } on PlatformException {
      return _unsupported;
    } on MissingPluginException {
      return _unsupported;
    }
  }

  /// {status}: granted, denied, default or unsupported.
  static Future<Map<String, dynamic>> status() => _call('status');

  /// The device for the notification service; asks the user first when [prompt].
  static Future<Map<String, dynamic>> register(bool prompt) => _call('register', {'prompt': prompt});

  /// The device as it is now, never asking (sign-out).
  static Future<Map<String, dynamic>> token() => _call('token');

  /// The url of the notification that started the app, once.
  static Future<String?> initialUrl() async {
    if (!AppProperties.pushEnabled) return null;
    try {
      return await _channel.invokeMethod<String>('initialUrl');
    } on PlatformException {
      return null;
    } on MissingPluginException {
      return null;
    }
  }

  /// [open] gets the url of each notification tapped while the app runs.
  static void onOpen(void Function(String url) open) {
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'open' && call.arguments is String) open(call.arguments as String);
    });
  }

  /// A notification's url as a page of this app: relative ones resolve against the start URL
  /// (with its /{app}/{client} prefix on a shared host); another site's are refused.
  static Uri? resolve(String url) {
    final start = Uri.parse(AppProperties.startURL);
    var path = url.trim();
    if (path.isEmpty) return null;
    final at = start.path.indexOf('/page');
    final prefix = at > 0 ? start.path.substring(0, at) : '';
    if (path.startsWith('/') && !path.startsWith('//') && prefix.isNotEmpty && !path.startsWith('$prefix/')) {
      path = '$prefix$path';
    }
    final target = start.resolve(path);
    if (target.host != start.host || (target.scheme != 'https' && target.scheme != 'http')) return null;
    return target;
  }
}
