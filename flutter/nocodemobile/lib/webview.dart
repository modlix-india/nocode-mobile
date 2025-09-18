import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';
import 'package:dio/dio.dart';
import 'package:path_provider/path_provider.dart';
import 'package:flutter_file_dialog/flutter_file_dialog.dart';
import 'package:open_filex/open_filex.dart';

class MyWebView extends StatefulWidget {
  final String url;
  const MyWebView({super.key, required this.url});

  @override
  State<MyWebView> createState() => _MyWebViewState();
}

class _MyWebViewState extends State<MyWebView> {
  InAppWebViewController? _controller;
  final _dio = Dio();
  double? _progress; // 0..1 or null (hidden)

  void _toast(String msg) =>
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));

  Future<Map<String, String>> _cookieHeader(Uri url) async {
    final cookies = await CookieManager.instance().getCookies(
      url: WebUri(url.toString()),
    );
    if (cookies.isEmpty) return {};
    return {'Cookie': cookies.map((c) => '${c.name}=${c.value}').join('; ')};
    // Add other auth headers if your backend uses tokens:
    // return {'Cookie': cookieStr, 'Authorization': 'Bearer ...'};
  }

  String _inferName(String url, [String? suggested]) {
    if (suggested != null && suggested.trim().isNotEmpty) return suggested;
    final u = Uri.parse(url);
    final last = (u.pathSegments.isNotEmpty ? u.pathSegments.last : '').trim();
    return (last.isEmpty) ? 'file.bin' : last;
  }

  /// Streams the URL to a temp file, then shows a native "Save to..." dialog.
  Future<void> _downloadThenSave(String url, {String? suggestedName}) async {
    final headers = await _cookieHeader(Uri.parse(url));
    final filename = _inferName(url, suggestedName);

    // 1) Stream to a temp file (memory-safe for 10s of MB)
    final tmpDir = await getTemporaryDirectory();
    final tmpPath = '${tmpDir.path}/$filename';
    final file = File(tmpPath);
    if (file.existsSync()) await file.delete();

    setState(() => _progress = 0);
    try {
      final resp = await _dio.get<ResponseBody>(
        url,
        options: Options(
          responseType: ResponseType.stream,
          headers: headers,
          followRedirects: true,
        ),
      );

      final sink = file.openWrite();
      final total = resp.data?.contentLength ?? -1;
      int received = 0;

      await for (final chunk in resp.data!.stream) {
        received += chunk.length;
        sink.add(chunk);
        if (total > 0) setState(() => _progress = received / total);
      }
      await sink.close();
    } finally {
      if (mounted) setState(() => _progress = null);
    }

    // 2) Let the user pick a destination (Android SAF / iOS Files)
    final savedPath = await FlutterFileDialog.saveFile(
      params: SaveFileDialogParams(sourceFilePath: tmpPath, fileName: filename),
    );

    if (savedPath == null) {
      _toast('Save cancelled');
      return;
    }

    _toast('Saved to: $savedPath');

    // Optional: open the file right away
    // await OpenFilex.open(savedPath);
  }

  // (Optional) intercept “blob:” URLs created by JS
  static const _blobHook = r'''
    (function() {
      if (window.__blobHookInstalled) return; window.__blobHookInstalled = true;
      async function fetchBlobAsUrl(url, name) {
        try {
          const res = await fetch(url);
          const blob = await res.blob();
          const arrayBuffer = await blob.arrayBuffer();
          const bytes = new Uint8Array(arrayBuffer);
          let binary = '';
          const chunk = 0x8000;
          for (let i = 0; i < bytes.length; i += chunk) {
            binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
          }
          const b64 = btoa(binary);
          if (window.flutter_inappwebview?.callHandler) {
            await window.flutter_inappwebview.callHandler('saveBase64File', b64, name || 'file.bin');
          }
        } catch (e) { console.error('blob save failed', e); }
      }
      document.addEventListener('click', function(e) {
        const a = e.target.closest('a'); if (!a) return;
        const href = a.getAttribute('href') || '';
        const dl = a.getAttribute('download') || '';
        if (href.startsWith('blob:')) { e.preventDefault(); fetchBlobAsUrl(href, dl); }
      }, true);
    })();
  ''';

  Future<void> _saveBase64(String base64, String fileName) async {
    // Write to temp, then let user pick final location
    final tmpDir = await getTemporaryDirectory();
    final tmpPath =
        '${tmpDir.path}/${fileName.isNotEmpty ? fileName : 'file.bin'}';
    final f = File(tmpPath);
    await f.writeAsBytes(const Base64Decoder().convert(base64));
    final savedPath = await FlutterFileDialog.saveFile(
      params: SaveFileDialogParams(sourceFilePath: tmpPath, fileName: fileName),
    );
    if (savedPath != null) _toast('Saved to: $savedPath');
  }

  bool _looksLikeFileUrl(String u) => RegExp(
    r'\.(pdf|docx?|xlsx?|pptx?|zip|rar|7z|png|jpe?g|gif|mp4|apk)$',
    caseSensitive: false,
  ).hasMatch(u);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Stack(
        children: [
          InAppWebView(
            initialUrlRequest: URLRequest(url: WebUri(widget.url)),
            initialSettings: InAppWebViewSettings(
              javaScriptEnabled: true,
              allowsInlineMediaPlayback: true,
              useOnDownloadStart: true,
            ),
            onWebViewCreated: (c) async {
              _controller = c;

              // For blob: URLs
              c.addJavaScriptHandler(
                handlerName: 'saveBase64File',
                callback: (args) async {
                  final b64 = args[0] as String;
                  final name = (args.length > 1
                      ? args[1] as String
                      : 'file.bin');
                  await _saveBase64(b64, name);
                },
              );
            },
            onLoadStop: (c, url) async {
              await c.evaluateJavascript(source: _blobHook);
            },

            // Direct downloads (Content-Disposition etc.)
            onDownloadStartRequest: (controller, request) async {
              await _downloadThenSave(
                request.url.toString(),
                suggestedName: request.suggestedFilename,
              );
            },

            // Intercept common file extensions
            shouldOverrideUrlLoading: (controller, action) async {
              final u = action.request.url?.toString() ?? '';
              if (_looksLikeFileUrl(u)) {
                await _downloadThenSave(u);
                return NavigationActionPolicy.CANCEL;
              }
              return NavigationActionPolicy.ALLOW;
            },
          ),

          if (_progress != null)
            Positioned(
              left: 0,
              right: 0,
              bottom: 0,
              child: LinearProgressIndicator(
                value: _progress == 0 ? null : _progress,
              ),
            ),
        ],
      ),
    );
  }
}
