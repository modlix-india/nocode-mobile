import 'package:flutter/material.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';
import 'package:file_picker/file_picker.dart';

class MyWebView extends StatelessWidget {
  final String url;

  const MyWebView({super.key, required this.url});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: InAppWebView(
        initialUrlRequest: URLRequest(url: WebUri(url)),
        onWebViewCreated: (controller) {
          controller.addJavaScriptHandler(
            handlerName: 'fileSelected',
            callback: (args) async {
              await FilePicker.platform.pickFiles(
                allowMultiple: args[0] as bool,
                type: FileType.any,
              );
            },
          );
          controller.addJavaScriptHandler(
            handlerName: 'showFileChooser',
            callback: (args) async {
              await FilePicker.platform.pickFiles(
                allowMultiple: args[0] as bool,
                type: FileType.any,
              );
            },
          );
        },
        onPermissionRequest: (controller, request) async {
          return PermissionResponse(
            resources: request.resources,
            action: PermissionResponseAction.GRANT,
          );
        },
      ),
    );
  }
}
