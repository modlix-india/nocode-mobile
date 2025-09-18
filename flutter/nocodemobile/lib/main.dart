import 'package:flutter/material.dart';
import 'app_properties.dart';
import 'webview.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: AppProperties.appTitle,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
        useMaterial3: true,
      ),
      home: AppProperties.generatedSplashScreen
          ? SplashScreen()
          : MyWebView(url: AppProperties.startURL),
    );
  }
}

class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen> {
  @override
  void initState() {
    super.initState();
    _initializeApp();
  }

  _initializeApp() async {
    // Wait for minimum splash screen duration
    await Future.delayed(const Duration(seconds: 3));

    if (mounted) {
      // Navigate to webview
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(
          builder: (context) => MyWebView(url: AppProperties.startURL),
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: _getSplashColor(),
      body: AppProperties.splashScreenFullScreen
          ? _buildFullScreenSplash()
          : _buildCenteredSplash(),
    );
  }

  Color _getSplashColor() {
    try {
      // Check if we're in dark mode
      final brightness = MediaQuery.of(context).platformBrightness;
      final isDarkMode = brightness == Brightness.dark;

      // Use dark color if available and in dark mode, otherwise use regular color
      String colorString;
      if (isDarkMode && AppProperties.splashScreenColorDark.isNotEmpty) {
        colorString = AppProperties.splashScreenColorDark;
      } else if (AppProperties.splashScreenColor.isNotEmpty) {
        colorString = AppProperties.splashScreenColor;
      } else {
        return Colors.white; // Default fallback
      }

      return Color(int.parse(colorString.replaceFirst('#', '0xFF')));
    } catch (e) {
      return Colors.white;
    }
  }

  String _getSplashImagePath() {
    // Check if we're in dark mode
    final brightness = MediaQuery.of(context).platformBrightness;
    final isDarkMode = brightness == Brightness.dark;

    // Return dark image if available and in dark mode, otherwise return regular image
    if (isDarkMode && AppProperties.splashScreenImageDark.isNotEmpty) {
      return AppProperties.splashScreenImageDark;
    } else if (AppProperties.splashScreenImage.isNotEmpty) {
      return AppProperties.splashScreenImage;
    }

    return '';
  }

  String _getSplashBackgroundImagePath() {
    // Check if we're in dark mode
    final brightness = MediaQuery.of(context).platformBrightness;
    final isDarkMode = brightness == Brightness.dark;

    // Return dark background image if available and in dark mode, otherwise return regular background image
    if (isDarkMode &&
        AppProperties.splashScreenBackgroundImageDark.isNotEmpty &&
        AppProperties.splashScreenBackgroundImageDark !=
            'assets/splash_screen_background_dark.png') {
      return AppProperties.splashScreenBackgroundImageDark;
    } else if (AppProperties.splashScreenBackgroundImage.isNotEmpty &&
        AppProperties.splashScreenBackgroundImage !=
            'assets/splash_screen_background.png') {
      return AppProperties.splashScreenBackgroundImage;
    }

    return '';
  }

  Alignment _getSplashGravity() {
    switch (AppProperties.splashScreenGravity.toLowerCase()) {
      case 'top':
        return Alignment.topCenter;
      case 'bottom':
        return Alignment.bottomCenter;
      case 'left':
        return Alignment.centerLeft;
      case 'right':
        return Alignment.centerRight;
      case 'center':
      default:
        return Alignment.center;
    }
  }

  Widget _buildFullScreenSplash() {
    return Container(
      width: double.infinity,
      height: double.infinity,
      decoration: BoxDecoration(
        color: _getSplashColor(),
        image: _getSplashBackgroundImagePath().isNotEmpty
            ? DecorationImage(
                image: AssetImage(_getSplashBackgroundImagePath()),
                fit: BoxFit.cover,
              )
            : null,
      ),
      child: _buildSplashContent(),
    );
  }

  Widget _buildCenteredSplash() {
    return Container(
      width: double.infinity,
      height: double.infinity,
      decoration: BoxDecoration(
        color: _getSplashColor(),
        image: _getSplashBackgroundImagePath().isNotEmpty
            ? DecorationImage(
                image: AssetImage(_getSplashBackgroundImagePath()),
                fit: BoxFit.cover,
              )
            : null,
      ),
      child: Center(
        child: Container(
          padding: const EdgeInsets.all(20),
          child: _buildSplashContent(),
        ),
      ),
    );
  }

  Widget _buildSplashContent() {
    return Align(
      alignment: _getSplashGravity(),
      child: _getSplashImagePath().isNotEmpty
          ? Image.asset(
              _getSplashImagePath(),
              fit: BoxFit.contain,
              errorBuilder: (context, error, stackTrace) {
                return Icon(Icons.web, size: 100, color: Colors.blue);
              },
            )
          : Icon(Icons.web, size: 100, color: Colors.blue),
    );
  }
}
