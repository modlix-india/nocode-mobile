class AppProperties {
  static const String appTitle = '<appTitle>';
  static const String homePageTitle = '<appTitle>';
  static const String appVersion = '1.0.0';
  static const String startURL = 'https://apps.modlix.com';
  static const String appCode = '<appCode>';
  static const String clientCode = '<clientCode>';
  static const String appUserAgentTag = 'ModlixApp/$appVersion $clientCode/$appCode';
  // Custom URL scheme for the social-login callback from the system browser.
  // Unique per app; make.py overwrites this with "modlix.<clientCode>.<appCode>".
  // Must match android/app/build.gradle.kts manifestPlaceholders["ssoCallbackScheme"].
  static const String ssoCallbackScheme = 'modlix';
  static const bool generatedSplashScreen = false;
  static const String splashScreenImage = 'assets/splash_screen.png';
  static const String splashScreenBackgroundImage =
      'assets/splash_screen_background.png';
  static const String splashScreenImageDark = 'assets/splash_screen_dark.png';
  static const String splashScreenBackgroundImageDark =
      'assets/splash_screen_background_dark.png';
  static const bool splashScreenFullScreen = true;
  static const String splashScreenColor = '#FFFFFF';
  static const String splashScreenGravity = 'center';
  static const String splashScreenColorDark = '#FFFFFF';
}
