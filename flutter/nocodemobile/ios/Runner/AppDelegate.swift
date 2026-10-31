import Flutter
import UIKit
import UserNotifications

// Push (APNs) for the web app through the `modlix/push` channel (lib/push.dart):
//   status     -> {status}
//   register   -> {status, platform, token, appIdentifier, providerAccount, apnsEnv}; asks with {prompt: true}
//   token      -> the same, never asking
//   initialUrl -> the url of the notification that started the app, once
// and "open" (url) to Dart when a notification is tapped while the app runs.
//
// No Firebase: the notification service posts to APNs with the Apple team's key. make.py writes
// ModlixApnsTeamId and ModlixApnsEnv into Info.plist and the aps-environment entitlement for an
// app with push on; without the entitlement registering fails and push answers "unsupported".
@main
@objc class AppDelegate: FlutterAppDelegate {
  private var channel: FlutterMethodChannel?
  private var waiting: [FlutterResult] = []
  private var initialUrl: String?
  /// Dart asked for the initial url, so it is listening for "open".
  private var dartReady = false

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    GeneratedPluginRegistrant.register(with: self)
    UNUserNotificationCenter.current().delegate = self
    if let push = launchOptions?[.remoteNotification] as? [AnyHashable: Any] {
      initialUrl = AppDelegate.url(of: push)
    }
    if let controller = window?.rootViewController as? FlutterViewController {
      let ch = FlutterMethodChannel(name: "modlix/push", binaryMessenger: controller.binaryMessenger)
      ch.setMethodCallHandler { [weak self] call, result in self?.handle(call, result) }
      channel = ch
    }
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  private static func url(of userInfo: [AnyHashable: Any]) -> String? {
    guard let u = userInfo["url"] as? String, !u.isEmpty else { return nil }
    return u
  }

  private func handle(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
    switch call.method {
    case "status":
      status { result(["status": $0]) }
    case "register":
      let prompt = (call.arguments as? [String: Any])?["prompt"] as? Bool ?? false
      register(prompt: prompt, result)
    case "token":
      register(prompt: false, result)
    case "initialUrl":
      dartReady = true
      result(initialUrl)
      initialUrl = nil
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func status(_ done: @escaping (String) -> Void) {
    UNUserNotificationCenter.current().getNotificationSettings { s in
      let value: String
      switch s.authorizationStatus {
      case .authorized, .provisional: value = "granted"
      case .denied: value = "denied"
      default: value = "default"
      }
      DispatchQueue.main.async { done(value) }
    }
  }

  private func register(prompt: Bool, _ result: @escaping FlutterResult) {
    status { current in
      if current == "granted" {
        self.waiting.append(result)
        UIApplication.shared.registerForRemoteNotifications()
      } else if current == "default" && prompt {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, _ in
          DispatchQueue.main.async {
            if granted {
              self.waiting.append(result)
              UIApplication.shared.registerForRemoteNotifications()
            } else {
              result(["status": "denied"])
            }
          }
        }
      } else {
        result(["status": current])
      }
    }
  }

  private func answerWaiting(_ answer: [String: Any]) {
    let all = waiting
    waiting = []
    all.forEach { $0(answer) }
  }

  override func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
    let info = Bundle.main.infoDictionary ?? [:]
    answerWaiting([
      "status": "granted",
      "platform": "IOS",
      "token": deviceToken.map { String(format: "%02x", $0) }.joined(),
      "appIdentifier": Bundle.main.bundleIdentifier ?? "",
      "providerAccount": info["ModlixApnsTeamId"] as? String ?? "",
      "apnsEnv": info["ModlixApnsEnv"] as? String ?? "sandbox",
    ])
  }

  override func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
    // No aps-environment entitlement (push off for this app) or no network.
    answerWaiting(["status": "unsupported"])
  }

  // The web app's in-app toast shows a notification that arrives in the foreground.
  override func userNotificationCenter(
    _ center: UNUserNotificationCenter,
    willPresent notification: UNNotification,
    withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
  ) {
    completionHandler([])
  }

  override func userNotificationCenter(
    _ center: UNUserNotificationCenter,
    didReceive response: UNNotificationResponse,
    withCompletionHandler completionHandler: @escaping () -> Void
  ) {
    if let u = AppDelegate.url(of: response.notification.request.content.userInfo) {
      if dartReady, let ch = channel { ch.invokeMethod("open", arguments: u) } else { initialUrl = u }
    }
    completionHandler()
  }
}
