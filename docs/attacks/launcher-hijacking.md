# Launcher Hijacking

Replacing the device's home screen with a malicious launcher that traps the user in a controlled environment. The malware registers as a HOME intent handler and actively prevents the user from reverting to the original launcher by killing Settings apps and blocking navigation.

## HOME Intent Registration

The malware declares an Activity with `CATEGORY_HOME` and `CATEGORY_DEFAULT` intent filters, making it eligible as a home screen replacement:

```xml
<activity android:exported="true" android:launchMode="singleTask"
    android:name=".MaliciousLauncherActivity"
    android:stateNotNeeded="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.HOME"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>
```

When the user presses the Home button with multiple launcher-capable apps installed, Android shows a chooser dialog. The malware's onboarding flow socially engineers the user into selecting it as the default.

`android:stateNotNeeded="true"` tells the system this activity can be restarted without saved state. This is the standard declaration for HOME activities -- it prevents the system from permanently removing the task after a crash, since the activity can always restart cleanly.

## Deceptive Onboarding

The typical onboarding chain forces the user through a sequence that ends with setting the malicious app as the default launcher:

```
FakeProgressActivity (animated "cleaning" or "optimizing" screen, 10-15 seconds)
  → WelcomeActivity (single-button "Get Started" intro)
  → SetupGuideActivity (forces user to set app as default launcher)
  → MaliciousLauncherActivity (user is trapped)
```

The setup guide activity gates all app features behind the launcher-is-default check. The fake progress animation creates urgency and primes the user to tap through subsequent screens quickly.

## Settings App Killing

Once set as default, the malware actively prevents the user from changing back by killing Settings apps. Two primary mechanisms are used:

### killBackgroundProcesses (Pre-Android 14)

```java
String[] settingsPackages = {
    "com.android.settings", "com.samsung.android.settings",
    "com.miui.securitycenter", "com.huawei.systemmanager",
    "com.oppo.settings", "com.vivo.settings",
    "com.google.android.permissioncontroller"
};
ActivityManager am = getSystemService(ActivityManager.class);
for (String pkg : settingsPackages) {
    am.killBackgroundProcesses(pkg);
}
```

`killBackgroundProcesses()` requires only [`KILL_BACKGROUND_PROCESSES`](../permissions/normal/receive-boot-completed.md), a normal permission (auto-granted). It kills the target app's background processes, disrupting any Settings session the user has open.

!!! warning "Android 14+ Restriction"

    Starting with [Android 14](https://developer.android.com/about/versions/14/behavior-changes-all), `killBackgroundProcesses()` can only kill the calling app's own background processes. Passing another app's package name has no effect. This restriction applies to all apps regardless of `targetSdkVersion`.

### Reflective removeTask

The hidden API `ActivityManager.removeTask(int taskId)` can remove arbitrary tasks by ID. The malware discovers Settings task IDs via `ActivityManager.getRunningTasks()` (deprecated but still functional) and removes them via reflection:

```java
Method removeTask = ActivityManager.class.getDeclaredMethod("removeTask", int.class);
removeTask.setAccessible(true);
removeTask.invoke(activityManager, settingsTaskId);
```

This requires the `REMOVE_TASKS` permission (signature-level on modern Android), so it may only succeed on older devices or with [hidden API bypass](anti-analysis-techniques.md#hidden-api-bypass) techniques. On newer Android versions, this approach is increasingly blocked by hidden API restrictions.

The kill list covers all major OEM Settings packages:

| Package | OEM |
|---------|-----|
| `com.android.settings` | AOSP / Pixel |
| `com.samsung.android.settings` | Samsung |
| `com.miui.securitycenter` | Xiaomi |
| `com.huawei.systemmanager` | Huawei |
| `com.oppo.settings` | OPPO |
| `com.vivo.settings` | Vivo |
| `com.google.android.permissioncontroller` | Google (permission manager) |

The check runs every time the malicious launcher resumes (i.e., every Home press), ensuring the user cannot stay in Settings long enough to change the default launcher or navigate to the uninstall screen.

## Navigation Trapping

The malicious launcher restricts user navigation to a small number of controlled states:

- **Swipe left**: shows ads, subscription paywall, or monetization content
- **Swipe right**: returns to home
- **Home button**: always returns to the malicious launcher (it is the default)
- **Back button**: trapped within the launcher's activity stack
- **Recents**: HOME tasks do not appear in the recents screen (see below)

The gesture detector limits the user to two states: home screen and ads/paywall. There is no path to the app drawer, other apps, or system settings without going through the launcher's controlled flow.

## HOME Task Behavior

Activities registered with `CATEGORY_HOME` receive special treatment from the Android activity manager. In AOSP, `RecentTasks.isVisibleRecentTask()` returns `false` for `ACTIVITY_TYPE_HOME`, meaning home tasks are excluded from the recents screen entirely. They do not appear as cards in the overview, cannot be swiped away, and are unaffected by "Clear All."

This means the malicious launcher cannot be removed from the recents screen. The user's only options are:

- Changing the default launcher in Settings (which the malware tries to prevent)
- Force-stopping the app via Settings > Apps (which the malware also tries to prevent)
- Using ADB (`adb shell pm clear <package>` or `adb shell am force-stop <package>`)

## Feature Gating

A checkpoint activity gates all app functionality behind a set of prerequisites:

| Prerequisite | Purpose |
|-------------|---------|
| App is default launcher | Ensures the trap is active |
| Storage permission granted | Filesystem access for data collection |
| Usage stats permission granted | Monitors which apps the user runs |

If any prerequisite is not met, the user is redirected back to the setup flow. This creates a persistent pressure to maintain the malicious configuration.

## Detection

- `CATEGORY_HOME` + `CATEGORY_DEFAULT` in intent filters for non-launcher apps
- `killBackgroundProcesses()` calls targeting Settings packages
- Reflection calls to hidden `ActivityManager` methods (`removeTask`, `getRunningTasks`)
- `android:stateNotNeeded="true"` on HOME activities in non-launcher utility apps

## Platform Lifecycle

| Android Version | API | Change | Impact |
|----------------|-----|--------|--------|
| 5.0 | 21 | `getRunningTasks()` deprecated, limited to own tasks | Harder to discover Settings task IDs |
| 9 | 28 | Hidden API restrictions introduced | Reflection to `removeTask()` may be blocked |
| 10 | 29 | Background activity start restrictions | Launcher must be foreground to interact with tasks |
| 14 | 34 | [`killBackgroundProcesses()` restricted to own app](https://developer.android.com/about/versions/14/behavior-changes-all) | Cannot kill Settings processes; primary kill mechanism neutered |
