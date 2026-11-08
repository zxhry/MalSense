"""
Explainable AI (XAI) for MalSense.
For ONE scanned app, shows which features pushed the XGBoost decision towards
"malware" or towards "safe". Uses XGBoost's built-in SHAP values (pred_contribs=True):
each feature gets a score; all scores + a base value add up to the model's output (log-odds).
  positive score -> pushed towards MALWARE      negative score -> pushed towards SAFE
"""
import numpy as np
import pandas as pd
import xgboost as xgb

# Plain-language meaning of the permissions that matter most (Android developer documentation)
PERMISSION_TEXT = {
    "READ_PHONE_STATE": "read your phone number, IMEI and call status",
    "SEND_SMS": "send SMS messages (can cost money or sign you up to paid services)",
    "RECEIVE_SMS": "read incoming SMS, including one-time passwords (OTP)",
    "READ_SMS": "read all your text messages, including OTPs",
    "WRITE_SMS": "write or delete your text messages",
    "RECEIVE_MMS": "receive multimedia messages",
    "CALL_PHONE": "make phone calls without you dialling",
    "READ_CALL_LOG": "read your call history",
    "WRITE_CALL_LOG": "change your call history",
    "PROCESS_OUTGOING_CALLS": "see and redirect calls you make",
    "READ_CONTACTS": "read your contacts",
    "WRITE_CONTACTS": "change your contacts",
    "GET_ACCOUNTS": "see the accounts (e.g. Google) on your phone",
    "ACCESS_FINE_LOCATION": "know your exact GPS location",
    "ACCESS_COARSE_LOCATION": "know your approximate location",
    "ACCESS_BACKGROUND_LOCATION": "track your location even when the app is closed",
    "CAMERA": "use the camera",
    "RECORD_AUDIO": "record audio with the microphone",
    "READ_EXTERNAL_STORAGE": "read files and photos on your storage",
    "WRITE_EXTERNAL_STORAGE": "change or delete files on your storage",
    "MANAGE_EXTERNAL_STORAGE": "access all files on your storage",
    "SYSTEM_ALERT_WINDOW": "draw over other apps (used for fake login screens and pop-up ads)",
    "RECEIVE_BOOT_COMPLETED": "start automatically when the phone is switched on",
    "KILL_BACKGROUND_PROCESSES": "close other apps running in the background",
    "GET_TASKS": "see which other apps you are using",
    "STATUS_BAR": "control the notification/status bar",
    "EXPAND_STATUS_BAR": "pull down the notification bar",
    "INSTALL_SHORTCUT": "add icons to your home screen",
    "REQUEST_INSTALL_PACKAGES": "install other apps",
    "DELETE_PACKAGES": "uninstall apps",
    "MOUNT_UNMOUNT_FILESYSTEMS": "mount or unmount storage",
    "CHANGE_WIFI_STATE": "turn Wi-Fi on/off and change Wi-Fi settings",
    "ACCESS_WIFI_STATE": "see Wi-Fi network information",
    "ACCESS_NETWORK_STATE": "see whether you are online",
    "INTERNET": "use the internet",
    "WAKE_LOCK": "keep the phone awake",
    "VIBRATE": "make the phone vibrate",
    "DISABLE_KEYGUARD": "turn off the screen lock",
    "WRITE_SETTINGS": "change system settings",
    "BIND_DEVICE_ADMIN": "become a device administrator (hard to uninstall)",
    "BIND_ACCESSIBILITY_SERVICE": "read everything on screen and act for you",
    "FOREGROUND_SERVICE": "keep running as a foreground service",
    "BLUETOOTH": "connect to Bluetooth devices",
    "BLUETOOTH_ADMIN": "change Bluetooth settings",
    "READ_PHONE_NUMBERS": "read your phone number",
    "ANSWER_PHONE_CALLS": "answer phone calls",
    "USE_FINGERPRINT": "use the fingerprint sensor",
    "BIND_CHOOSER_TARGET_SERVICE": "appear in the share menu",
}

COUNT_TEXT = {
    "nr_permissions": "Number of standard permissions requested",
    "normal": "Number of 'normal' (low-risk) permissions",
    "dangerous": "Number of 'dangerous' permissions",
    "signature": "Number of 'signature' (system-level) permissions",
    "nr_custom": "Number of custom (non-Android) permissions",
    "custom_yes": "Declares custom permissions",
    "total_perm": "Total number of permissions",
    "CFileSize": "APK file size",
    "UFileSize": "Uncompressed app size",
    "FilesInsideAPK": "Number of files inside the APK",
    "Activities": "Number of screens (activities)",
    "NrServices": "Number of background services",
}


def _describe(name, value):
    if value != value:                                     # NaN = value missing in the dataset
        return COUNT_TEXT.get(name, name), "unknown", None
    if name in COUNT_TEXT:
        if name in ("CFileSize", "UFileSize"):
            shown = f"{value / 1048576:.1f} MB"
        elif name == "custom_yes":
            shown = "yes" if value else "no"
        else:
            shown = f"{int(value)}"
        return COUNT_TEXT[name], shown, None
    meaning = PERMISSION_TEXT.get(name)
    if value:
        return f"Requests {name}", "yes", meaning
    return f"Does not request {name}", "no", meaning


def explain(bundle, features, top=6):
    """features = the raw feature dict from extract_features(). Returns a list of reasons."""
    names = bundle["features"]
    raw_df = pd.DataFrame([[features[n] for n in names]], columns=names, dtype=float)
    raw = raw_df.to_numpy()
    X = bundle["preprocess"].transform(raw_df)
    contrib = bundle["model"].get_booster().predict(xgb.DMatrix(X), pred_contribs=True)[0]
    scores = contrib[:-1]                                   # last value is the base (bias)
    order = np.argsort(-np.abs(scores))[:top]
    biggest = max(abs(scores[order[0]]), 1e-9)
    reasons = []
    for i in order:
        if abs(scores[i]) < 0.01:                          # ignore features with ~no effect
            continue
        label, shown, meaning = _describe(names[i], raw[0, i])
        reasons.append({"feature": names[i], "label": label, "value": shown, "meaning": meaning,
                        "score": round(float(scores[i]), 3),
                        "direction": "malware" if scores[i] > 0 else "safe",
                        "width": int(round(100 * abs(scores[i]) / biggest))})
    return reasons