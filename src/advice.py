"""
Security advice shown on the results page after an APK is analysed (security-awareness goal of MalSense).

advice_for(r) returns:
  {"now":       steps to take before installing,
   "installed": steps if the app is ALREADY on the phone (empty for LOW risk),
   "perms":     extra tips for the risky permissions THIS app asks for (max 5)}

Advice follows common mobile-security guidance (Google Play Protect help, OWASP Mobile Top 10,
CyberSecurity Malaysia / MyCERT public advisories). Edit the text here - the page updates itself.
"""

RISK_ADVICE = {
    "HIGH": {
        "now": [
            ("Do not install this app.", "It was flagged as malware, so installing it could put your data and money at risk."),
            ("Delete the APK file.", "Remove it from your Downloads folder and any chat (e.g. WhatsApp, Telegram) where you received it."),
            ("Warn the sender.", "If someone sent you this file, tell them it is malware - their phone may already be infected."),
        ],
        "installed": [
            ("Disconnect from the internet.", "Turn on airplane mode so the app cannot send your data out while you clean up."),
            ("Uninstall it.", "Settings > Apps > find the app > Uninstall. If Uninstall is greyed out, first remove it from "
                              "Settings > Security > Device admin apps (the exact menu name may differ on your phone; "
                              "search 'device admin' in Settings)."),
            ("Run Google Play Protect.", "Play Store > your profile picture > Play Protect > Scan."),
            ("Change your passwords.", "Use another, trusted device to change your email, banking and social media passwords, "
                                       "and turn on two-factor authentication."),
            ("Watch your bank and SMS.", "Check for transactions or messages you did not make. If you see any, call your bank "
                                         "straight away and report it to the NSRC hotline 997."),
        ],
    },
    "MEDIUM": {
        "now": [
            ("Install only from a trusted source.", "Prefer the Google Play Store or the developer's official website over APK files shared online."),
            ("Check the developer.", "Search the app and developer name - look for reviews, an official website and complaints about scams."),
            ("Refuse permissions it does not need.", "When Android asks, tap \"Don't allow\" for anything unrelated to what the app is for."),
            ("Scan again later.", "Antivirus engines learn about new malware every day - a second check in a few days may give a clearer answer."),
        ],
        "installed": [
            ("Review its permissions.", "Settings > Apps > this app > Permissions - switch off anything it does not need."),
            ("Run Google Play Protect.", "Play Store > your profile picture > Play Protect > Scan."),
            ("Uninstall it if anything looks odd.", "Unexpected pop-up ads, battery drain, high data use or messages you did not send are warning signs."),
        ],
    },
    "LOW": {
        "now": [
            ("Still check the permissions.", "No threat was found, but only allow the permissions the app really needs."),
            ("Turn off \"Install unknown apps\" afterwards.", "Settings > Apps > Special app access > Install unknown apps - switch it off for "
                                                             "the browser or chat app you used, so nothing else installs silently."),
            ("Keep it updated.", "Updates fix security holes - install them from the same trusted source."),
        ],
        "installed": [],
    },
}

# Extra tips for risky permissions. Several permissions can share one tip (key = tuple).
PERMISSION_ADVICE = [
    (("SEND_SMS", "RECEIVE_SMS", "READ_SMS", "WRITE_SMS"),
     "SMS access", "It can read your one-time passwords (OTP) and send paid SMS. Never share OTPs, and check your phone bill for unknown SMS charges."),
    (("CALL_PHONE", "PROCESS_OUTGOING_CALLS", "ANSWER_PHONE_CALLS", "READ_CALL_LOG", "WRITE_CALL_LOG"),
     "Calls", "It can make or redirect calls and read your call history. Watch for calls you did not make on your bill."),
    (("READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS"),
     "Contacts & accounts", "It can copy your contacts and see your accounts. Scammers use this to message your friends pretending to be you."),
    (("ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION"),
     "Location", "It can track where you are. Set location to \"Only while using the app\", or deny it."),
    (("CAMERA", "RECORD_AUDIO"),
     "Camera & microphone", "It can take photos or record sound. Android shows a green dot at the top of the screen while they are in use - watch for it."),
    (("READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE"),
     "Files & photos", "It can read or change your files and photos. Do not keep IC/passport scans or bank statements in shared storage."),
    (("SYSTEM_ALERT_WINDOW",),
     "Draw over other apps", "It can show fake login screens on top of your banking apps. Always check you are in the real app before typing a password."),
    (("BIND_ACCESSIBILITY_SERVICE",),
     "Accessibility", "It can read everything on screen and tap for you - a favourite trick of banking malware. Only allow this for apps you fully trust."),
    (("BIND_DEVICE_ADMIN",),
     "Device admin", "Device admin apps are hard to uninstall. Remove it in Settings > Security > Device admin apps first (the exact menu name may differ on your phone; search 'device admin' in Settings)."),
    (("REQUEST_INSTALL_PACKAGES", "DELETE_PACKAGES"),
     "Installing apps", "It can install or remove other apps. Keep \"Install unknown apps\" switched off for it."),
    (("READ_PHONE_STATE", "READ_PHONE_NUMBERS"),
     "Phone identity", "It can read your phone number and device ID, which can be used to track you or for SIM-related fraud."),
    (("RECEIVE_BOOT_COMPLETED",),
     "Starts by itself", "It runs automatically when the phone is switched on. If you uninstall it, restart the phone afterwards."),
]


def advice_for(r):
    """r = the scan result shown on the page (needs 'risk', and 'permissions' / 'dangerous_permissions')."""
    risk = r.get("risk", "LOW")
    base = RISK_ADVICE.get(risk, RISK_ADVICE["LOW"])
    asked = set(r.get("permissions") or []) | set(r.get("dangerous_permissions") or [])
    perms = []
    for names, title, tip in PERMISSION_ADVICE:
        found = [n for n in names if n in asked]
        if found:
            perms.append({"title": title, "tip": tip, "perms": found})
    return {"now": base["now"], "installed": base["installed"], "perms": perms[:5]}
