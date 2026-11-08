"""
Content of the Mobile Security Checklist page (linked from the home page).
Six groups of good security habits for Android users.
Adapted (rewritten, not copied) from the "Mobile Security Checklist" poster by Sandbox Security
(https://sandboxsecurity.ai) - the page credits them at the top and bottom. Edit the text here - the page layout is in
templates/checklist.html. Each item: (short title, explanation).
"""

SECTIONS = [
    {"title": "Keep Up To Date", "icon": "update", "items": [
        ("Update Android", "Turn on automatic system updates. Each update fixes security holes that malware "
                           "can use to take over your phone."),
        ("Update your apps", "Turn on automatic app updates in the Play Store. Old app versions often have "
                             "known weaknesses that attackers already know how to exploit."),
    ]},
    {"title": "Use Strong Authentication", "icon": "lock", "items": [
        ("Lock your phone", "Use a strong PIN or password together with your fingerprint or face unlock, so "
                            "nobody can open your phone if it is lost or borrowed."),
        ("Turn on two-factor authentication (2FA)", "Enable 2FA for email, social media and banking. Even if "
                            "someone steals your password, they still cannot log in without the second code."),
    ]},
    {"title": "Practise Good App Security", "icon": "apps", "items": [
        ("Install from official stores only", "Use Google Play. Keep 'Install unknown apps' switched off, and "
                            "never install APK files sent through WhatsApp, Telegram or SMS links."),
        ("Scan doubtful APKs first", "If you really must use an APK file, analyse it with MalSense before "
                            "installing - and read why it got its verdict."),
        ("Delete apps you no longer use", "Every app is a possible way in. Review your apps regularly and "
                            "uninstall the ones you do not need."),
        ("Share as little personal data as possible", "Only give apps the personal details they really need "
                            "- no extra phone numbers, IC numbers or addresses."),
        ("Grant only the permissions an app needs", "Check Settings > Apps > Permissions. A torch or game app "
                            "has no reason to read your SMS, contacts or call log."),
        ("Allow location only while using the app", "Choose 'Only while using the app' instead of 'Allow all "
                            "the time', so your location cannot be tracked in the background."),
    ]},
    {"title": "Protect Network Connections", "icon": "wifi", "items": [
        ("Switch off what you are not using", "Turn off Bluetooth, NFC, Wi-Fi and GPS when you do not need "
                            "them. Every open connection is another possible point of attack."),
        ("Be careful with public Wi-Fi", "Free Wi-Fi in cafes, malls and airports can be watched by attackers. "
                            "Avoid banking on it, or use mobile data or a trusted VPN."),
    ]},
    {"title": "Protect The Device", "icon": "shield", "items": [
        ("Keep Google Play Protect on", "Play Protect scans your apps for harmful behaviour. Check that it is "
                            "switched on in the Play Store settings."),
        ("Use trusted chargers and cables", "Public USB charging points and unknown cables can be used to "
                            "steal data or install malware ('juice jacking'). Use your own charger."),
        ("Turn on Find My Device", "If your phone is lost or stolen, you can locate it, lock it, or erase all "
                            "your data remotely so nobody can misuse it."),
    ]},
    {"title": "Beware Of Phishing And Scams", "icon": "phish", "items": [
        ("Verify before you click", "Be careful with SMS, WhatsApp messages and emails that create panic or "
                            "promise prizes. Contact the bank or sender through their official number first. "
                            "Never share your OTP or TAC with anyone."),
    ]},
]
