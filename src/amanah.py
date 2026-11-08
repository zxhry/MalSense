"""
Content of the "Digital Amanah" page: Islamic reminders, Maqasid Syariah and practical digital-safety advice.
Kept here (not in the HTML) so it is easy to review and edit.

IMPORTANT: Quran verses use the Sahih International English translation; hadith references follow the
standard collections (Arba'in al-Nawawi numbers where available). Please have the texts and the Maqasid
mapping checked by a qualified lecturer before presenting them.
"""

# what "amanah" means here (short intro at the top of the page)
INTRO = ("Amanah means trust. Our phone, our data, our accounts and the people whose details we keep are all "
         "an amanah from Allah - something we will be asked about. Protecting them is part of being a "
         "responsible Muslim, not only a technical skill.")

# Islamic reminders - ONE per day of the week (Monday first). The page shows today's reminder,
# so the 7 reminders repeat every week. Keep exactly 7 items in this order.
REMINDERS = [
    # Monday
    {"kind": "Quran", "text": "Indeed, Allah commands you to render trusts to whom they are due.",
     "ref": "Surah an-Nisa' 4:58",
     "lesson": "Personal data that people share with us - contacts, photos, messages - is a trust. Do not "
               "install apps that leak it."},
    # Tuesday
    {"kind": "Quran", "text": "O you who have believed, if there comes to you a disobedient one with "
                              "information, investigate, lest you harm a people out of ignorance and become, "
                              "over what you have done, regretful.",
     "ref": "Surah al-Hujurat 49:6",
     "lesson": "Tabayyun: verify before you act. Check any message that asks you to install an APK or click "
               "a link - call the bank or sender through their official number."},
    # Wednesday
    {"kind": "Quran", "text": "And do not spy.",
     "ref": "Surah al-Hujurat 49:12",
     "lesson": "Spyware and stalkerware that secretly read messages or track location go against this "
               "command. Never install them on someone else's phone."},
    # Thursday
    {"kind": "Quran", "text": "And do not pursue that of which you have no knowledge. Indeed, the hearing, "
                              "the sight and the heart - about all those [one] will be questioned.",
     "ref": "Surah al-Isra' 17:36",
     "lesson": "Do not install or forward something you do not understand. Learn what an app does first - "
               "that is why MalSense explains every result."},
    # Friday
    {"kind": "Hadith", "text": "Leave that which makes you doubt for that which does not make you doubt.",
     "ref": "Narrated by al-Tirmidhi and al-Nasa'i (Arba'in al-Nawawi, no. 11)",
     "lesson": "If an app looks suspicious - unknown source, strange permissions, a MEDIUM or HIGH risk "
               "result - leave it and choose a trusted alternative."},
    # Saturday
    {"kind": "Hadith", "text": "There should be neither harming nor reciprocating harm.",
     "ref": "Narrated by Ibn Majah and al-Daraqutni (Arba'in al-Nawawi, no. 32)",
     "lesson": "Never create, share or forward malware, even as a joke. Harming others' devices or data is "
               "harm to people."},
    # Sunday
    {"kind": "Hadith", "text": "The Muslim is the one from whose tongue and hand the Muslims are safe.",
     "ref": "Narrated by al-Bukhari and Muslim",
     "lesson": "Online, our 'hand' is what we click, share and forward. Make sure nobody is harmed by what "
               "you send in group chats."},
]

# Maqasid Syariah: the five essentials (al-daruriyyat al-khams) applied to digital safety
MAQASID = [
    {"name": "Hifz al-Din", "meaning": "Protecting religion",
     "digital": "Religious apps (Quran, prayer times, zakat, qibla) are popular - so attackers copy them. "
                "Fake versions may carry malware or collect your data.",
     "do": "Download religious apps only from the official store or the developer's website, and check "
           "the permissions they ask for.",
     "perms": []},
    {"name": "Hifz al-Nafs", "meaning": "Protecting life and safety",
     "digital": "Apps that track your location in the background can expose where you live, study or travel "
                "- a real risk of stalking and physical harm.",
     "do": "Allow location only 'while using the app', and only for apps that truly need it (maps, ride-hailing).",
     "perms": ["ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION"]},
    {"name": "Hifz al-'Aql", "meaning": "Protecting the mind and sound judgement",
     "digital": "Scams work by causing panic or greed - 'your account will be blocked', 'you won a prize'. "
                "Adware and misleading content also cloud our judgement.",
     "do": "Pause before reacting. Practise tabayyun: verify the message from an official source first.",
     "perms": ["SYSTEM_ALERT_WINDOW"]},
    {"name": "Hifz al-Nasl", "meaning": "Protecting family, lineage and honour",
     "digital": "Contacts, family photos and private chats can be stolen and misused for blackmail or to "
                "scam your relatives in your name.",
     "do": "Do not give contact, photo, camera or microphone access to apps that do not need it. Help "
           "parents and children set up their phones safely.",
     "perms": ["READ_CONTACTS", "CAMERA", "RECORD_AUDIO", "READ_EXTERNAL_STORAGE"]},
    {"name": "Hifz al-Mal", "meaning": "Protecting wealth",
     "digital": "Banking malware reads SMS one-time passwords (OTP) and sends SMS in the background to empty "
                "bank and e-wallet accounts.",
     "do": "Never share your OTP or TAC with anyone - including someone who claims to be from the bank or police.",
     "perms": ["READ_SMS", "RECEIVE_SMS", "SEND_SMS"]},
]

# Practical digital-safety advice (checklist)
ADVICE = [
    ("Install from official stores only", "Avoid APK files sent through WhatsApp, Telegram or links. Banks, "
     "couriers and government agencies never ask you to install an APK."),
    ("Check permissions before you allow them", "Ask: does this app really need it? A torch app has no reason "
     "to read your SMS or contacts."),
    ("Scan doubtful APKs with MalSense first", "If you must use an APK, analyse it here before installing - "
     "and read the reasons, not only the verdict."),
    ("Protect your OTP, TAC and PIN", "No real officer or bank staff will ever ask for them. Sharing them "
     "gives away your money."),
    ("Keep Android and apps updated", "Updates close security holes that malware uses. Turn on Google Play "
     "Protect."),
    ("Use a screen lock and two-factor authentication", "Protect your phone with a PIN or fingerprint, and "
     "turn on 2FA for email, social media and banking."),
    ("Back up what matters", "Keep a backup of photos and documents, so ransomware or a lost phone does not "
     "take everything."),
    ("Act fast if you were scammed", "Call your bank immediately, then the National Scam Response Centre (NSRC) "
     "at 997. Report cyber incidents to CyberSecurity Malaysia's Cyber999."),
]
