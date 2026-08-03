#!/usr/bin/env python3
"""
Cloudora incident CLD-0001 - synthetic log generator.

Produces two CSV files that mirror Microsoft Entra ID sign-in and audit log
schemas as they land in a Log Analytics / Azure Data Explorer custom table:

    cloudora_signin_logs.csv  -> CloudoraSignIn_CL
    cloudora_audit_logs.csv   -> CloudoraAudit_CL

Scenario: 8 days of activity for Cloudora, a 150-person B2B HR software company
in London. On the final day an attacker password-sprays the tenant from Lagos,
Nigeria, lands a successful sign-in on the CEO's account at 03:12 UTC, registers
a new MFA method, consents a rogue OAuth application, and pivots to two more
accounts. The IT admin notices at 08:55.

Deterministic: fixed RNG seed, so re-running reproduces the identical dataset.
"""

import csv
import random
import uuid
from datetime import datetime, timedelta

SEED = 20260802
random.seed(SEED)

# ---------------------------------------------------------------------------
# Time window: 2026-07-26 00:00 UTC through 2026-08-02 12:00 UTC
# ---------------------------------------------------------------------------
START = datetime(2026, 7, 26, 0, 0, 0)
INCIDENT_DAY = datetime(2026, 8, 2)
END = datetime(2026, 8, 2, 12, 0, 0)

TENANT = "cloudora.io"

# ---------------------------------------------------------------------------
# Population
# ---------------------------------------------------------------------------
FIRST = ["James", "Olivia", "Harry", "Amelia", "Oliver", "Isla", "Jack", "Ava",
         "Charlie", "Mia", "Thomas", "Grace", "George", "Freya", "Noah", "Ruby",
         "Leo", "Ella", "Arthur", "Poppy", "Rory", "Nadia", "Kwame", "Aisha",
         "Ben", "Chloe", "Daniel", "Erin", "Femi", "Hannah", "Ibrahim", "Jasmine",
         "Kieran", "Lucy", "Marcus", "Nina", "Owen", "Priya", "Quinn", "Rachel",
         "Sam", "Tara", "Umar", "Verity", "Will", "Yasmin", "Zach", "Bethan",
         "Callum", "Dara", "Eoin", "Fiona", "Gareth", "Heidi", "Ivan", "Jonas"]
LAST = ["Whitfield", "Barlow", "Hughes", "Okafor", "Sinclair", "Rahman", "Bennett",
        "Kaur", "Doyle", "Ferguson", "Ncube", "Patel", "Riley", "Novak", "Alvarez",
        "Sharma", "Bright", "Coleman", "Dunn", "Elliot", "Fraser", "Gill",
        "Hartley", "Iqbal", "Jennings", "Kelly", "Lowe", "Mensah", "Nolan",
        "Osborne", "Pryce", "Quinlan", "Reid", "Stone", "Trent", "Upton",
        "Vaughan", "Wren", "Yates", "Zielinski"]

# Named cast the investigation revolves around
CAST = [
    # upn, display, dept, role_tag
    ("daniel.reeve",   "Daniel Reeve",    "Executive",  "ceo"),
    ("priya.nair",     "Priya Nair",      "Finance",    "finance"),
    ("tom.ashworth",   "Tom Ashworth",    "Executive",  "exec_assistant"),
    ("marcus.webb",    "Marcus Webb",     "IT",         "it_admin"),
    ("sarvesh.iyer",   "Sarvesh Iyer",    "Security",   "vciso"),
    ("helena.crosby",  "Helena Crosby",   "Executive",  "cfo"),
    ("adam.fenwick",   "Adam Fenwick",    "Executive",  "coo"),
    ("sophie.laurent", "Sophie Laurent",  "Sales",      "traveller"),
    ("nathan.obi",     "Nathan Obi",      "Engineering","night_shift"),
    ("clara.mendez",   "Clara Mendez",    "Legal",      "staff"),
]


def build_users():
    users, seen = [], set()
    for upn, disp, dept, tag in CAST:
        users.append({"upn": f"{upn}@{TENANT}", "display": disp, "dept": dept,
                      "tag": tag, "uid": str(uuid.UUID(int=random.getrandbits(128)))})
        seen.add(upn)
    depts = ["Engineering", "Sales", "Marketing", "Finance", "HR",
             "Customer Success", "Product", "Legal", "IT"]
    while len(users) < 150:
        f, l = random.choice(FIRST), random.choice(LAST)
        upn = f"{f.lower()}.{l.lower()}"
        if upn in seen:
            continue
        seen.add(upn)
        users.append({"upn": f"{upn}@{TENANT}", "display": f"{f} {l}",
                      "dept": random.choice(depts), "tag": "staff",
                      "uid": str(uuid.UUID(int=random.getrandbits(128)))})
    return users


USERS = build_users()
BY_UPN = {u["upn"]: u for u in USERS}

# ---------------------------------------------------------------------------
# Network / geo profiles
# ---------------------------------------------------------------------------
BENIGN_NETWORKS = [
    # (ip_prefix, country, city, state, asn, isp, weight)
    ("81.134.22.",  "GB", "London",     "England",          2856,  "British Telecommunications", 46),
    ("86.15.108.",  "GB", "London",     "England",          5089,  "Virgin Media",               18),
    ("51.148.63.",  "GB", "Manchester", "England",          2856,  "British Telecommunications",  9),
    ("92.40.176.",  "GB", "Bristol",    "England",          5378,  "Vodafone UK",                 7),
    ("31.94.12.",   "GB", "Leeds",      "England",          20712, "Three UK",                    5),
    ("109.157.44.", "GB", "Edinburgh",  "Scotland",         2856,  "British Telecommunications",  4),
    ("87.44.201.",  "IE", "Dublin",     "Leinster",         5466,  "Eir",                         3),
]

# Corporate office egress - the single most common source
OFFICE_IP = "81.134.22.14"

# Attacker infrastructure
ATTACK_IP = "102.89.44.117"
ATTACK_GEO = ("NG", "Lagos", "Lagos", 29465, "MTN Nigeria Communications")
ROTATE_IP = "45.144.212.88"
ROTATE_GEO = ("NL", "Amsterdam", "North Holland", 202015, "HostSlick Datacenter")

APPS = [
    ("Office 365 Exchange Online", 30),
    ("Microsoft Teams", 22),
    ("OfficeHome", 16),
    ("SharePoint Online", 12),
    ("Microsoft 365 Admin Portal", 4),
    ("Azure Portal", 4),
    ("Cloudora HR Portal", 8),
    ("Salesforce", 4),
]

DEVICES = [
    ("Windows 10", "Edge 126.0.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/126.0.0", 34),
    ("Windows 11", "Edge 126.0.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/126.0.0", 26),
    ("Windows 11", "Chrome 127.0.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/127.0.0", 12),
    ("MacOs", "Safari 17.5", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.5", 10),
    ("Ios 17.5.1", "Mobile Safari", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1) Mobile/15E148", 12),
    ("Android 14", "Chrome Mobile 127", "Mozilla/5.0 (Linux; Android 14) Chrome/127.0.0 Mobile", 6),
]

COUNTRY_NAMES = {
    "GB": "United Kingdom",
    "NG": "Nigeria",
    "IE": "Ireland",
    "FR": "France",
    "NL": "Netherlands",
}

RESULTS = {
    "0":     "",
    "50126": "Error validating credentials due to invalid username or password.",
    "50074": "Strong Authentication is required.",
    "50076": "Due to a configuration change made by your administrator, or because you moved to a new location, you must use multi-factor authentication to access the resource.",
    "50158": "External security challenge was not satisfied.",
    "53003": "Access has been blocked by Conditional Access policies.",
    "50053": "Account is locked because the user tried to sign in too many times with an incorrect user ID or password.",
    "50140": "Interrupt - keep me signed in.",
}

SIGNIN_FIELDS = [
    "TimeGenerated", "Id", "CorrelationId", "UserPrincipalName", "UserDisplayName",
    "UserId", "AppDisplayName", "ClientAppUsed", "IPAddress", "Location", "Country",
    "City", "State", "AutonomousSystemNumber", "NetworkISP", "DeviceOS", "DeviceBrowser",
    "UserAgent", "ResultType", "ResultDescription", "ConditionalAccessStatus",
    "AuthenticationRequirement", "MfaAuthMethod", "RiskLevelDuringSignIn",
    "RiskState", "RiskEventTypes",
]

AUDIT_FIELDS = [
    "TimeGenerated", "Id", "CorrelationId", "Category", "OperationName", "Result",
    "ResultReason", "InitiatedByUser", "InitiatedByIpAddress", "InitiatedByApp",
    "TargetResourceName", "TargetResourceType", "TargetUserPrincipalName",
    "ModifiedProperty", "OldValue", "NewValue",
]

signin_rows, audit_rows = [], []


def wpick(items):
    """items: list of tuples ending in an integer weight."""
    total = sum(i[-1] for i in items)
    r = random.uniform(0, total)
    acc = 0
    for it in items:
        acc += it[-1]
        if r <= acc:
            return it
    return items[-1]


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def add_signin(dt, user, app, ip, geo, device, result="0", ca="notApplied",
               authreq="singleFactorAuthentication", mfa="", risk="none",
               riskstate="none", riskevents="", client="Browser", corr=None):
    country, city, state, asn, isp = geo
    signin_rows.append({
        "TimeGenerated": ts(dt),
        "Id": str(uuid.UUID(int=random.getrandbits(128))),
        "CorrelationId": corr or str(uuid.UUID(int=random.getrandbits(128))),
        "UserPrincipalName": user["upn"],
        "UserDisplayName": user["display"],
        "UserId": user["uid"],
        "AppDisplayName": app,
        "ClientAppUsed": client,
        "IPAddress": ip,
        "Location": country,
        "Country": COUNTRY_NAMES.get(country, country),
        "City": city,
        "State": state,
        "AutonomousSystemNumber": asn,
        "NetworkISP": isp,
        "DeviceOS": device[0],
        "DeviceBrowser": device[1],
        "UserAgent": device[2],
        "ResultType": result,
        "ResultDescription": RESULTS.get(result, ""),
        "ConditionalAccessStatus": ca,
        "AuthenticationRequirement": authreq,
        "MfaAuthMethod": mfa,
        "RiskLevelDuringSignIn": risk,
        "RiskState": riskstate,
        "RiskEventTypes": riskevents,
    })


def add_audit(dt, category, op, result, actor, actor_ip, target_name,
              target_type, target_upn="", prop="", old="", new="",
              app="", reason="", corr=None):
    audit_rows.append({
        "TimeGenerated": ts(dt),
        "Id": str(uuid.UUID(int=random.getrandbits(128))),
        "CorrelationId": corr or str(uuid.UUID(int=random.getrandbits(128))),
        "Category": category,
        "OperationName": op,
        "Result": result,
        "ResultReason": reason,
        "InitiatedByUser": actor,
        "InitiatedByIpAddress": actor_ip,
        "InitiatedByApp": app,
        "TargetResourceName": target_name,
        "TargetResourceType": target_type,
        "TargetUserPrincipalName": target_upn,
        "ModifiedProperty": prop,
        "OldValue": old,
        "NewValue": new,
    })


def home_network(user):
    """Stable per-user home network so each identity has a consistent baseline."""
    rnd = random.Random(user["upn"])
    net = rnd.choices(BENIGN_NETWORKS, weights=[n[-1] for n in BENIGN_NETWORKS])[0]
    prefix, country, city, state, asn, isp = net[:6]
    ip = prefix + str(rnd.randint(3, 250))
    return ip, (country, city, state, asn, isp)


def home_device(user):
    rnd = random.Random(user["upn"] + "dev")
    return rnd.choices(DEVICES, weights=[d[-1] for d in DEVICES])[0][:3]


# ---------------------------------------------------------------------------
# Baseline traffic
# ---------------------------------------------------------------------------
def business_hour():
    """Weighted toward the UK working day, with a small out-of-hours tail."""
    buckets = [(7, 3), (8, 9), (9, 14), (10, 13), (11, 12), (12, 8), (13, 9),
               (14, 12), (15, 12), (16, 11), (17, 8), (18, 5), (19, 3),
               (20, 2), (21, 2), (22, 1), (6, 2), (23, 1)]
    return wpick([(h, w) for h, w in buckets])[0]


def generate_baseline():
    day = START
    while day < END:
        weekend = day.weekday() >= 5
        # Partial final day: baseline only runs to midday
        if day.date() == END.date():
            volume = 22
        elif weekend:
            volume = random.randint(14, 22)
        else:
            volume = random.randint(250, 280)

        for _ in range(volume):
            # Users with dedicated profiles below are excluded so their
            # baselines stay clean and the anomalies remain meaningful.
            user = random.choice(USERS)
            while user["tag"] in ("ceo", "traveller", "night_shift"):
                user = random.choice(USERS)
            hour = business_hour()
            if day.date() == END.date() and hour > 11:
                hour = random.randint(7, 11)
            dt = day.replace(hour=hour, minute=random.randint(0, 59),
                             second=random.randint(0, 59),
                             microsecond=random.randint(0, 999) * 1000)
            if dt >= END:
                continue

            ip, geo = home_network(user)
            # Most staff sign in from the office egress during the day
            if not weekend and 8 <= hour <= 18 and random.random() < 0.42:
                ip, geo = OFFICE_IP, ("GB", "London", "England", 2856,
                                      "British Telecommunications")
            device = home_device(user)
            app = wpick(APPS)[0]

            roll = random.random()
            if roll < 0.055:
                res, ca, authreq, mfa = "50126", "notApplied", "singleFactorAuthentication", ""
            elif roll < 0.085:
                res, ca, authreq, mfa = "50074", "success", "multiFactorAuthentication", ""
            elif roll < 0.10:
                res, ca, authreq, mfa = "50140", "success", "multiFactorAuthentication", "PhoneAppNotification"
            elif roll < 0.11:
                res, ca, authreq, mfa = "53003", "failure", "multiFactorAuthentication", ""
            else:
                res, ca = "0", "success"
                if random.random() < 0.55:
                    authreq, mfa = "multiFactorAuthentication", random.choice(
                        ["PhoneAppNotification", "PhoneAppOTP", "Fido"])
                else:
                    authreq, mfa = "singleFactorAuthentication", ""

            add_signin(dt, user, app, ip, geo, device, result=res, ca=ca,
                       authreq=authreq, mfa=mfa,
                       client="Mobile Apps and Desktop clients"
                       if device[0].startswith(("Ios", "Android")) and random.random() < 0.6
                       else "Browser")
        day += timedelta(days=1)


def generate_ceo_baseline():
    """Daniel Reeve's clean pattern - the profile the 03:12 event breaks."""
    ceo = BY_UPN[f"daniel.reeve@{TENANT}"]
    laptop = ("Windows 11", "Edge 126.0.0",
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/126.0.0")
    phone = ("Ios 17.5.1", "Mobile Safari",
             "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1) Mobile/15E148")
    home_ip = "86.15.108.77"
    london = ("GB", "London", "England", 5089, "Virgin Media")
    office = ("GB", "London", "England", 2856, "British Telecommunications")

    day = START
    while day.date() <= datetime(2026, 8, 1).date():
        for hour in ([8, 9, 11, 14, 16, 19, 22] if day.weekday() < 5 else [10, 20]):
            dt = day.replace(hour=hour, minute=random.randint(0, 59),
                             second=random.randint(0, 59),
                             microsecond=random.randint(0, 999) * 1000)
            mobile = hour in (8, 19, 22) or random.random() < 0.3
            add_signin(dt, ceo, wpick(APPS)[0],
                       home_ip if mobile else OFFICE_IP,
                       london if mobile else office,
                       phone if mobile else laptop,
                       result="0", ca="success",
                       authreq="multiFactorAuthentication",
                       mfa="PhoneAppNotification",
                       client="Mobile Apps and Desktop clients" if mobile else "Browser")
        day += timedelta(days=1)

    # Impossible-travel anchor: London at 22:41 on 1 Aug, Lagos at 03:12 on 2 Aug
    add_signin(datetime(2026, 8, 1, 22, 41, 9, 220000), ceo,
               "Office 365 Exchange Online", home_ip, london, phone,
               result="0", ca="success", authreq="multiFactorAuthentication",
               mfa="PhoneAppNotification", client="Mobile Apps and Desktop clients")


# ---------------------------------------------------------------------------
# The attack
# ---------------------------------------------------------------------------
def generate_attack():
    attacker_device = ("Windows 10", "Chrome 124.0.0",
                       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0")
    ceo = BY_UPN[f"daniel.reeve@{TENANT}"]
    priya = BY_UPN[f"priya.nair@{TENANT}"]
    tom = BY_UPN[f"tom.ashworth@{TENANT}"]
    helena = BY_UPN[f"helena.crosby@{TENANT}"]
    adam = BY_UPN[f"adam.fenwick@{TENANT}"]

    # --- Phase 1: password spray, 02:41 to 03:09 ---
    spray_targets = [ceo, priya, tom, helena, adam] + random.sample(
        [u for u in USERS if u["tag"] == "staff"], 21)
    t = INCIDENT_DAY.replace(hour=2, minute=41, second=3, microsecond=110000)
    for user in spray_targets:
        for _ in range(random.randint(1, 3)):
            add_signin(t, user, "Office 365 Exchange Online", ATTACK_IP,
                       ATTACK_GEO, attacker_device, result="50126",
                       ca="notApplied", authreq="singleFactorAuthentication",
                       risk="medium", riskstate="atRisk",
                       riskevents="unfamiliarFeatures")
            t += timedelta(seconds=random.randint(9, 47))

    # Two accounts lock out under the spray
    for user in random.sample(spray_targets[5:], 2):
        add_signin(t, user, "Office 365 Exchange Online", ATTACK_IP, ATTACK_GEO,
                   attacker_device, result="50053", ca="notApplied",
                   authreq="singleFactorAuthentication", risk="medium",
                   riskstate="atRisk", riskevents="unfamiliarFeatures")
        t += timedelta(seconds=31)

    # --- Phase 2: successful CEO sign-in at 03:12:07 ---
    corr = str(uuid.UUID(int=random.getrandbits(128)))
    add_signin(INCIDENT_DAY.replace(hour=3, minute=12, second=7, microsecond=433000),
               ceo, "Office 365 Exchange Online", ATTACK_IP, ATTACK_GEO,
               attacker_device, result="0", ca="notApplied",
               authreq="singleFactorAuthentication", mfa="",
               risk="high", riskstate="atRisk",
               riskevents="unfamiliarFeatures,anonymizedIPAddress,impossibleTravel",
               corr=corr)

    for mins, app in [(14, "OfficeHome"), (17, "Microsoft Teams"),
                      (23, "SharePoint Online"), (52, "Office 365 Exchange Online")]:
        add_signin(INCIDENT_DAY.replace(hour=3, minute=mins,
                                        second=random.randint(0, 59),
                                        microsecond=random.randint(0, 999) * 1000),
                   ceo, app, ATTACK_IP, ATTACK_GEO, attacker_device,
                   result="0", ca="notApplied",
                   authreq="singleFactorAuthentication",
                   risk="high", riskstate="atRisk",
                   riskevents="unfamiliarFeatures,impossibleTravel")

    # --- Phase 3: persistence, recorded in the audit log ---
    add_audit(INCIDENT_DAY.replace(hour=3, minute=26, second=41),
              "UserManagement", "User registered security info", "success",
              ceo["upn"], ATTACK_IP, ceo["display"], "User", ceo["upn"],
              "StrongAuthenticationPhoneAppDetail", "",
              "Phone: +234 803 447 2210", app="Microsoft Authenticator",
              corr=corr)

    add_audit(INCIDENT_DAY.replace(hour=3, minute=31, second=18),
              "ApplicationManagement", "Consent to application", "success",
              ceo["upn"], ATTACK_IP, "MailFlow Sync", "ServicePrincipal",
              ceo["upn"], "ConsentAction.Permissions", "",
              "Mail.Read, Mail.ReadWrite, Mail.Send, offline_access",
              app="Azure Portal", corr=corr)

    add_audit(INCIDENT_DAY.replace(hour=3, minute=31, second=52),
              "ApplicationManagement", "Add service principal", "success",
              ceo["upn"], ATTACK_IP, "MailFlow Sync", "ServicePrincipal",
              "", "AppId", "", "e2b91f4c-7d33-49aa-9c11-8f0d5b62a7e4",
              app="Azure Portal", corr=corr)

    add_audit(INCIDENT_DAY.replace(hour=3, minute=38, second=27),
              "UserManagement", "Update user", "success",
              ceo["upn"], ATTACK_IP, ceo["display"], "User", ceo["upn"],
              "MobilePhone", "+44 7700 900184", "+234 803 447 2210",
              app="Azure Portal", corr=corr)

    # Inbox rule hiding security notifications
    add_audit(INCIDENT_DAY.replace(hour=3, minute=41, second=9),
              "MailboxConfiguration", "New-InboxRule", "success",
              ceo["upn"], ATTACK_IP, "RSS Feeds", "MailboxRule", ceo["upn"],
              "MoveToFolder", "", "Deleted Items; SubjectContainsWords: "
              "invoice, payment, wire, security alert, sign-in",
              app="Outlook Web App", corr=corr)

    # --- Phase 4: lateral movement to two more accounts ---
    add_signin(INCIDENT_DAY.replace(hour=3, minute=44, second=52, microsecond=17000),
               priya, "Office 365 Exchange Online", ATTACK_IP, ATTACK_GEO,
               attacker_device, result="0", ca="notApplied",
               authreq="singleFactorAuthentication", risk="high",
               riskstate="atRisk",
               riskevents="unfamiliarFeatures,impossibleTravel")

    add_signin(INCIDENT_DAY.replace(hour=4, minute=2, second=36, microsecond=804000),
               tom, "Office 365 Exchange Online", ATTACK_IP, ATTACK_GEO,
               attacker_device, result="0", ca="notApplied",
               authreq="singleFactorAuthentication", risk="high",
               riskstate="atRisk",
               riskevents="unfamiliarFeatures,impossibleTravel")

    add_audit(INCIDENT_DAY.replace(hour=4, minute=11, second=44),
              "MailboxConfiguration", "Add-MailboxPermission", "success",
              priya["upn"], ATTACK_IP, priya["display"], "Mailbox", priya["upn"],
              "AccessRights", "", "FullAccess granted to daniel.reeve@cloudora.io",
              app="Exchange Admin Center")

    # Failed privilege escalation - attacker has no admin rights
    add_audit(INCIDENT_DAY.replace(hour=4, minute=29, second=2),
              "RoleManagement", "Add member to role", "failure",
              ceo["upn"], ATTACK_IP, "Global Administrator", "Role", ceo["upn"],
              "Role.DisplayName", "", "Global Administrator",
              app="Azure Portal",
              reason="Authorization_RequestDenied: Insufficient privileges")

    # --- Phase 5: infrastructure rotation ---
    for mins in (12, 34, 58):
        add_signin(INCIDENT_DAY.replace(hour=6, minute=mins,
                                        second=random.randint(0, 59),
                                        microsecond=random.randint(0, 999) * 1000),
                   ceo, "Office 365 Exchange Online", ROTATE_IP, ROTATE_GEO,
                   attacker_device, result="0", ca="notApplied",
                   authreq="singleFactorAuthentication", risk="high",
                   riskstate="atRisk",
                   riskevents="anonymizedIPAddress,unfamiliarFeatures")

    add_signin(INCIDENT_DAY.replace(hour=7, minute=6, second=31, microsecond=90000),
               priya, "SharePoint Online", ROTATE_IP, ROTATE_GEO,
               attacker_device, result="0", ca="notApplied",
               authreq="singleFactorAuthentication", risk="high",
               riskstate="atRisk", riskevents="anonymizedIPAddress")

    # --- Phase 6: detection ---
    admin = BY_UPN[f"marcus.webb@{TENANT}"]
    add_signin(INCIDENT_DAY.replace(hour=8, minute=55, second=12, microsecond=644000),
               admin, "Microsoft 365 Admin Portal", OFFICE_IP,
               ("GB", "London", "England", 2856, "British Telecommunications"),
               ("Windows 11", "Edge 126.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/126.0.0"),
               result="0", ca="success", authreq="multiFactorAuthentication",
               mfa="Fido")

    # The real Daniel Reeve wakes up in London
    add_signin(INCIDENT_DAY.replace(hour=9, minute=14, second=3, microsecond=511000),
               ceo, "Office 365 Exchange Online", "86.15.108.77",
               ("GB", "London", "England", 5089, "Virgin Media"),
               ("Ios 17.5.1", "Mobile Safari",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1) Mobile/15E148"),
               result="50074", ca="success",
               authreq="multiFactorAuthentication",
               client="Mobile Apps and Desktop clients")


def generate_benign_anomalies():
    """Decoys: legitimate activity that looks suspicious under a naive query."""
    sophie = BY_UPN[f"sophie.laurent@{TENANT}"]
    laptop = ("MacOs", "Safari 17.5",
              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.5")
    # Sales trip to Paris, Tue-Thu, with MFA satisfied every time
    for d, hours in [(28, [9, 13, 17]), (29, [8, 12, 16, 19]), (30, [9, 15])]:
        for h in hours:
            add_signin(datetime(2026, 7, d, h, random.randint(0, 59),
                                random.randint(0, 59), random.randint(0, 999) * 1000),
                       sophie, wpick(APPS)[0], "185.24.186.42",
                       ("FR", "Paris", "Ile-de-France", 12322, "Free SAS"),
                       laptop, result="0", ca="success",
                       authreq="multiFactorAuthentication",
                       mfa="PhoneAppNotification",
                       risk="low", riskstate="dismissed",
                       riskevents="unfamiliarFeatures")

    # Night-shift engineer: 03:00 sign-ins from London, entirely normal for him
    nathan = BY_UPN[f"nathan.obi@{TENANT}"]
    for d in range(26, 32):
        add_signin(datetime(2026, 7, d, 3, random.randint(0, 59),
                            random.randint(0, 59), random.randint(0, 999) * 1000),
                   nathan, "Azure Portal", "51.148.63.91",
                   ("GB", "Manchester", "England", 2856,
                    "British Telecommunications"),
                   ("Windows 11", "Chrome 127.0.0",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/127.0.0"),
                   result="0", ca="success",
                   authreq="multiFactorAuthentication", mfa="Fido")


def generate_routine_audit():
    """Normal admin activity so the attacker's audit entries are not the only rows."""
    admin = f"marcus.webb@{TENANT}"
    helpdesk = f"clara.mendez@{TENANT}"
    ops = [
        ("UserManagement", "Reset user password", "User"),
        ("GroupManagement", "Add member to group", "Group"),
        ("UserManagement", "Update user", "User"),
        ("GroupManagement", "Remove member from group", "Group"),
        ("UserManagement", "Add user", "User"),
        ("DeviceManagement", "Update device", "Device"),
        ("ApplicationManagement", "Update application", "Application"),
    ]
    day = START
    while day < END:
        n = random.randint(6, 11) if day.weekday() < 5 else random.randint(1, 3)
        for _ in range(n):
            cat, op, ttype = random.choice(ops)
            target = random.choice(USERS)
            dt = day.replace(hour=random.randint(8, 18),
                             minute=random.randint(0, 59),
                             second=random.randint(0, 59))
            if dt >= END:
                continue
            add_audit(dt, cat, op, "success",
                      random.choice([admin, helpdesk]), OFFICE_IP,
                      target["display"], ttype, target["upn"],
                      app="Microsoft 365 Admin Portal")
        day += timedelta(days=1)


# ---------------------------------------------------------------------------
def main():
    generate_baseline()
    generate_ceo_baseline()
    generate_benign_anomalies()
    generate_attack()
    generate_routine_audit()

    # Trim surplus background noise to land on the documented row count.
    # Only untouched background rows are eligible - anything belonging to the
    # scenario, the named cast, or the decoys is protected.
    TARGET = 1479
    protected_ips = {ATTACK_IP, ROTATE_IP, "185.24.186.42", "51.148.63.91"}
    protected_upns = {u["upn"] for u in USERS if u["tag"] != "staff"}
    surplus = len(signin_rows) - TARGET
    if surplus > 0:
        eligible = [i for i, r in enumerate(signin_rows)
                    if r["IPAddress"] not in protected_ips
                    and r["UserPrincipalName"] not in protected_upns]
        drop = set(random.Random(99).sample(eligible, surplus))
        signin_rows[:] = [r for i, r in enumerate(signin_rows) if i not in drop]

    signin_rows.sort(key=lambda r: r["TimeGenerated"])
    audit_rows.sort(key=lambda r: r["TimeGenerated"])

    with open("cloudora_signin_logs.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SIGNIN_FIELDS)
        w.writeheader()
        w.writerows(signin_rows)

    with open("cloudora_audit_logs.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=AUDIT_FIELDS)
        w.writeheader()
        w.writerows(audit_rows)

    print(f"cloudora_signin_logs.csv : {len(signin_rows)} rows")
    print(f"cloudora_audit_logs.csv  : {len(audit_rows)} rows")


if __name__ == "__main__":
    main()
