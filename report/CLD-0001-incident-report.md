# Incident Report CLD-0001

**Client:** Cloudora (fictional)
**Ticket:** CLD-0001
**Classification:** Confirmed account takeover
**Severity:** Critical
**Analyst:** Rishita Yadav
**Investigation window:** 26 July 2026 00:00 UTC to 2 August 2026 12:00 UTC
**Data reviewed:** 1,479 Entra ID sign-in events, 51 Entra ID audit events

---

## 1. Summary

Three Cloudora user accounts were taken over in the early hours of 2 August 2026. The attacker guessed passwords from an address in Lagos, Nigeria, got into the CEO's mailbox at 03:12, and then made a series of changes designed to keep that access even if the password was changed.

The most serious of those changes was a consent grant to an application called MailFlow Sync, which holds a refresh token with the `offline_access` permission. **A password reset alone will not remove this access.** The consent grant has to be revoked separately.

The attacker also registered their own phone number as a multi-factor authentication method on the CEO's account, created a mail rule to hide security warnings, and gave themselves full access to the Financial Controller's mailbox. They attempted to make the CEO a Global Administrator at 04:29 and were refused.

The activity was not detected until 08:55, roughly five hours and forty minutes after the first successful sign-in.

---

## 2. What was in scope, and what was not

I was given two sources: Entra ID sign-in logs and Entra ID audit logs, covering eight days.

I was not given mailbox contents, message trace data, endpoint telemetry, or network logs. That limits this report in one important way. I can show which mailboxes the attacker had access to and for how long, but I cannot show which individual emails were opened, forwarded, or downloaded. Any statement about what data actually left the organisation would be guesswork, so this report does not make one. Section 10 lists what would answer that question.

---

## 3. How the investigation was carried out

I worked through four questions in order, because each one narrows the next.

**First, is the alert real?** The IT admin flagged one sign-in. On its own, a login from Nigeria proves nothing. Executives travel, and a false accusation against the CEO would be its own kind of damage. So before looking at the flagged event I built a picture of how this account normally behaves, using the seven days before the incident. That gave me something to measure the alert against.

**Second, how far did it spread?** Once I could confirm the account was compromised, I stopped following the user and started following the attacker's IP address. This is the step that found the two extra victims. Nobody had raised an alert about either of them.

**Third, is the attacker still inside?** Sign-in logs show that somebody got in. They do not show what was changed afterwards. For that I moved to the audit log, which is where the persistence mechanisms were found. This step is the reason the recommendations in section 9 are ordered the way they are.

**Fourth, why did it work?** The answer was visible in every attacker record and is covered in section 8.

I also ran a deliberately naive detection query near the end, to test my own conclusions. That is covered in section 7.

---

## 4. Timeline

All times UTC.

| Time | Event | Source |
|---|---|---|
| 1 Aug 22:41 | Daniel Reeve signs in legitimately from London, MFA satisfied. Last known good activity | Sign-in |
| 2 Aug 02:41 | Password guessing begins from 102.89.44.117 (Lagos, Nigeria, MTN Nigeria) | Sign-in |
| 02:41 to 04:02 | 26 accounts attempted, 64 attempts total, 57 rejected | Sign-in |
| 03:12:07 | **Daniel Reeve's password accepted.** Single factor only, no Conditional Access applied, risk scored high | Sign-in |
| 03:14 to 03:52 | Attacker moves through OfficeHome, Teams, SharePoint and Exchange on the same session | Sign-in |
| 03:26:41 | Attacker registers phone number +234 803 447 2210 as an MFA method | Audit |
| 03:31:18 | Consent granted to application "MailFlow Sync" with Mail.Read, Mail.ReadWrite, Mail.Send and offline_access | Audit |
| 03:31:52 | Service principal created for that application | Audit |
| 03:38:27 | Daniel Reeve's mobile number overwritten with the attacker's number | Audit |
| 03:41:09 | Inbox rule created, moving mail containing invoice, payment, wire, security alert or sign-in to Deleted Items | Audit |
| 03:44:52 | **Priya Nair compromised** from the same address | Sign-in |
| 04:02:36 | **Tom Ashworth compromised** from the same address | Sign-in |
| 04:11:44 | Full mailbox access on Priya Nair's mailbox granted to Daniel Reeve's account | Audit |
| 04:29:02 | Attempt to add Daniel Reeve to Global Administrator. **Refused**, insufficient privileges | Audit |
| 06:12 to 07:06 | Attacker switches to 45.144.212.88 (Amsterdam, hosting provider) and continues accessing both mailboxes | Sign-in |
| 08:55:12 | IT admin signs in and identifies the suspicious activity | Sign-in |
| 09:14:03 | Daniel Reeve attempts to sign in from his usual London device and is prompted for MFA | Sign-in |

---

## 5. Findings

### 5.1 The CEO's account was accessed by an unauthorised party

**What I saw.** Across the seven days before the incident, Daniel Reeve signed in 40 times. Every one of those came from London, from one of two addresses, on one of two devices, and every single one satisfied multi-factor authentication. There were no exceptions.

At 03:12:07 on 2 August his account authenticated successfully from 102.89.44.117, an MTN Nigeria address in Lagos, on a Windows 10 machine running Chrome. The three events immediately before it, at 02:41 and 02:42, were failed password attempts from that same address.

His last legitimate sign-in was from London at 22:41 the previous evening. The gap between the two is 4 hours and 31 minutes, across roughly 5,000 kilometres. No commercial route covers that distance in that time.

**What I conclude.** This was not travel and not a misattributed IP address. The failed attempts immediately preceding the success show password guessing that landed. High confidence.

### 5.2 Two further accounts were compromised without generating an alert

**What I saw.** Pivoting on the attacker address rather than the user, that IP touched 26 separate accounts between 02:41 and 04:02. Three of them authenticated successfully:

- Daniel Reeve, CEO, at 03:12
- Priya Nair, Financial Controller, at 03:44
- Tom Ashworth, Executive Assistant, at 04:02

The other 23 were attempted and held. Two of those locked out under the attempts.

**What I conclude.** The incident as reported covered one account. It actually covers three. The two additional accounts were found only by pivoting on the indicator, which is why that step matters. Both are finance-adjacent or executive-adjacent roles, which is consistent with an attacker looking for payment authority. High confidence.

### 5.3 The attacker established persistence that survives a password reset

**What I saw.** Seven directory changes were made from the attacker's addresses. In order:

1. **03:26** A new MFA phone number, +234 803 447 2210, registered on the CEO's account. The attacker can now satisfy MFA themselves.
2. **03:31** Consent granted to an application called MailFlow Sync, with permission to read, write and send mail, plus `offline_access`.
3. **03:31** A service principal created for that application, ID `e2b91f4c-7d33-49aa-9c11-8f0d5b62a7e4`.
4. **03:38** The CEO's registered mobile number replaced with the attacker's, meaning self-service password reset codes would go to them.
5. **03:41** An inbox rule named "RSS Feeds" created, moving any message containing invoice, payment, wire, security alert or sign-in into Deleted Items.
6. **04:11** Full access to Priya Nair's mailbox granted to the CEO's account.
7. **04:29** An attempt to add the CEO to the Global Administrator role, which failed with insufficient privileges.

**What I conclude.** Item 2 is the most serious. The `offline_access` permission issues a refresh token that continues to work after a password change. If Cloudora resets the three passwords and takes no further action, the attacker keeps mailbox access. Items 1 and 4 mean the account recovery process itself is compromised. Item 5 is why the CEO saw no warning emails.

Item 7 is the good news. The attacker tried to escalate to tenant-wide administrative control and was blocked because the CEO account does not hold that privilege. This is the strongest available argument that the compromise stayed at three accounts rather than spreading further. High confidence.

### 5.4 The attacker changed infrastructure partway through

**What I saw.** From 06:12, activity continues on both compromised mailboxes but from 45.144.212.88, an address in Amsterdam belonging to a hosting provider rather than a residential or mobile network. Neither address appears anywhere in the seven days before the incident.

**What I conclude.** Address rotation is normal attacker behaviour, often after suspecting detection. The important detail for containment is that the second address found no new victims, so the compromised set remains three. Medium to high confidence.

---

## 6. Accounts affected

### Confirmed compromised

| Account | Role | First access | Basis |
|---|---|---|---|
| daniel.reeve@cloudora.io | CEO | 2 Aug 03:12 | Successful authentication from attacker IP, followed by directory changes |
| priya.nair@cloudora.io | Financial Controller | 2 Aug 03:44 | Successful authentication from attacker IP, mailbox delegation granted |
| tom.ashworth@cloudora.io | Executive Assistant | 2 Aug 04:02 | Successful authentication from attacker IP |

### Targeted, not compromised

23 further accounts were subject to password attempts from the same address and rejected. They were not accessed, but their passwords were part of an attempted guess and should be treated as exposed. Two of these accounts locked out during the attack, so the users concerned may report being unable to sign in.

---

## 7. Activity I looked at and ruled out

Two patterns in this data will fire on a simple out-of-hours detection rule. Both are legitimate, and I want to be clear that neither employee is under suspicion.

**Nathan Obi, Engineering.** He appears at the top of any query for successful sign-ins between midnight and 06:00, with six events. That is more than two of the actual victims produced. Looking at the detail: six events across six separate nights, all from the same Manchester address, all satisfying multi-factor authentication with a FIDO security key, all to the Azure Portal, and all scored `RiskState: none`. This is a consistent working pattern, not an intrusion. He is on night shift.

**Sophie Laurent, Sales.** Nine successful sign-ins from Paris between 28 and 30 July. Foreign country, and a naive geographic rule would flag it. But MFA was satisfied on every one of the nine, the device is her usual MacBook, the activity spreads across three working days rather than one night, and Entra had already scored and dismissed the risk. This is a sales trip.

The three genuine compromises are separable from both of these by three attributes appearing together: single-factor authentication only, `RiskState: atRisk`, and no prior sign-in history from that location. Any one of those alone produces false positives. All three together did not.

---

## 8. Root cause

Every legitimate sign-in on Daniel Reeve's account in the seven days before the incident required multi-factor authentication. Every one of the attacker's sign-ins shows `AuthenticationRequirement: singleFactorAuthentication` and `ConditionalAccessStatus: notApplied`.

Multi-factor authentication was not bypassed or defeated. It was never asked for. The Conditional Access policy did not apply to the sign-in path the attacker used, so a correct password was sufficient on its own.

Entra ID scored these sign-ins as high risk at the time they happened. That risk signal existed and nothing acted on it.

So there are two failures here, not one. A gap in Conditional Access coverage allowed the sign-in. The absence of any automatic response to a high risk score allowed it to continue for five and a half hours.

---

## 9. Recommendations

### Immediate, within hours

Order matters here. Resetting passwords first, without doing the rest, leaves the attacker connected.

1. **Revoke the MailFlow Sync consent grant and delete the associated service principal.** Do this first. Until it is done, the `offline_access` token keeps working regardless of anything else.
2. **Revoke all refresh tokens** for the three compromised accounts.
3. **Remove the MFA method** registered at 03:26 (+234 803 447 2210) from Daniel Reeve's account, and restore his correct mobile number.
4. **Delete the inbox rule** named "RSS Feeds" on Daniel Reeve's mailbox, and check the Deleted Items folder for anything it caught.
5. **Remove the mailbox permission** granted on Priya Nair's mailbox at 04:11.
6. **Reset passwords** for all three compromised accounts, and force re-registration of MFA.
7. **Reset passwords** for the 23 targeted accounts.
8. **Review the finance approval queue** for anything submitted or approved between 03:12 and 09:00 on 2 August. The combination of a CEO mailbox and a Financial Controller mailbox is the setup for a payment fraud attempt.

### Short term, within days

9. **Close the Conditional Access gap.** Identify the sign-in path that returned `notApplied` and extend policy coverage to it. Confirm no privileged account can authenticate with a single factor by any route.
10. **Turn on a sign-in risk policy** that blocks or challenges at high risk. This attack was scored high risk in real time and nothing happened.
11. **Restrict user consent to applications.** A standard user should not be able to grant mail permissions to an unverified application without administrative approval. This single change would have stopped the most damaging step in the whole incident.
12. **Alert on new MFA method registration**, particularly from an unfamiliar location.

### Longer term

13. Move privileged accounts to phishing-resistant authentication such as FIDO2 security keys.
14. Add detection for inbox rules that move mail matching security or finance keywords to Deleted Items.
15. Set up detection for password spray patterns, meaning many accounts and few attempts each from one source in a short window.
16. Review why five hours and forty minutes passed before anyone noticed, and whether out-of-hours alerting is adequate.

---

## 10. Limitations

- **No mailbox content or message trace.** I can show access, not what was read or sent. Confirming whether data was exfiltrated needs Exchange message trace and mailbox audit logs.
- **No endpoint or network telemetry.** If any credential theft happened on a company device, I would not see it here.
- **Initial access method not established.** The password guessing succeeded, but I cannot tell from these logs whether the password was guessed outright, reused from a previous breach, or obtained by phishing. Checking the CEO's address against known credential breach data would help.
- **Eight day window.** I cannot rule out reconnaissance before 26 July.
- **Failed escalation is strong but not conclusive.** The blocked Global Administrator attempt is good evidence the compromise did not spread further, but it is inference from an absence rather than direct proof.

---

*Prepared by Rishita Yadav. Data used in this investigation is synthetic and generated for training purposes. No real organisation, individual, or network is represented.*
