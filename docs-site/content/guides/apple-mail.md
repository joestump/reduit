---
title: Connecting Apple Mail
sidebar_label: Apple Mail (macOS & iOS)
sidebar_position: 4
---

# Connecting Apple Mail

Reduit speaks standard **IMAPS** and **SMTPS**, so the built-in Mail app on
macOS and iOS connects with no plugins and no Proton Bridge. This guide uses
Apple Mail; the same four values work in any IMAP client (`mutt`, Thunderbird,
Outlook, the iOS/Android stock apps).

## Get your credentials

Reduit issues its **own** IMAP/SMTP password for each account — you never put
your Proton password into the mail client. In the Reduit dashboard:

1. Open the account and go to its **Credentials** page
   (`/accounts/{id}/credentials`).
2. Note the **Username** (your account's primary alias, e.g.
   `joe@stump.rocks`).
3. If no password is set yet, click **Generate** (or **Rotate**) to mint one.
   The IMAP/SMTP password is shown there — copy it now.

The page gives you everything you need:

| Field | Value |
|-------|-------|
| **Username** | your primary alias (full email address) |
| **Password** | the generated Reduit IMAP/SMTP password (one password, both protocols) |
| **IMAP server** | your Reduit host, e.g. `reduit.family.tld` |
| **IMAP port** | `993`, SSL/TLS |
| **SMTP server** | your Reduit host, e.g. `reduit.family.tld` |
| **SMTP port** | `465`, SSL/TLS |

:::tip This is not your Proton password
The username/password here are Reduit credentials, scoped to one account.
Rotating the password immediately invalidates every client still using the old
one — handy if a device is lost.
:::

## macOS Mail

1. **Mail ▸ Settings… ▸ Accounts ▸ +** (or **Mail ▸ Add Account…**).
2. Choose **Other Mail Account…** and click **Continue**.
3. Enter your **Name**, the **Email Address** (your primary alias), and the
   Reduit **Password**. Click **Sign In**.
4. Mail will fail to auto-detect — that's expected. Fill in the details manually
   when prompted:
   - **Account Type:** IMAP
   - **Incoming Mail Server:** `reduit.family.tld`
   - **Outgoing Mail Server:** `reduit.family.tld`
   - **User Name:** your primary alias (e.g. `joe@stump.rocks`)
   - **Password:** the Reduit password
5. Click **Sign In** again to finish.

### Verify the ports and TLS

After the account is added, open **Mail ▸ Settings… ▸ Accounts ▸ _your
account_ ▸ Server Settings** and confirm:

- **Incoming (IMAP):** Host `reduit.family.tld`, Port **993**, **Use TLS/SSL
  ✔**. Turn **off** “Automatically manage connection settings” if it picks the
  wrong port.
- **Outgoing (SMTP):** Host `reduit.family.tld`, Port **465**, **Use TLS/SSL
  ✔**, Authentication **Password**.

## iOS / iPadOS Mail

1. **Settings ▸ Mail ▸ Accounts ▸ Add Account ▸ Other ▸ Add Mail Account**.
2. Enter your name, the alias email, and the Reduit password.
3. On the IMAP screen, set both **Incoming** and **Outgoing** host to
   `reduit.family.tld`, with your alias as the username and the Reduit password.
4. Save. iOS negotiates SSL on 993/465 automatically; if it complains, set
   the SMTP port to `465` with SSL under the account's advanced settings.

## How authentication works

Reduit authenticates the IMAP/SMTP session with **SASL PLAIN** using a
`local@host` identity — exactly the `username` shown on the Credentials page.
The password is the Reduit-issued secret, verified against a stored hash; your
Proton session lives server-side, encrypted under the
[master key](/guides/configuration). Authentication failures return a generic
error by design and never reveal which field was wrong
([SPEC-0003](/specs/imap-server/spec)).

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| “The mail server … is not responding” | Confirm 993/465 are reachable from the client and TLS is on. Reduit only serves these over TLS. |
| Login rejected | Re-copy the password from **Credentials** (it may have been rotated). The username is the alias, not your Proton login. |
| Sending fails but receiving works | Check the **outgoing** server: port **465**, SSL on, Authentication = Password. |
| Mail looks stale | The sync worker mirrors Proton in the background; give a newly linked account a moment to backfill. |
