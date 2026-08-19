# Privacy Policy

Effective date: August 19, 2026

This Privacy Policy explains how the Android-Device-Trust demo app and its backend process information when you use the demo app or send device check requests to the service.

This policy applies only to the demo app and the demo backend operated by Reveny. If you obtained this software from another source, deploy the code yourself, or point the app at a different backend, this policy does not apply to that deployment, and the operator of that deployment is responsible for their own privacy compliance.

## Who Is Responsible (Data Controller)

The data controller for the demo app and backend is:

Reveny
Email: [contact@reveny.me](mailto:contact@reveny.me)
Website: [https://reveny.me](https://reveny.me)

For questions, requests, or complaints about this Privacy Policy or your data, contact the email address above.

## What This Service Does

Android-Device-Trust is a device attestation and trust verification demo. Its purpose is to evaluate whether a device appears to be a normal physical device, an emulator, a modified environment, or an otherwise abnormal runtime.

**Collecting device signals is the core function of this app.** When you run a device check, the app collects device trust signals and sends them to the backend for server-side validation. The backend returns a compact result, such as whether emulator signals were detected and whether the device has been seen before.

## Your Agreement Before Any Data Is Sent

On first launch, the app displays a notice describing this data collection with a link to this Privacy Policy. **No device check runs and no data is sent to the backend until you actively agree.** If you decline, you can close the app and no information leaves your device.

By agreeing and running a check, you acknowledge that your device will be fingerprinted as described in this policy. You can withdraw from further collection at any time by simply not running further checks and uninstalling the app, and you can request deletion of stored records as described under "Your Rights."

## Information We Collect

The app and backend may process the following categories of information:

- **Device properties**, such as manufacturer, model, Android version, SDK version, build values, ABI information, display information, locale, and system configuration values.
- **Device trust and integrity signals**, such as emulator-related signals, native bridge indicators, process and runtime metadata, app integrity values, native library integrity values, and modified environment indicators.
- **Hardware and platform signals**, such as sensor inventory metadata or derived hashes, GPU or graphics metadata, battery metadata and other device capability information.
- **Attestation and key information**, such as hardware-backed key attestation results, certificate-chain metadata, public-key-derived identifiers, signature verification results, challenge verification results, and whether the attestation matches the expected app identity.
- **Generated identifiers**, such as device instance IDs, device cluster IDs, request IDs, nonces, and derived fingerprints used to recognize repeated device checks.
- **Request metadata**, such as IP address, approximate network prefix, user-agent, request time, app version, payload size, and server-side request logs.
- **Derived or hashed values**, such as hashes of selected files, properties, identifiers, package data, app signing data, and device fingerprints.

The service is designed to avoid storing raw high-volume device files when a derived value is enough for fraud and integrity analysis. Some raw values may still be processed transiently by the backend to decode and evaluate a request.

## Information We Do Not Collect

The demo app is not intended to collect:

- Names, email addresses, phone numbers, or account credentials.
- Contacts, call logs, SMS messages, photos, videos, or files from user storage.
- Precise GPS location.
- Advertising IDs for advertising or profiling.
- Payment information.

## How We Use Information

We use the information for:

- Device attestation and device trust verification.
- Emulator, automation, modified environment, and runtime integrity analysis.
- Fraud, abuse, spam, and account-security research.
- Recognizing whether the same device or a similar device has been seen before.
- Debugging false positives and improving detection quality.
- Backend security, rate limiting, abuse prevention, monitoring, and incident investigation.
- Maintaining aggregate statistics about device checks and signal quality.

We do **not** use this information for targeted advertising, and we do not build advertising or marketing profiles.

## Legal Basis

For users in the European Economic Area, the United Kingdom, or other regions with similar requirements, we rely on the following legal bases:

- **Consent** — the in-app agreement described above, covering the collection of device signals from your device when you run a check. Where rules on accessing information stored on a device apply (such as ePrivacy rules), this agreement is the basis for that access.
- **Legitimate interests** — for backend processing necessary for fraud prevention, abuse prevention, platform security, rate limiting, debugging, and protecting the integrity of the service. We have balanced these interests against your rights and expectations; because the app is clearly labeled as a fingerprinting demo and collection happens only after your agreement, we believe the processing matches what users of this app reasonably expect. You can request more information about this balancing by contacting us.
- **Compliance with legal obligations**, where applicable.

Where consent is the basis, you may withdraw it at any time with effect for the future by ceasing to use the app; this does not affect the lawfulness of processing before withdrawal.

## Automated Evaluation

The backend evaluates device signals automatically and returns a device status. In the demo app, this status is only used to display the result of the device check and to help test the detection system.

The demo service does not make decisions that produce legal or similarly significant effects for you, and it must not be used for that purpose. If you integrate this code into a system that gates access to accounts or services, you are operating outside this policy and are responsible for your own compliance, including any rules on automated decision-making.

## How Long We Keep Information

Logs and stored device check records are kept only as long as needed for testing, debugging, fraud research, and security analysis. Derived device records may be kept longer than raw request logs so the service can recognize repeated devices while reducing the amount of stored data.

Current retention targets:

- Raw request logs: up to **24 hours**.
- Debug logs: up to **24 hours**.
- Device check events and derived device records: up to **1 month**.
- Aggregated statistics that no longer identify a device or user: may be kept longer.

When retention periods expire, records are deleted or irreversibly aggregated.

## Security

We take reasonable technical and organizational measures to protect the information we process, including transport encryption (HTTPS) for requests between the app and backend, access controls on backend systems and logs, storing derived and hashed values instead of raw data where possible, and short retention periods that limit how much data exists at any time. No system is perfectly secure, and this is a demo service provided without warranties, but we design it to minimize the data it holds and the time it holds it.

## Sharing Information

We do **not** sell personal information.

We do **not** share personal information for cross-context behavioral advertising.

We do **not** share collected device check information with third parties for their own use.

Information may be processed by infrastructure and service providers necessary to operate the demo app and backend, such as hosting providers and network providers. These providers process information only as needed to provide their services to us.

Information may also be disclosed if required by law, legal process, security incident response, or to protect the rights, safety, and security of users, the service, or others.

## International Transfers

The backend and infrastructure providers may process information in countries other than the country where you are located. Where required, appropriate safeguards are used for international transfers, such as standard contractual clauses or equivalent legal mechanisms.

## Your Rights

Depending on where you live, you may have rights over your personal information, including the right to:

- Request access to information processed about you.
- Request correction of inaccurate information.
- Request deletion of information.
- Object to or restrict certain processing.
- Request portability of information.
- Withdraw consent, where processing is based on consent.
- Lodge a complaint with a data protection authority.

To make a request, contact [contact@reveny.me](mailto:contact@reveny.me).

**Identifying your records:** the service does not collect your name or account details, so we may need information such as a request ID, nonce, or the device ID shown in the app to locate records relating to your device. If we cannot identify which records relate to you, we may be unable to fulfil parts of your request; where that is the case, we will tell you, as permitted by applicable law (for example, Article 11 GDPR).

## California and US State Privacy Rights

Depending on your location and whether applicable legal thresholds are met, you may have rights under California or other US state privacy laws, including the right to know, access, delete, correct, and opt out of certain sharing or sale of personal information.

We do not sell personal information and do not share personal information for targeted advertising.

The categories of personal information processed by this service may include identifiers, internet or network activity information, device information, derived inferences used for fraud and security analysis, and approximate request metadata.

To exercise applicable rights, contact [contact@reveny.me](mailto:contact@reveny.me).

## Brazil and Other Regional Privacy Rights

Depending on your location, you may have additional rights under laws such as Brazil's LGPD or similar regional privacy laws. These may include rights to confirm processing, access data, correct data, anonymize or delete data where applicable, request portability, and receive information about data sharing.

To exercise applicable rights, contact [contact@reveny.me](mailto:contact@reveny.me).

## Children's Privacy

This demo app and service are not intended for children, and the app is directed at developers and security researchers. We do not knowingly collect personal information from children. If you believe a child has provided information to the service, contact us so the information can be reviewed and deleted where appropriate.

## Changes

This Privacy Policy may be updated as the project changes. The effective date at the top of this file shows when it was last updated.

Material changes **will** be communicated in a reasonable way, such as through the app, the release page, the repository, or the project website. Where a change materially expands the data collected, the in-app agreement will be shown again before further checks run.
