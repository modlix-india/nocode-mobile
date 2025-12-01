# iOS App Store Build Setup Documentation

This document provides comprehensive instructions for setting up iOS app builds for the Modlix no-code mobile app platform. There are two publishing options available:

- **PLATFORM_ACCOUNT**: Apps are published under Modlix's Apple Developer account
- **TENANT_ACCOUNT**: Apps are published under the tenant's own Apple Developer account

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Platform Account Setup (Modlix Account)](#platform-account-setup-modlix-account)
3. [Tenant Account Setup](#tenant-account-setup)
4. [Build Machine Configuration](#build-machine-configuration)
5. [Backend Configuration](#backend-configuration)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before proceeding, ensure you have:

- A Mac computer with macOS 12.0 or later
- Xcode 14.0 or later installed
- Flutter SDK installed and configured
- CocoaPods installed (`sudo gem install cocoapods`)
- Access to an Apple Developer account ($99/year membership)

---

## Platform Account Setup (Modlix Account)

Use this mode when tenants want their apps published under Modlix's Apple Developer account. The app will appear as "by Modlix" in the App Store.

### Step 1: Apple Developer Program Enrollment

1. Go to https://developer.apple.com/programs/enroll/
2. Sign in with your Apple ID or create a new one
3. Follow the enrollment process and pay the $99/year fee
4. Wait for approval (typically 24-48 hours)

### Step 2: Generate App Store Connect API Key

The API key allows automated Bundle ID creation.

1. Go to https://appstoreconnect.apple.com/
2. Click on **Users and Access** in the top navigation
3. Select the **Keys** tab
4. Click the **+** button to generate a new key
5. Configure the key:
   - **Name**: "Mobile App Builder API" (or any descriptive name)
   - **Access**: Select **Admin** (required for creating Bundle IDs)
6. Click **Generate**
7. **IMPORTANT**: Download the `.p8` file immediately - it's only available once!
8. Note down the following values:
   - **Key ID**: Displayed in the keys list (10-character alphanumeric, e.g., `ABC123DEFG`)
   - **Issuer ID**: Found at the top of the Keys page (UUID format, e.g., `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)

### Step 3: Get Team ID

1. Go to https://developer.apple.com/account/
2. Navigate to **Membership** in the left sidebar
3. Note down your **Team ID** (10-character alphanumeric, e.g., `TEAM123456`)

### Step 4: Create Distribution Certificate

1. Go to **Certificates, Identifiers & Profiles** > **Certificates**
2. Click the **+** button to create a new certificate
3. Select **Apple Distribution** under "Software" section
4. Click **Continue**

#### Create a Certificate Signing Request (CSR)

On your Mac:

1. Open **Keychain Access** (Applications > Utilities > Keychain Access)
2. From the menu bar, select **Keychain Access** > **Certificate Assistant** > **Request a Certificate from a Certificate Authority**
3. Fill in the form:
   - **User Email Address**: Your email
   - **Common Name**: Your name or company name
   - **CA Email Address**: Leave empty
   - **Request is**: Select **Saved to disk**
4. Click **Continue** and save the CSR file

#### Upload CSR and Download Certificate

1. Back in Apple Developer Portal, upload the CSR file you just created
2. Click **Continue** and then **Download**
3. Double-click the downloaded `.cer` file to install it in Keychain Access

#### Export as .p12 File

1. Open **Keychain Access** (Applications > Utilities > Keychain Access)
2. In the left sidebar, select **login** under Keychains and **My Certificates** under Category
3. Find your "Apple Distribution" certificate
   - **Important**: Look for the certificate with a disclosure triangle (▶) next to it, indicating it has a private key attached
   - If you expand the triangle, you should see your private key underneath
   - If there's no triangle/private key, the certificate was not properly installed with the CSR you created
4. Click on the certificate (not the private key) to select it
5. Right-click on the certificate and select **Export "Apple Distribution: ..."**
   - **Note**: If "Personal Information Exchange (.p12)" is grayed out, it means the certificate doesn't have an associated private key. You need to:
     - Ensure you installed the certificate on the same Mac where you created the CSR
     - The private key is created when you generate the CSR, and the certificate must be installed on that same machine
6. Choose **Personal Information Exchange (.p12)** as the format
7. Set a strong password and note it down securely
8. Click **Save** and authenticate with your macOS password if prompted
9. Save the file (e.g., `modlix-distribution.p12`)

**Troubleshooting - .p12 Export Disabled:**

If the .p12 option is disabled, try these solutions:

1. **Certificate without private key**: Re-create the CSR on your Mac, upload it to Apple Developer Portal, download and install the new certificate on the **same Mac**

2. **Wrong certificate selected**: Make sure you're selecting the certificate under "My Certificates" category, not under "Certificates" category

3. **Keychain locked**: Unlock your keychain by right-clicking on "login" keychain and selecting "Unlock Keychain"

### Step 5: Get Certificate ID (One-Time Setup)

To enable fully automated provisioning profile creation, you need to get your distribution certificate's ID from Apple.

1. Go to **Certificates, Identifiers & Profiles** > **Certificates**
2. Click on your **Apple Distribution** certificate
3. Look at the URL in your browser - it will contain the certificate ID
   - Example URL: `https://developer.apple.com/account/resources/certificates/download/XXXXXXXXXX`
   - The certificate ID is the last part: `XXXXXXXXXX`

Alternatively, use the API to list certificates:

```bash
# Generate JWT and call the API
curl -H "Authorization: Bearer YOUR_JWT" \
  "https://api.appstoreconnect.apple.com/v1/certificates?filter[certificateType]=DISTRIBUTION"
```

The response will include the certificate ID in the `id` field.

### Step 6: Fully Automated Flow (Recommended)

> **When the backend is fully configured** (API key + certificate ID), Bundle IDs and Provisioning Profiles are created **automatically** when a tenant requests PLATFORM_ACCOUNT mode. **No manual steps are required per app.**

The automated flow:
1. Tenant selects "Platform Account" in the mobile app configuration
2. Backend automatically creates the Bundle ID via Apple API
3. Backend automatically creates the App Store provisioning profile via Apple API
4. Provisioning profile is stored in the database
5. Build machine uses the stored profile - no file management needed

### Manual Fallback (If Automation Not Available)

If the certificate ID is not configured, or if you need special capabilities for an app, you can manually create Bundle IDs and provisioning profiles:

#### 6a. Register the Bundle ID (in Modlix's Apple Developer Account)

1. Go to **Identifiers** > Click **+**
2. Select **App IDs** and click **Continue**
3. Select **App** and click **Continue**
4. Fill in:
   - **Description**: App name (e.g., "MyApp - TenantName")
   - **Bundle ID**: Select **Explicit** and enter: `com.modlix.apps.{clientcode}.{appname}`
     - Example: `com.modlix.apps.acme.inventory`
5. Enable any required capabilities (Push Notifications, etc.)
6. Click **Continue** and **Register**

#### 6b. Create the Provisioning Profile (in Modlix's Apple Developer Account)

1. Go to **Profiles** > Click **+**
2. Select **App Store** under Distribution
3. Click **Continue**
4. Select the App ID you just created
5. Click **Continue**
6. Select your Distribution Certificate
7. Click **Continue**
8. Enter a profile name (e.g., "MyApp - TenantName - App Store")
9. Click **Generate** and **Download**
10. Save the `.mobileprovision` file to: `MODLIX_IOS_PROFILE_DIR/{bundle_id}.mobileprovision`

### Step 7: Configure Build Machine

Set these environment variables on your build machine:

```bash
# iOS Platform Account Configuration (required)
export MODLIX_IOS_CERTIFICATE="/path/to/modlix-distribution.p12"
export MODLIX_IOS_CERT_PASSWORD="your-certificate-password"

# Optional: Only needed if NOT using fully automated provisioning profiles
export MODLIX_IOS_PROFILE_DIR="/path/to/provisioning-profiles"
```

**Note**: When the backend is fully configured with `APPLE_CERTIFICATE_ID`, provisioning profiles are automatically created and stored in the database. The `MODLIX_IOS_PROFILE_DIR` is only needed as a fallback.

**Manual Provisioning Profile Directory Structure (Fallback):**

```
/path/to/provisioning-profiles/
├── com.modlix.apps.acme.inventory.mobileprovision
├── com.modlix.apps.acme.sales.mobileprovision
└── com.modlix.apps.beta.dashboard.mobileprovision
```

Each provisioning profile file should be named with the Bundle ID.

---

## Tenant Account Setup

Use this mode when tenants want their apps published under their own Apple Developer account. The app will appear as "by TenantCompany" in the App Store.

### Step 1: Apple Developer Program

The tenant must have their own Apple Developer Program membership ($99/year).

### Step 2: Create App ID (Bundle Identifier)

1. Go to https://developer.apple.com/account/
2. Navigate to **Certificates, Identifiers & Profiles** > **Identifiers**
3. Click **+** to register a new identifier
4. Select **App IDs** > **App**
5. Enter:
   - **Description**: Your app name
   - **Bundle ID**: Select **Explicit** and enter a unique identifier
     - Format: `com.yourcompany.appname`
     - Example: `com.acmecorp.inventoryapp`
6. Enable any required capabilities
7. Click **Continue** and **Register**

### Step 3: Create Distribution Certificate

Follow the same steps as [Platform Account Step 4](#step-4-create-distribution-certificate).

### Step 4: Create App Store Provisioning Profile

1. Go to **Profiles** > Click **+**
2. Select **App Store** under Distribution
3. Click **Continue**
4. Select the App ID created in Step 2
5. Click **Continue**
6. Select your Distribution Certificate
7. Click **Continue**
8. Enter a profile name
9. Click **Generate** and **Download**

### Step 5: Get Team ID

1. Go to **Membership** section in Apple Developer Portal
2. Note down your **Team ID**

### Step 6: Provide Credentials to Modlix Platform

Upload or enter the following in your mobile app configuration:

| Field | Description | How to Obtain |
|-------|-------------|---------------|
| Distribution Certificate (.p12) | Your signing certificate | Exported from Keychain Access |
| Certificate Password | Password for the .p12 file | Set during export |
| Provisioning Profile (.mobileprovision) | App Store distribution profile | Downloaded from Apple Developer Portal |
| Team ID | Your Apple Developer Team ID | Found in Membership section |
| Bundle ID | Your app's unique identifier | The Bundle ID you registered |

---

## Build Machine Configuration

### Required Software

Ensure the following are installed on the build machine:

```bash
# Check Xcode
xcode-select --version

# Check Flutter
flutter doctor

# Check CocoaPods
pod --version
```

### Environment Variables

Add to your shell profile (`.bashrc`, `.zshrc`, etc.) or CI/CD configuration:

```bash
# For Platform Account mode
export MODLIX_IOS_CERTIFICATE="/path/to/modlix-distribution.p12"
export MODLIX_IOS_CERT_PASSWORD="your-certificate-password"
export MODLIX_IOS_TEAM_ID="TEAM123456"
export MODLIX_IOS_PROFILE_DIR="/path/to/provisioning-profiles"

# Apple App Store Connect API (for automated Bundle ID creation)
export APPLE_API_KEY_ID="ABC123DEFG"
export APPLE_API_ISSUER_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export APPLE_API_KEY_PATH="/path/to/AuthKey_ABC123DEFG.p8"
```

### Directory Structure

Recommended directory structure on the build machine:

```
/opt/modlix-mobile-builder/
├── certificates/
│   └── modlix-distribution.p12
├── api-keys/
│   └── AuthKey_ABC123DEFG.p8
├── provisioning-profiles/
│   ├── com.modlix.apps.client1.app1.mobileprovision
│   └── com.modlix.apps.client2.app2.mobileprovision
└── scripts/
    └── run_local.sh
```

---

## Backend Configuration

### application-default.yml

Add the following configuration under the `ui:` section:

```yaml
ui:
  # ... existing configuration ...
  
  # Apple App Store Connect API Configuration
  apple:
    apiKeyId: ${APPLE_API_KEY_ID:}
    apiIssuerId: ${APPLE_API_ISSUER_ID:}
    apiKeyContent: ${APPLE_API_KEY_CONTENT:}
    bundleIdPrefix: com.modlix.apps
    teamId: ${APPLE_TEAM_ID:}
    certificateId: ${APPLE_CERTIFICATE_ID:}  # Required for auto-generating provisioning profiles
```

### Required Environment Variables for Backend

```bash
export APPLE_API_KEY_ID="ABC123DEFG"
export APPLE_API_ISSUER_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export APPLE_API_KEY_CONTENT="<base64 encoded .p8 file>"
export APPLE_TEAM_ID="TEAM123456"
export APPLE_CERTIFICATE_ID="XXXXXXXXXX"  # Get from Apple Developer Portal (see Step 5)
```

### Base64 Encoding the .p8 File

To set the `APPLE_API_KEY_CONTENT` environment variable:

```bash
# On macOS/Linux
base64 -i AuthKey_ABC123DEFG.p8 | tr -d '\n'

# Copy the output and set as environment variable
export APPLE_API_KEY_CONTENT="LS0tLS1CRUdJTi..."
```

---

## Troubleshooting

### Common Issues

#### "No signing certificate found"

**Cause**: The distribution certificate is not properly installed or the keychain is locked.

**Solution**:
1. Verify the certificate is installed: `security find-identity -v -p codesigning`
2. Ensure the keychain is unlocked
3. Check that the certificate has not expired

#### "Provisioning profile not found"

**Cause**: The provisioning profile file is missing or incorrectly named.

**Solution**:
1. Verify the file exists in `MODLIX_IOS_PROFILE_DIR`
2. Ensure the filename matches the Bundle ID: `{bundle_id}.mobileprovision`
3. Check that the profile has not expired

#### "Bundle ID already exists"

**Cause**: Attempting to create a Bundle ID that's already registered.

**Solution**: This is handled automatically - the system will use the existing Bundle ID.

#### "Code signing failed"

**Cause**: Mismatch between certificate, provisioning profile, or bundle ID.

**Solution**:
1. Verify the provisioning profile includes the correct certificate
2. Verify the Bundle ID matches in all configurations
3. Ensure the Team ID is correct

### Logs and Debugging

The build process logs are available in the console output. Look for:
- `iOS build mode: PLATFORM_ACCOUNT` or `TENANT_ACCOUNT`
- `Certificate imported successfully`
- `Installed provisioning profile: {name}`
- `Updated Xcode project signing`

### Getting Help

If you encounter issues not covered here, please:
1. Check the build logs for specific error messages
2. Verify all credentials are correct and not expired
3. Contact the Modlix engineering team with the build logs

---

## Quick Reference

### Environment Variables Summary

**Build Machine:**

| Variable | Description | Required |
|----------|-------------|----------|
| `MODLIX_IOS_CERTIFICATE` | Path to .p12 certificate | Yes |
| `MODLIX_IOS_CERT_PASSWORD` | Certificate password | Yes |
| `MODLIX_IOS_PROFILE_DIR` | Directory with provisioning profiles | Only if not using auto-generation |

**Backend (for full automation):**

| Variable | Description | Required |
|----------|-------------|----------|
| `APPLE_API_KEY_ID` | App Store Connect API Key ID | Yes |
| `APPLE_API_ISSUER_ID` | App Store Connect API Issuer ID | Yes |
| `APPLE_API_KEY_CONTENT` | Base64-encoded .p8 file content | Yes |
| `APPLE_TEAM_ID` | Apple Team ID | Yes |
| `APPLE_CERTIFICATE_ID` | Distribution certificate ID from Apple | Yes (for auto profiles) |

### API Response Fields (TENANT_ACCOUNT)

| Field | Type | Description |
|-------|------|-------------|
| `iosPublishMode` | String | "TENANT_ACCOUNT" or "PLATFORM_ACCOUNT" |
| `iosCertificate` | String | Base64-encoded .p12 certificate |
| `iosCertificatePassword` | String | Certificate password |
| `iosProvisioningProfile` | String | Base64-encoded .mobileprovision file |
| `iosTeamId` | String | 10-character Apple Team ID |
| `iosBundleId` | String | App Bundle Identifier |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025 | Initial documentation |

