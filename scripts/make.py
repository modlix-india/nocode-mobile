import argparse
import base64
import configparser
import uuid as uuid_module
import requests
import shutil
import logging
import os
import traceback
import subprocess
import re
import plistlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('nocode-mobile')

def read_cli_arguments():
    """
    Reads command line arguments for the nocode-mobile app builder.
    Returns parsed arguments containing env, username, password and conffile.
    """
    parser = argparse.ArgumentParser(description='Build nocode-mobile applications')
    
    # Add arguments
    parser.add_argument('--env', 
                       choices=['local', 'dev', 'stage', 'prod'],
                       help='Environment to fetch app definitions from')
    
    parser.add_argument('--username',
                       help='Username for authentication')
    
    parser.add_argument('--password', 
                       help='Password for authentication')
    
    parser.add_argument('--conffile',
                       help='Path to configuration file in properties format.')
    
    parser.add_argument('--keep-build',
                       action='store_true',
                       help='Keep the build folder after completion (useful for debugging)')
    
    args = parser.parse_args()
    
    # If conffile is provided, read properties from it
    if args.conffile:
        config = configparser.ConfigParser()
        config.read(args.conffile)
        
        # Override CLI arguments with config file values if present
        if 'DEFAULT' in config:
            if 'env' in config['DEFAULT']:
                args.env = config['DEFAULT']['env']
            if 'username' in config['DEFAULT']:
                args.username = config['DEFAULT']['username']
            if 'password' in config['DEFAULT']:
                args.password = config['DEFAULT']['password']

    
    # Check if required arguments are provided
    if not all([args.env, args.username, args.password]):
        parser.print_help()
        parser.exit(1)
    
    return args

def shortuuid():
    base = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    baseDivisor = int(len(base))
    hex = str(uuid_module.uuid4()).replace('-', '')
    
    num = int('0x' + hex, 16)
    a = []
    
    while num > 0:
        a.append(base[int(num % baseDivisor)])
        num = num // baseDivisor
    
    return ''.join(reversed(a))

def download_file_withextension(url, path):
    response = requests.get(url)
    if response.status_code == 200:
        extension = url.split('.')[-1]
        with open(f"{path}.{extension}", 'wb') as f:
            f.write(response.content)
        logger.info(f"Downloaded file: {url} to {path}.{extension}")
        return extension
    else:
        raise Exception(f"Failed to download file: {url} with status code: {response.status_code}")


# ===================== iOS Build Helper Functions =====================

def create_temporary_keychain(keychain_name, keychain_password):
    """Create a temporary keychain for iOS code signing."""
    keychain_path = f"{os.path.expanduser('~')}/Library/Keychains/{keychain_name}"
    
    logger.info(f"=== Creating temporary keychain: {keychain_name} ===")
    logger.info(f"Keychain path: {keychain_path}")
    
    # Delete existing keychain if present
    logger.info("Checking for existing keychain...")
    delete_result = subprocess.run(['security', 'delete-keychain', keychain_path], capture_output=True, text=True)
    if delete_result.returncode == 0:
        logger.info("Deleted existing keychain")
    else:
        logger.info("No existing keychain found (this is OK)")
    
    # Create new keychain
    logger.info("Creating new keychain...")
    result = subprocess.run(
        ['security', 'create-keychain', '-p', keychain_password, keychain_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        logger.error(f"Failed to create keychain. stdout: {result.stdout}, stderr: {result.stderr}")
        raise Exception(f"Failed to create keychain: {result.stderr}")
    logger.info("Keychain created successfully")
    
    # Verify keychain exists
    if not os.path.exists(keychain_path):
        raise Exception(f"Keychain file does not exist after creation: {keychain_path}")
    logger.info(f"✓ Verified keychain file exists: {keychain_path}")
    
    # Set keychain settings
    logger.info("Setting keychain settings (no timeout, no lock)...")
    settings_result = subprocess.run(
        ['security', 'set-keychain-settings', '-lut', '21600', keychain_path],
        capture_output=True, text=True
    )
    if settings_result.returncode != 0:
        logger.warning(f"Warning setting keychain settings: {settings_result.stderr}")
    else:
        logger.info("✓ Keychain settings configured")
    
    # Unlock keychain
    logger.info("Unlocking keychain...")
    unlock_result = subprocess.run(
        ['security', 'unlock-keychain', '-p', keychain_password, keychain_path],
        capture_output=True, text=True
    )
    if unlock_result.returncode != 0:
        logger.error(f"Failed to unlock keychain. stdout: {unlock_result.stdout}, stderr: {unlock_result.stderr}")
        raise Exception(f"Failed to unlock keychain: {unlock_result.stderr}")
    logger.info("✓ Keychain unlocked")
    
    # Verify keychain is unlocked
    verify_result = subprocess.run(
        ['security', 'show-keychain-info', keychain_path],
        capture_output=True, text=True
    )
    if verify_result.returncode == 0:
        logger.info(f"✓ Keychain info: {verify_result.stdout.strip()}")
    else:
        logger.warning(f"Could not verify keychain info: {verify_result.stderr}")
    
    # Add to search list
    logger.info("Adding keychain to search list...")
    list_result = subprocess.run(['security', 'list-keychains', '-d', 'user'], capture_output=True, text=True)
    keychains = list_result.stdout.strip().replace('"', '').split('\n')
    keychains = [k.strip() for k in keychains if k.strip()]
    logger.info(f"Current keychain search list: {keychains}")
    
    keychains.insert(0, keychain_path)
    set_result = subprocess.run(
        ['security', 'list-keychains', '-d', 'user', '-s'] + keychains,
        capture_output=True, text=True
    )
    if set_result.returncode != 0:
        logger.error(f"Failed to set keychain search list: {set_result.stderr}")
        raise Exception(f"Failed to set keychain search list: {set_result.stderr}")
    
    # Verify keychain is in search list
    verify_list_result = subprocess.run(['security', 'list-keychains', '-d', 'user'], capture_output=True, text=True)
    updated_keychains = verify_list_result.stdout.strip().replace('"', '').split('\n')
    updated_keychains = [k.strip() for k in updated_keychains if k.strip()]
    if keychain_path in updated_keychains:
        logger.info(f"✓ Keychain verified in search list (position: {updated_keychains.index(keychain_path)})")
    else:
        logger.error(f"✗ Keychain NOT found in search list!")
        logger.error(f"Current search list: {updated_keychains}")
        raise Exception(f"Keychain not in search list after adding: {keychain_path}")
    
    logger.info(f"=== Successfully created and configured keychain: {keychain_path} ===")
    return keychain_path


def import_certificate_to_keychain(keychain_path, cert_path, cert_password, keychain_password):
    """Import a .p12 certificate into the keychain."""
    logger.info(f"=== Importing certificate to keychain ===")
    logger.info(f"Certificate path: {cert_path}")
    logger.info(f"Keychain path: {keychain_path}")
    
    # Verify certificate file exists
    if not os.path.exists(cert_path):
        raise Exception(f"Certificate file does not exist: {cert_path}")
    logger.info(f"✓ Certificate file exists: {cert_path}")
    
    # Check file size
    cert_size = os.path.getsize(cert_path)
    logger.info(f"Certificate file size: {cert_size} bytes")
    if cert_size == 0:
        raise Exception(f"Certificate file is empty: {cert_path}")
    
    # Verify keychain exists and is accessible
    if not os.path.exists(keychain_path):
        raise Exception(f"Keychain does not exist: {keychain_path}")
    logger.info(f"✓ Keychain exists: {keychain_path}")
    
    # Import certificate
    logger.info("Importing certificate into keychain...")
    
    # Ensure keychain is unlocked before import (critical for non-interactive import)
    logger.info("Ensuring keychain is unlocked before import...")
    unlock_result = subprocess.run(
        ['security', 'unlock-keychain', '-p', keychain_password, keychain_path],
        capture_output=True, text=True
    )
    if unlock_result.returncode == 0:
        logger.info("✓ Keychain unlocked")
    else:
        logger.warning(f"Could not unlock keychain: {unlock_result.stderr}")
    
    # Add xcodebuild to trusted applications so it can access the certificate
    xcodebuild_path = '/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild'
    if not os.path.exists(xcodebuild_path):
        # Try alternative location
        xcodebuild_path = '/usr/bin/xcodebuild'
    
    # Check if certificate already exists in keychain to avoid duplicate import
    check_result = subprocess.run(
        ['security', 'find-identity', '-v', '-p', 'codesigning', keychain_path],
        capture_output=True, text=True
    )
    
    # Try to import with -A flag to allow access from any application (non-interactive)
    # Also use -f pkcs12 to specify format explicitly
    # The -A flag allows non-interactive import
    result = subprocess.run([
        'security', 'import', cert_path,
        '-k', keychain_path,
        '-P', cert_password,
        '-A',  # Allow access from any application (non-interactive) - this is key!
        '-f', 'pkcs12',  # Explicitly specify format
        '-T', '/usr/bin/codesign',
        '-T', '/usr/bin/security',
        '-T', xcodebuild_path
    ], capture_output=True, text=True)
    
    # If import fails with "User interaction is not allowed", the -A flag didn't work
    # This can happen if the keychain has additional security restrictions
    if result.returncode != 0 and "User interaction is not allowed" in result.stderr:
        logger.warning("Import with -A flag failed, trying alternative approach...")
        # Try setting keychain to allow access before import
        # First, ensure keychain settings allow access
        settings_result = subprocess.run(
            ['security', 'set-keychain-settings', '-lut', '21600', keychain_path],
            capture_output=True, text=True
        )
        # Try import again with explicit unlock in the same command
        result = subprocess.run([
            'security', 'import', cert_path,
            '-k', keychain_path,
            '-P', cert_password,
            '-f', 'pkcs12',
            '-T', '/usr/bin/codesign',
            '-T', '/usr/bin/security',
            '-T', xcodebuild_path
        ], capture_output=True, text=True, input=keychain_password + '\n')
    
    if result.returncode != 0:
        # Check if certificate already exists (this is OK)
        if check_result.returncode == 0 and check_result.stdout:
            # Check if the certificate is already in the keychain
            cert_identifier = None
            # Try to extract certificate info from the p12 file to check if it matches
            logger.info("Import failed, checking if certificate already exists in keychain...")
            verify_result = subprocess.run(
                ['security', 'find-identity', '-v', '-p', 'codesigning', keychain_path],
                capture_output=True, text=True
            )
            if verify_result.returncode == 0 and verify_result.stdout:
                logger.info("Certificate may already exist in keychain. Verifying...")
                # If we can find identities, the keychain is working
                # The import might have failed because cert already exists
                logger.warning(f"Certificate import returned error, but checking if it's already present: {result.stderr}")
                # Don't fail if we can verify the keychain has certificates
                if "valid identities" in verify_result.stdout:
                    logger.info("✓ Certificate appears to already be in keychain, continuing...")
                else:
                    logger.error(f"Certificate import failed and no certificates found. stdout: {result.stdout}, stderr: {result.stderr}")
                    raise Exception(f"Failed to import certificate: {result.stderr}")
            else:
                logger.error(f"Certificate import failed. stdout: {result.stdout}, stderr: {result.stderr}")
                raise Exception(f"Failed to import certificate: {result.stderr}")
        else:
            logger.error(f"Certificate import failed. stdout: {result.stdout}, stderr: {result.stderr}")
            raise Exception(f"Failed to import certificate: {result.stderr}")
    else:
        logger.info(f"✓ Certificate import command succeeded")
        if result.stdout:
            logger.info(f"Import output: {result.stdout}")
    
    # Set key partition list to allow codesign and xcodebuild access
    logger.info("Setting key partition list for codesign and xcodebuild access...")
    # First, get the certificate identity hash to set partition list specifically
    find_identity_result = subprocess.run(
        ['security', 'find-identity', '-v', '-p', 'codesigning', keychain_path],
        capture_output=True, text=True
    )
    
    if find_identity_result.returncode == 0 and find_identity_result.stdout:
        # Extract the identity hash (first 40 chars after the number)
        identity_match = re.search(r'\d+\)\s+([A-F0-9]{40})', find_identity_result.stdout)
        if identity_match:
            identity_hash = identity_match.group(1)
            logger.info(f"Setting partition list for identity: {identity_hash[:20]}...")
            
            # Set partition list for the specific identity
            partition_result = subprocess.run([
                'security', 'set-key-partition-list',
                '-S', 'apple-tool:,apple:,codesign:',
                '-s', '-k', keychain_password,
                keychain_path
            ], capture_output=True, text=True)
        else:
            # Fallback to general partition list setting
            partition_result = subprocess.run([
                'security', 'set-key-partition-list',
                '-S', 'apple-tool:,apple:,codesign:',
                '-s', '-k', keychain_password, keychain_path
            ], capture_output=True, text=True)
    else:
        # Fallback if we can't find the identity
        partition_result = subprocess.run([
            'security', 'set-key-partition-list',
            '-S', 'apple-tool:,apple:,codesign:',
            '-s', '-k', keychain_password, keychain_path
        ], capture_output=True, text=True)
    
    if partition_result.returncode != 0:
        logger.warning(f"Warning setting key partition list: {partition_result.stderr}")
    else:
        logger.info("✓ Key partition list configured")
    
    # Verify certificate was imported by listing identities
    logger.info("Verifying certificate import by listing identities...")
    verify_result = subprocess.run(
        ['security', 'find-identity', '-v', '-p', 'codesigning', keychain_path],
        capture_output=True, text=True
    )
    
    if verify_result.returncode != 0:
        logger.error(f"Failed to verify certificate import: {verify_result.stderr}")
        raise Exception(f"Could not verify certificate import: {verify_result.stderr}")
    
    identities = verify_result.stdout.strip()
    logger.info(f"Found identities in keychain:\n{identities}")
    
    if not identities or "0 valid identities found" in identities:
        logger.error("✗ No valid signing identities found in keychain!")
        raise Exception("No valid signing identities found after certificate import")
    
    # Check for iOS Distribution certificate
    if "iPhone Distribution" in identities or "Apple Distribution" in identities:
        logger.info("✓ Found iOS Distribution certificate")
    else:
        logger.warning("⚠ Warning: No 'iPhone Distribution' or 'Apple Distribution' certificate found")
        logger.warning("This may cause signing issues if the certificate type is incorrect")
    
    logger.info("=== Certificate imported and verified successfully ===")


def verify_signing_certificate(keychain_path, team_id, expected_cert_type="iOS Distribution"):
    """Verify that a signing certificate matching the team ID exists in the keychain."""
    logger.info(f"=== Verifying signing certificate ===")
    logger.info(f"Team ID: {team_id}")
    logger.info(f"Expected certificate type: {expected_cert_type}")
    
    # Find all identities in the keychain
    result = subprocess.run(
        ['security', 'find-identity', '-v', '-p', 'codesigning', keychain_path],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        logger.error(f"Failed to find identities: {result.stderr}")
        raise Exception(f"Could not find identities in keychain: {result.stderr}")
    
    identities_output = result.stdout
    logger.info(f"All identities in keychain:\n{identities_output}")
    
    # Check for iOS Distribution certificate
    if expected_cert_type == "iOS Distribution":
        cert_keywords = ["iPhone Distribution", "Apple Distribution"]
    else:
        cert_keywords = [expected_cert_type]
    
    found_cert = False
    matching_team_cert = False
    
    for line in identities_output.split('\n'):
        if any(keyword in line for keyword in cert_keywords):
            found_cert = True
            logger.info(f"✓ Found {expected_cert_type} certificate: {line}")
            
            # Extract certificate hash and get details
            # Format: "   1) ABC123... \"iPhone Distribution: Company Name (TEAMID)\""
            if team_id in line:
                matching_team_cert = True
                logger.info(f"✓ Certificate matches team ID {team_id}")
                
                # Try to get more details about this certificate
                # Certificate hash format: "   1) ABC123DEF456... \"Certificate Name\""
                cert_hash_match = re.search(r'\)\s+([A-F0-9]+)', line)
                if cert_hash_match:
                    cert_hash = cert_hash_match.group(1)
                    logger.info(f"Certificate hash: {cert_hash[:20]}... (truncated for display)")
                    
                    # Try to get certificate details (optional, may not always work)
                    try:
                        cert_details = subprocess.run(
                            ['security', 'find-certificate', '-c', cert_hash, '-p', keychain_path],
                            capture_output=True, text=True, timeout=5
                        )
                        if cert_details.returncode == 0:
                            logger.info(f"✓ Certificate details retrieved successfully")
                    except Exception as e:
                        logger.debug(f"Could not retrieve full certificate details: {e}")
    
    if not found_cert:
        logger.error(f"✗ No {expected_cert_type} certificate found in keychain!")
        logger.error("Available identities:")
        logger.error(identities_output)
        raise Exception(f"No {expected_cert_type} certificate found in keychain")
    
    if not matching_team_cert:
        logger.error(f"✗ No {expected_cert_type} certificate matching team ID {team_id} found!")
        logger.error("This may cause signing errors. Available certificates:")
        logger.error(identities_output)
        raise Exception(f"No {expected_cert_type} certificate matching team ID {team_id} found")
    
    logger.info(f"=== Certificate verification successful ===")
    return True


def extract_profile_certificates(profile_path):
    """Extract certificate information from a provisioning profile.
    
    Returns a list of certificate SHA-1 fingerprints included in the profile.
    """
    with open(profile_path, 'rb') as f:
        content = f.read()
    
    # Extract plist from the signed profile
    start = content.find(b'<?xml')
    end = content.find(b'</plist>') + len(b'</plist>')
    if start == -1 or end == -1:
        return []
    
    plist_data = content[start:end]
    profile_info = plistlib.loads(plist_data)
    
    # Get the DeveloperCertificates array (contains DER-encoded certificates)
    dev_certs = profile_info.get('DeveloperCertificates', [])
    
    cert_fingerprints = []
    for cert_data in dev_certs:
        # Calculate SHA-1 fingerprint of the certificate
        import hashlib
        fingerprint = hashlib.sha1(cert_data).hexdigest().upper()
        cert_fingerprints.append(fingerprint)
    
    return cert_fingerprints


def get_certificate_fingerprint_from_keychain(keychain_path, team_id):
    """Get the SHA-1 fingerprint of the signing certificate in the keychain."""
    result = subprocess.run(
        ['security', 'find-identity', '-v', '-p', 'codesigning', keychain_path],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        return None
    
    # Parse the output to find certificate matching team ID
    # Format: "   1) ABC123DEF456... \"Apple Distribution: Company Name (TEAMID)\""
    for line in result.stdout.split('\n'):
        if team_id in line:
            # Extract the certificate hash (40 hex chars)
            cert_match = re.search(r'\d+\)\s+([A-F0-9]{40})', line)
            if cert_match:
                return cert_match.group(1)
    
    return None


def verify_certificate_in_profile(profile_path, keychain_path, team_id):
    """Verify that the signing certificate is included in the provisioning profile.
    
    Returns (is_valid, error_message)
    """
    logger.info("=== Verifying certificate is in provisioning profile ===")
    
    # Get certificate fingerprints from profile
    profile_fingerprints = extract_profile_certificates(profile_path)
    logger.info(f"Certificates in provisioning profile: {len(profile_fingerprints)}")
    for fp in profile_fingerprints:
        logger.info(f"  - {fp}")
    
    # Get signing certificate fingerprint from keychain
    signing_cert_fp = get_certificate_fingerprint_from_keychain(keychain_path, team_id)
    if not signing_cert_fp:
        return False, f"Could not find signing certificate for team ID {team_id} in keychain"
    
    logger.info(f"Signing certificate fingerprint: {signing_cert_fp}")
    
    # Check if signing certificate is in profile
    if signing_cert_fp in profile_fingerprints:
        logger.info("✓ Signing certificate IS included in provisioning profile")
        return True, None
    else:
        error_msg = (
            f"CERTIFICATE MISMATCH: The signing certificate ({signing_cert_fp}) "
            f"is NOT included in the provisioning profile.\n"
            f"The provisioning profile contains certificates: {profile_fingerprints}\n"
            f"This usually means the provisioning profile was created with a different certificate.\n"
            f"Solutions:\n"
            f"  1. Regenerate the provisioning profile using the same certificate (modlix-distro2.p12)\n"
            f"  2. Or use the certificate that matches the provisioning profile\n"
            f"  3. Check Apple Developer Portal to ensure the certificate is added to the provisioning profile"
        )
        logger.error(f"✗ {error_msg}")
        return False, error_msg


def install_provisioning_profile(profile_path):
    """Install a provisioning profile."""
    profiles_dir = os.path.expanduser('~/Library/MobileDevice/Provisioning Profiles')
    os.makedirs(profiles_dir, exist_ok=True)
    
    # Read the profile to get its UUID
    with open(profile_path, 'rb') as f:
        content = f.read()
    
    # Extract UUID from the profile using plistlib
    # The profile is a signed plist, so we need to extract the plist portion
    start = content.find(b'<?xml')
    end = content.find(b'</plist>') + len(b'</plist>')
    if start != -1 and end != -1:
        plist_data = content[start:end]
        profile_info = plistlib.loads(plist_data)
        profile_uuid = profile_info.get('UUID', str(uuid_module.uuid4()))
        profile_name = profile_info.get('Name', 'Unknown')
    else:
        profile_uuid = str(uuid_module.uuid4())
        profile_name = 'Unknown'
    
    dest_path = os.path.join(profiles_dir, f"{profile_uuid}.mobileprovision")
    shutil.copy2(profile_path, dest_path)
    
    logger.info(f"Installed provisioning profile: {profile_name} ({profile_uuid})")
    return profile_uuid, profile_name


def update_xcode_project_signing(project_dir, bundle_id, team_id, profile_name, cert_hash=None):
    """Update Xcode project with manual signing configuration.
    
    Sets bundle ID, team ID, and manual signing settings in Runner.xcodeproj only.
    This does NOT affect Pods.xcodeproj.
    
    Args:
        project_dir: Directory containing the iOS project
        bundle_id: Bundle identifier
        team_id: Development team ID
        profile_name: Provisioning profile name
        cert_hash: Optional certificate hash (SHA1) to use directly instead of name
    """
    pbxproj_path = os.path.join(project_dir, 'ios', 'Runner.xcodeproj', 'project.pbxproj')
    
    with open(pbxproj_path, 'r') as f:
        content = f.read()
    
    logger.info(f"Updating Xcode project: bundle_id={bundle_id}, team_id={team_id}, profile={profile_name}")
    if cert_hash:
        logger.info(f"Using certificate hash for CODE_SIGN_IDENTITY: {cert_hash[:20]}...")
    
    # Update bundle identifier everywhere it appears
    content = re.sub(
        r'PRODUCT_BUNDLE_IDENTIFIER = [^;]+;',
        f'PRODUCT_BUNDLE_IDENTIFIER = {bundle_id};',
        content
    )
    
    # Use certificate hash if provided, otherwise use "Apple Distribution"
    # Modern certificates are "Apple Distribution", not "iOS Distribution"
    # xcodebuild should accept "Apple Distribution" for App Store distribution certificates
    if cert_hash:
        code_sign_identity = cert_hash
    else:
        # Use "Apple Distribution" - this matches the actual certificate name
        code_sign_identity = "Apple Distribution"
    
    # Update CODE_SIGN_IDENTITY to use certificate hash or Apple Distribution
    content = re.sub(
        r'"CODE_SIGN_IDENTITY\[sdk=iphoneos\*\]" = "[^"]*";',
        f'"CODE_SIGN_IDENTITY[sdk=iphoneos*]" = "{code_sign_identity}";',
        content
    )
    
    # The signing settings need to be added to the Runner target's Release build configuration
    # The Release config for Runner target is 97C147071CF9000F007C117D
    # We need to add these settings to its buildSettings block
    
    # Find the Runner target's Release configuration and add signing settings
    # Pattern to find the Release config buildSettings block
    release_config_pattern = r'(97C147071CF9000F007C117D /\* Release \*/ = \{\s*isa = XCBuildConfiguration;\s*baseConfigurationReference = [^;]+;\s*buildSettings = \{)'
    
    signing_settings = f'''
				CODE_SIGN_IDENTITY = "{code_sign_identity}";
				"CODE_SIGN_IDENTITY[sdk=iphoneos*]" = "{code_sign_identity}";
				CODE_SIGN_STYLE = Manual;
				DEVELOPMENT_TEAM = {team_id};
				PROVISIONING_PROFILE_SPECIFIER = "{profile_name}";'''
    
    # Check if CODE_SIGN_STYLE already exists in the Release config
    if 'CODE_SIGN_STYLE = Manual' not in content:
        # Add signing settings after the buildSettings = { line
        content = re.sub(
            release_config_pattern,
            r'\g<1>' + signing_settings,
            content
        )
    
    # Also update the Debug configuration for consistency (97C147061CF9000F007C117D)
    debug_config_pattern = r'(97C147061CF9000F007C117D /\* Debug \*/ = \{\s*isa = XCBuildConfiguration;\s*baseConfigurationReference = [^;]+;\s*buildSettings = \{)'
    
    if 'CODE_SIGN_STYLE = Manual' not in content or content.count('CODE_SIGN_STYLE = Manual') < 2:
        content = re.sub(
            debug_config_pattern,
            r'\g<1>' + signing_settings,
            content
        )
    
    # Update TargetAttributes to set ProvisioningStyle = Manual
    runner_target_id = '97C146ED1CF9000F007C117D'
    
    # Replace or add ProvisioningStyle in TargetAttributes
    if 'ProvisioningStyle' in content:
        content = re.sub(
            r'ProvisioningStyle = [^;]+;',
            'ProvisioningStyle = Manual;',
            content
        )
    
    # Add DevelopmentTeam and ProvisioningStyle to the Runner target in TargetAttributes if not present
    if f'{runner_target_id} = {{' in content and 'ProvisioningStyle = Manual' not in content:
        # Find the Runner target block in TargetAttributes and add the settings
        target_block_pattern = rf'({runner_target_id} = \{{\s*\n\s+CreatedOnToolsVersion = [^;]+;\s*\n)(\s+LastSwiftMigration = [^;]+;\s*\n\s+\}};)'
        replacement = rf'\g<1>\t\t\t\t\tDevelopmentTeam = {team_id};\n\g<2>'
        content = re.sub(target_block_pattern, replacement, content)
        
        # Add ProvisioningStyle
        target_block_pattern2 = rf'({runner_target_id} = \{{\s*\n\s+CreatedOnToolsVersion = [^;]+;\s*\n\s+DevelopmentTeam = [^;]+;\s*\n\s+LastSwiftMigration = [^;]+;\s*\n)(\s+\}};)'
        replacement2 = rf'\g<1>\t\t\t\t\tProvisioningStyle = Manual;\n\t\t\t\t\g<2>'
        content = re.sub(target_block_pattern2, replacement2, content)
    
    with open(pbxproj_path, 'w') as f:
        f.write(content)
    
    # Verify the changes were made
    with open(pbxproj_path, 'r') as f:
        verify_content = f.read()
    
    has_manual_style = 'ProvisioningStyle = Manual' in verify_content
    has_code_sign_manual = 'CODE_SIGN_STYLE = Manual' in verify_content
    has_profile_specifier = f'PROVISIONING_PROFILE_SPECIFIER = "{profile_name}"' in verify_content
    
    logger.info(f"Verification - ProvisioningStyle=Manual: {has_manual_style}")
    logger.info(f"Verification - CODE_SIGN_STYLE=Manual: {has_code_sign_manual}")
    logger.info(f"Verification - PROVISIONING_PROFILE_SPECIFIER set: {has_profile_specifier}")
    
    if not has_code_sign_manual or not has_profile_specifier:
        logger.warning("Some signing settings may not have been applied correctly!")
    
    logger.info(f"Updated Xcode project with manual signing: bundle_id={bundle_id}, team_id={team_id}, profile={profile_name}")


def create_export_options_plist(output_path, team_id, bundle_id, profile_name, method='app-store'):
    """Create ExportOptions.plist for iOS archive export."""
    export_options = {
        'method': method,
        'teamID': team_id,
        'signingStyle': 'manual',
        'provisioningProfiles': {
            bundle_id: profile_name
        },
        'uploadSymbols': True,
        'compileBitcode': False
    }
    
    with open(output_path, 'wb') as f:
        plistlib.dump(export_options, f)
    
    logger.info(f"Created ExportOptions.plist at {output_path}")


def ensure_keychain_unlocked(keychain_path, keychain_password):
    """Ensure the keychain is unlocked and accessible."""
    unlock_result = subprocess.run(
        ['security', 'unlock-keychain', '-p', keychain_password, keychain_path],
        capture_output=True, text=True
    )
    if unlock_result.returncode != 0:
        logger.warning(f"Could not unlock keychain: {unlock_result.stderr}")
        return False
    return True


def cleanup_keychain(keychain_path):
    """Delete the temporary keychain."""
    try:
        subprocess.run(['security', 'delete-keychain', keychain_path], capture_output=True)
        logger.info(f"Deleted temporary keychain: {keychain_path}")
    except Exception as e:
        logger.warning(f"Failed to delete keychain: {e}")


def get_ios_credentials(mobileApp):
    """Get iOS credentials from API response or environment variables."""
    details = mobileApp.get('details', {})
    ios_publish_mode = details.get('iosPublishMode', 'TENANT_ACCOUNT')
    
    if ios_publish_mode == 'PLATFORM_ACCOUNT':
        # Use environment variables for Modlix's account
        cert_path = os.environ.get('MODLIX_IOS_CERTIFICATE')
        cert_password = os.environ.get('MODLIX_IOS_CERT_PASSWORD')
        team_id = mobileApp.get('iosTeamId') or os.environ.get('MODLIX_IOS_TEAM_ID')
        
        if not all([cert_path, cert_password, team_id]):
            raise Exception("PLATFORM_ACCOUNT mode requires MODLIX_IOS_CERTIFICATE, MODLIX_IOS_CERT_PASSWORD, and team ID")
        
        # Bundle ID should be provided by the backend
        bundle_id = mobileApp.get('iosBundleId')
        if not bundle_id:
            raise Exception("iosBundleId not provided for PLATFORM_ACCOUNT mode")
        
        # Check if provisioning profile is provided by the backend API (auto-generated)
        profile_base64 = mobileApp.get('iosProvisioningProfile')
        profile_path = None
        
        if not profile_base64:
            # Fallback to file-based provisioning profile
            profile_dir = os.environ.get('MODLIX_IOS_PROFILE_DIR')
            if profile_dir:
                profile_path = os.path.join(profile_dir, f"{bundle_id}.mobileprovision")
                if not os.path.exists(profile_path):
                    raise Exception(f"Provisioning profile not found: {profile_path}. Either configure the backend to auto-generate profiles or manually add the profile file.")
            else:
                raise Exception("No provisioning profile available. Configure APPLE_CERTIFICATE_ID in backend for auto-generation, or set MODLIX_IOS_PROFILE_DIR for manual profiles.")
        else:
            logger.info("Using auto-generated provisioning profile from backend API")
        
        return {
            'mode': 'PLATFORM_ACCOUNT',
            'cert_path': cert_path,
            'cert_password': cert_password,
            'team_id': team_id,
            'bundle_id': bundle_id,
            'profile_path': profile_path,
            'profile_base64': profile_base64
        }
    else:
        # Use tenant-provided credentials from API response
        ios_cert = mobileApp.get('iosCertificate')
        ios_cert_password = mobileApp.get('iosCertificatePassword')
        ios_profile = mobileApp.get('iosProvisioningProfile')
        team_id = mobileApp.get('iosTeamId')
        bundle_id = mobileApp.get('iosBundleId')
        
        if not all([ios_cert, ios_cert_password, ios_profile, team_id, bundle_id]):
            raise Exception("TENANT_ACCOUNT mode requires iosCertificate, iosCertificatePassword, iosProvisioningProfile, iosTeamId, and iosBundleId")
        
        return {
            'mode': 'TENANT_ACCOUNT',
            'cert_path': None,
            'cert_password': ios_cert_password,
            'team_id': team_id,
            'bundle_id': bundle_id,
            'profile_path': None,
            'cert_base64': ios_cert,
            'profile_base64': ios_profile
        }


# ===================== End iOS Build Helper Functions =====================

args = read_cli_arguments()

logger.info(f"Starting nocode-mobile app builder with env: {args.env}")

# if the env is local, then the server URL is https://apps.local.modlix.com
# if the env is dev, then the server URL is https://apps.dev.modlix.com
# if the env is stage, then the server URL is https://apps.stage.modlix.com
# if the env is prod, then the server URL is https://apps.modlix.com

url_prefix = {
    'local': 'https://apps.local.modlix.com',
    'dev': 'https://apps.dev.modlix.com',
    'stage': 'https://apps.stage.modlix.com',
    'prod': 'https://apps.modlix.com'
}[args.env]

if not url_prefix:
    logger.error(f"Invalid environment: {args.env}")
    exit(1)

logger.info(f"Using server URL: {url_prefix}")

basic_token = base64.b64encode(f"{args.username}:{args.password}".encode()).decode()
headers={"Authorization": f"Basic {basic_token}"}

nextAppResponse = requests.get(
    f"{url_prefix}/api/ui/applications/mobileApps/next",
    headers=headers
)

if nextAppResponse.status_code == 404:
    logger.info(f"No more apps to build")
    exit(0)

if nextAppResponse.status_code != 200:
    logger.error(f"Error: {nextAppResponse.json()}")
    exit(1)

mobileApp = nextAppResponse.json()

# Debug: Log iOS-related fields from the API response
logger.info("=== API Response iOS Fields ===")
logger.info(f"iosBundleId: {mobileApp.get('iosBundleId')}")
logger.info(f"iosTeamId: {mobileApp.get('iosTeamId')}")
logger.info(f"iosProvisioningProfile: {'SET (' + str(len(mobileApp.get('iosProvisioningProfile', '') or '')) + ' chars)' if mobileApp.get('iosProvisioningProfile') else 'NOT SET'}")
logger.info(f"details.iosPublishMode: {mobileApp.get('details', {}).get('iosPublishMode')}")
logger.info(f"details.ios: {mobileApp.get('details', {}).get('ios')}")
logger.info("================================")

if 'exceptionId' in mobileApp or not 'details' in mobileApp:
    logger.error(f"Error: {mobileApp}")
    exit(1)

try :

    requests.post(f"{url_prefix}/api/ui/applications/mobileApps/status/{mobileApp['id']}", headers=headers, json={"status": "IN_PROGRESS"})

    logger.info(f"Updated the status to IN_PROGRESS")
    
    details = mobileApp['details']

    logger.info(f"Generating for mobile app: {details['name']}")

    uuid = f"app_{shortuuid()}"

    logger.info(f"Creating the folder with uuid: {uuid}")

    # Copy the ../flutter/nocodemobile to ./{uuid}
    shutil.copytree('../flutter/nocodemobile', f'./{uuid}')

    # Replace the app title in the app_properties.dart file
    app_properties_file = f'./{uuid}/lib/app_properties.dart'

    with open(app_properties_file, 'w') as f:
        f.write(f"class AppProperties {{\n")
        f.write(f"  static const String appTitle = '{details['name']}';\n")
        f.write(f"  static const String homePageTitle = '{details['name']}';\n")
        f.write(f"  static const String appVersion = '{details['version']}.0.0';\n")
        f.write(f"  static const String startURL = '{details['startURL']}';\n")

        if 'splashScreen' in details:
            if 'image' in details['splashScreen']:
                extension = download_file_withextension(f"{url_prefix}/{details['splashScreen']['image']}", f'./{uuid}/assets/splash_screen')
                details['splashScreen']['image'] = f"assets/splash_screen.{extension}"
                f.write(f"  static const String splashScreenImage = 'assets/splash_screen.{extension}';\n")
            else:
                f.write(f"  static const String splashScreenImage = '';\n")

            if 'backgroundImage' in details['splashScreen']:
                extension = download_file_withextension(f"{url_prefix}/{details['splashScreen']['backgroundImage']}", f'./{uuid}/assets/splash_screen_background')
                details['splashScreen']['backgroundImage'] = f"assets/splash_screen_background.{extension}"
                f.write(f"  static const String splashScreenBackgroundImage = 'assets/splash_screen_background.{extension}';\n")
            else:
                f.write(f"  static const String splashScreenBackgroundImage = '';\n")

            if 'image_dark' in details['splashScreen']:
                extension = download_file_withextension(f"{url_prefix}/{details['splashScreen']['image_dark']}", f'./{uuid}/assets/splash_screen_dark')
                details['splashScreen']['image_dark'] = f"assets/splash_screen_dark.{extension}"
                f.write(f"  static const String splashScreenImageDark = 'assets/splash_screen_dark.{extension}';\n")
            else:
                f.write(f"  static const String splashScreenImageDark = '';\n")

            if 'background_image_dark' in details['splashScreen']:
                extension = download_file_withextension(f"{url_prefix}/{details['splashScreen']['background_image_dark']}", f'./{uuid}/assets/splash_screen_background_dark')
                details['splashScreen']['background_image_dark'] = f"assets/splash_screen_background_dark.{extension}"
                f.write(f"  static const String splashScreenBackgroundImageDark = 'assets/splash_screen_background_dark.{extension}';\n")
            else:
                f.write(f"  static const String splashScreenBackgroundImageDark = '';\n")

            if 'color' in details['splashScreen']:
                f.write(f"  static const String splashScreenColor = '{details['splashScreen']['color']}';\n")
            else:
                f.write(f"  static const String splashScreenColor = '#FFFFFF';\n")

            if 'color_dark' in details['splashScreen']:
                f.write(f"  static const String splashScreenColorDark = '{details['splashScreen']['color_dark']}';\n")
            else:
                f.write(f"  static const String splashScreenColorDark = '';\n")

            if 'fullScreen' in details['splashScreen']:
                value = "true" if details['splashScreen']['fullScreen'] else "false"
                f.write(f"  static const bool splashScreenFullScreen = {value};\n")
            else:
                f.write(f"  static const bool splashScreenFullScreen = false;\n")

            if 'gravity' in details['splashScreen']:
                f.write(f"  static const String splashScreenGravity = '{details['splashScreen']['gravity']}';\n")
            else:
                f.write(f"  static const String splashScreenGravity = 'center';\n")

            f.write(f"  static const bool generatedSplashScreen = true;\n")
        else:
            f.write(f"  static const String splashScreenImage = '';\n")
            f.write(f"  static const String splashScreenBackgroundImage = '';\n")
            f.write(f"  static const String splashScreenImageDark = '';\n")
            f.write(f"  static const String splashScreenBackgroundImageDark = '';\n")
            f.write(f"  static const String splashScreenColor = '#FFFFFF';\n")
            f.write(f"  static const String splashScreenColorDark = '#FFFFFF';\n")
            f.write(f"  static const bool splashScreenFullScreen = false;\n")
            f.write(f"  static const String splashScreenGravity = 'center';\n")
            f.write(f"  static const bool generatedSplashScreen = false;\n")
                
        f.write(f"}}\n")

    logger.info(f"App properties file created: {app_properties_file}")

    if details['icon']:
        # Download the icon
        icon_url = f"{url_prefix}/{details['icon']}"
        logger.info(f"Downloading icon from: {icon_url}")
        try:
            extension = download_file_withextension(icon_url, f'./{uuid}/assets/icon')
            details['icon'] = f"assets/icon.{extension}"
            logger.info(f"Icon downloaded successfully: {details['icon']}")
        except Exception as e:
            logger.error(f"Failed to download icon: {e}")
            details['icon'] = None

    logger.info(f"After all the downloads, the mobileApp is: {details}")

    # Appending the assets to the pubspec.yaml file
    with open(f'./{uuid}/pubspec.yaml', 'a') as f:
        f.write(f"\n  assets:\n")
        if 'icon' in details:   
            f.write(f"    - {details['icon']}\n")

        if 'splashScreen' in details:
            if 'image' in details['splashScreen']:
                f.write(f"    - {details['splashScreen']['image']}\n")
            if 'backgroundImage' in details['splashScreen']:
                f.write(f"    - {details['splashScreen']['backgroundImage']}\n")
            if 'image_dark' in details['splashScreen']:
                f.write(f"    - {details['splashScreen']['image_dark']}\n")
            if 'background_image_dark' in details['splashScreen']:
                f.write(f"    - {details['splashScreen']['background_image_dark']}\n")
            
            f.write(f"flutter_native_splash:\n")
            if 'color' in details['splashScreen']:
                f.write(f"  color: \"{details['splashScreen']['color']}\"\n")
            if 'image' in details['splashScreen']:
                f.write(f"  image: {details['splashScreen']['image']}\n")
            if 'backgroundImage' in details['splashScreen']:
                f.write(f"  backgroundImage: {details['splashScreen']['backgroundImage']}\n")
            if 'image_dark' in details['splashScreen']:
                f.write(f"  image_dark: {details['splashScreen']['image_dark']}\n")
            if 'background_image_dark' in details['splashScreen']:
                f.write(f"  background_image_dark: {details['splashScreen']['background_image_dark']}\n")
            if 'fullScreen' in details['splashScreen']:
                value = "true" if details['splashScreen']['fullScreen'] else "false"
                f.write(f"  fullscreen: {value}\n")
            if 'color_dark' in details['splashScreen']:
                f.write(f"  color_dark: {details['splashScreen']['color_dark']}\n")

            gravity = details['splashScreen']['gravity']
            if 'android' in details and details['android']:
                f.write(f"  android: true\n")
                f.write(f"  android_gravity: {gravity}\n")

            if 'ios' in details and details['ios']:
                f.write(f"  ios: true\n")

                ios_content_mode = {
                    'center': 'center',
                    'fill': 'scaleToFill',
                    'fitCenter': 'scaleAspectFit',
                    'centerCrop': 'scaleAspectFill'
                }[gravity]

                if ios_content_mode:
                    f.write(f"  ios_content_mode: {ios_content_mode}\n")

        f.write(f"version: {details['version']}.0.0+{details['version']}\n")
        lowercasename = details['name'].lower().replace(' ', '_')
        f.write(f"name: {lowercasename}\n")
        if 'description' in details:
            f.write(f"description: {details['description']}\n")

        if 'icon' in details:
            f.write(f"flutter_icons:\n")
            f.write(f"  image_path: {details['icon']}\n")
            if 'android' in details and details['android']:
                f.write(f"  android: true\n")
            if 'ios' in details and details['ios']:
                f.write(f"  ios: true\n")

    logger.info(f"Pubspec.yaml file updated: {f'./{uuid}/pubspec.yaml'}")


    blundle_gradle_kts = f"./{uuid}/android/app/build.gradle.kts"

    with open(blundle_gradle_kts, 'r') as f:
        content = f.read()

    client_code_lowercase = mobileApp['clientCode'].lower()
    content = content.replace("applicationId = \"com.modlix.nocodemobile\"", f"applicationId = \"com.modlix.nocodemobile.{client_code_lowercase}.{lowercasename}\"")

    with open(blundle_gradle_kts, 'w') as f:
        f.write(content)

    android_manifest = f"./{uuid}/android/app/src/main/AndroidManifest.xml"

    with open(android_manifest, 'r') as f:
        content = f.read()

    content = content.replace("android:label=\"nocodemobile\"", f"android:label=\"{details['name']}\"")

    with open(android_manifest, 'w') as f:
        f.write(content)

    ios_info_plist = f"./{uuid}/ios/Runner/Info.plist"

    with open(ios_info_plist, 'r') as f:
        content = f.read()

    content = content.replace("<string>Nocodemobile</string>", f"<string>{details['name']}</string>")

    with open(ios_info_plist, 'w') as f:
        f.write(content)


    if 'androidKeystore' in mobileApp:
        os.system(f"cd {uuid} && echo '{mobileApp['androidKeystore']}' | base64 -d > android/app/keystore/release.keystore")
        with open(f"./{uuid}/android/key.properties", 'w') as f:
            f.write(f"keyAlias={mobileApp['androidAlias']}\n")
            f.write(f"keyPassword={mobileApp['androidKeyPass']}\n")
            f.write(f"storePassword={mobileApp['androidStorePass']}\n")

    logger.info("Running flutter pub get...")
    os.system(f"cd {uuid} && flutter pub get")
    
    if details.get('icon'):
        logger.info("Generating app icons...")
        result = os.system(f"cd {uuid} && dart run flutter_launcher_icons --file pubspec.yaml")
        if result != 0:
            logger.error("Failed to generate app icons")
        else:
            logger.info("App icons generated successfully")
    
    logger.info("Adding rename package and setting app name...")
    os.system(f"cd {uuid} && dart run flutter_native_splash:create && dart pub add rename --dev && dart run rename setAppName --value \"{details['name']}\"")

    android_app_url = None
    ios_app_url = None
    
    # ===================== Android Build =====================
    if 'android' in details and details['android']:
        logger.info("Starting Android build...")
        os.system(f"cd {uuid} && flutter build appbundle --release")

        # Check if the file is built in the output directory {uuid}/build/app/outputs/bundle/release/app-release.aab
        filePath = f"./{uuid}/build/app/outputs/bundle/release/app-release.aab"

        if not os.path.exists(filePath):
            requests.post(f"{url_prefix}/api/ui/applications/mobileApps/status/{mobileApp['id']}", headers=headers, json={"status": "FAILED", "errorMessage": "Android build failed. Please, check with Engineering team."})
            exit(1)

        # Rename the file to <appCode>_<clientCode>_<version>.aab
        newFileName = f"{mobileApp['appCode']}_{client_code_lowercase}_{details['version']}.aab"
        newFilePath = f"./{uuid}/build/app/outputs/bundle/release/{newFileName}"
        os.rename(filePath, newFilePath)

        # Upload the file to the server, using Multipart/form-data
        fileUploadURL = f"api/files/secured/_withInClient/"

        with open(newFilePath, 'rb') as f:
            response = requests.post(f"{url_prefix}/{fileUploadURL}?clientCode={mobileApp['clientCode']}", headers=headers, files={'file': (newFileName, f, 'application/octet-stream')}, timeout=120)

        if response.status_code != 200:
            raise Exception(f"Failed to upload Android file to the server. URL: {fileUploadURL}. Status code: {response.status_code}. Response: {response.json()}")

        logger.info(f"Android file uploaded to the server. URL: {response.json()['url']}")
        android_app_url = f"api/files/secured/file/{mobileApp['clientCode']}/_withInClient/{mobileApp['appCode']}_{client_code_lowercase}_{details['version']}.aab"

    # ===================== iOS Build =====================
    if 'ios' in details and details['ios']:
        logger.info("Starting iOS build...")
        keychain_path = None
        keychain_name = f"build_{uuid}.keychain-db"
        keychain_password = str(uuid_module.uuid4())
        
        try:
            # Get iOS credentials
            ios_creds = get_ios_credentials(mobileApp)
            logger.info(f"iOS build mode: {ios_creds['mode']}")
            
            # Use a persistent keychain instead of temporary one
            # xcodebuild cannot access private keys in temporary keychains due to macOS security
            # Using a persistent keychain allows xcodebuild to access the certificate
            persistent_keychain_name = "build.keychain-db"
            persistent_keychain_password = "build_keychain_password"  # Use a fixed password for persistent keychain
            keychain_path = f"{os.path.expanduser('~')}/Library/Keychains/{persistent_keychain_name}"
            
            # Create or use existing persistent keychain
            # If keychain exists but we can't unlock it, delete and recreate it
            if os.path.exists(keychain_path):
                logger.info(f"=== Checking existing persistent keychain: {persistent_keychain_name} ===")
                logger.info(f"Keychain path: {keychain_path}")
                
                # Try to unlock with our password to verify we have access
                unlock_test = subprocess.run(
                    ['security', 'unlock-keychain', '-p', persistent_keychain_password, keychain_path],
                    capture_output=True, text=True
                )
                
                if unlock_test.returncode != 0:
                    logger.warning(f"Existing keychain cannot be unlocked with our password: {unlock_test.stderr}")
                    logger.info("Deleting existing keychain to recreate with known password...")
                    # Remove from search list first
                    list_result = subprocess.run(['security', 'list-keychains', '-d', 'user'], capture_output=True, text=True)
                    keychains = [k.strip().replace('"', '') for k in list_result.stdout.strip().split('\n') if k.strip()]
                    if keychain_path in keychains:
                        keychains.remove(keychain_path)
                        subprocess.run(['security', 'list-keychains', '-d', 'user', '-s'] + keychains, capture_output=True, text=True)
                    
                    # Delete the keychain
                    delete_result = subprocess.run(
                        ['security', 'delete-keychain', keychain_path],
                        capture_output=True, text=True
                    )
                    if delete_result.returncode == 0:
                        logger.info("✓ Deleted existing keychain")
                    else:
                        logger.warning(f"Could not delete keychain: {delete_result.stderr}")
                    # Fall through to create new keychain
                else:
                    logger.info("✓ Existing keychain is accessible")
            
            # Create keychain if it doesn't exist (or was just deleted)
            if not os.path.exists(keychain_path):
                logger.info(f"=== Creating persistent keychain: {persistent_keychain_name} ===")
                logger.info(f"Keychain path: {keychain_path}")
                create_result = subprocess.run(
                    ['security', 'create-keychain', '-p', persistent_keychain_password, keychain_path],
                    capture_output=True, text=True
                )
                if create_result.returncode != 0:
                    raise Exception(f"Failed to create persistent keychain: {create_result.stderr}")
                logger.info("✓ Persistent keychain created")
                
                # Configure keychain settings
                subprocess.run(
                    ['security', 'set-keychain-settings', '-lut', '21600', keychain_path],
                    capture_output=True, text=True
                )
            else:
                logger.info(f"=== Using existing persistent keychain: {persistent_keychain_name} ===")
            
            # Ensure keychain is unlocked
            unlock_result = subprocess.run(
                ['security', 'unlock-keychain', '-p', persistent_keychain_password, keychain_path],
                capture_output=True, text=True
            )
            if unlock_result.returncode != 0:
                raise Exception(f"Failed to unlock keychain: {unlock_result.stderr}")
            else:
                logger.info("✓ Keychain unlocked")
            
            # Ensure keychain is in search list and is first
            list_result = subprocess.run(['security', 'list-keychains', '-d', 'user'], capture_output=True, text=True)
            keychains = [k.strip().replace('"', '') for k in list_result.stdout.strip().split('\n') if k.strip()]
            if keychain_path not in keychains:
                keychains.insert(0, keychain_path)
            elif keychains[0] != keychain_path:
                keychains.remove(keychain_path)
                keychains.insert(0, keychain_path)
            
            set_result = subprocess.run(
                ['security', 'list-keychains', '-d', 'user', '-s'] + keychains,
                capture_output=True, text=True
            )
            if set_result.returncode == 0:
                logger.info(f"✓ Keychain is first in search list")
            
            # Set as default keychain
            subprocess.run(
                ['security', 'default-keychain', '-d', 'user', '-s', keychain_path],
                capture_output=True, text=True
            )
            logger.info(f"✓ Keychain set as default")
            
            # Update keychain_password variable for use in rest of code
            keychain_password = persistent_keychain_password
            
            # Prepare certificate and provisioning profile files
            if ios_creds['mode'] == 'TENANT_ACCOUNT':
                # Decode and save certificate from base64
                cert_temp_path = f"./{uuid}/ios_cert.p12"
                with open(cert_temp_path, 'wb') as f:
                    f.write(base64.b64decode(ios_creds['cert_base64']))
                cert_path = cert_temp_path
                
                # Decode and save provisioning profile from base64
                profile_temp_path = f"./{uuid}/ios_profile.mobileprovision"
                with open(profile_temp_path, 'wb') as f:
                    f.write(base64.b64decode(ios_creds['profile_base64']))
                profile_path = profile_temp_path
            else:
                # PLATFORM_ACCOUNT mode - use certificate from environment
                cert_path = ios_creds['cert_path']
                
                # Check if profile is provided via API (auto-generated) or from file
                if ios_creds['profile_base64']:
                    # Use auto-generated profile from backend API
                    profile_temp_path = f"./{uuid}/ios_profile.mobileprovision"
                    with open(profile_temp_path, 'wb') as f:
                        f.write(base64.b64decode(ios_creds['profile_base64']))
                    profile_path = profile_temp_path
                    logger.info("Using provisioning profile from backend API (auto-generated)")
                else:
                    # Use profile from file system
                    profile_path = ios_creds['profile_path']
                    logger.info(f"Using provisioning profile from file: {profile_path}")
            
            # Import certificate to temporary keychain
            import_certificate_to_keychain(keychain_path, cert_path, ios_creds['cert_password'], keychain_password)
            
            # Optionally import to login keychain if LOGIN_KEYCHAIN_PASSWORD is set
            # This can help xcodebuild find the certificate, but is not required
            # when using a properly configured build keychain
            certificate_in_login_keychain = False
            login_keychain_password = os.environ.get('LOGIN_KEYCHAIN_PASSWORD')
            
            if login_keychain_password:
                logger.info("Importing certificate to login keychain for xcodebuild access...")
                login_keychain = os.path.expanduser('~/Library/Keychains/login.keychain-db')
                if not os.path.exists(login_keychain):
                    login_keychain = os.path.expanduser('~/Library/Keychains/login.keychain')
                
                try:
                    # Unlock login keychain with provided password
                    logger.info("Unlocking login keychain with provided password...")
                    unlock_login = subprocess.run(
                        ['security', 'unlock-keychain', '-p', login_keychain_password, login_keychain],
                        capture_output=True, text=True
                    )
                    
                    if unlock_login.returncode != 0:
                        logger.warning(f"Could not unlock login keychain: {unlock_login.stderr}")
                    else:
                        # Import to login keychain with -A flag to allow access from any application
                        login_import_result = subprocess.run([
                            'security', 'import', cert_path,
                            '-k', login_keychain,
                            '-P', ios_creds['cert_password'],
                            '-A',  # Allow access from any application
                            '-T', '/usr/bin/codesign',
                            '-T', '/usr/bin/security',
                            '-T', '/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild'
                        ], capture_output=True, text=True)
                        
                        if login_import_result.returncode == 0:
                            logger.info("✓ Certificate imported to login keychain")
                            # Set key partition list for login keychain
                            subprocess.run([
                                'security', 'set-key-partition-list',
                                '-S', 'apple-tool:,apple:,codesign:',
                                '-s', '-k', login_keychain_password, login_keychain
                            ], capture_output=True, text=True)
                            certificate_in_login_keychain = True
                        else:
                            logger.warning(f"Could not import to login keychain: {login_import_result.stderr}")
                except Exception as e:
                    logger.warning(f"Error importing to login keychain: {e}")
            else:
                logger.info("Skipping login keychain import (LOGIN_KEYCHAIN_PASSWORD not set)")
                logger.info("Using dedicated build keychain only - this should work for most builds")
            
            # Verify certificate matches team ID
            logger.info("Verifying certificate matches team ID...")
            verify_signing_certificate(keychain_path, ios_creds['team_id'], "iOS Distribution")
            
            # Use "Apple Distribution" instead of certificate hash
            # The certificate is "Apple Distribution", so we need to match that name
            # Using the hash requires xcodebuild to access the keychain to look it up,
            # which it can't do reliably with temporary keychains
            cert_hash = None  # Don't use hash, use "Apple Distribution" instead
            logger.info("Will use 'Apple Distribution' for CODE_SIGN_IDENTITY (xcodebuild will find it by name)")
            
            # Install provisioning profile
            logger.info(f"Installing provisioning profile from: {profile_path}")
            profile_uuid, profile_name = install_provisioning_profile(profile_path)
            logger.info(f"Installed profile: UUID={profile_uuid}, Name={profile_name}")
            
            # Verify profile is installed
            profiles_dir = os.path.expanduser('~/Library/MobileDevice/Provisioning Profiles')
            installed_profile_path = os.path.join(profiles_dir, f"{profile_uuid}.mobileprovision")
            if os.path.exists(installed_profile_path):
                logger.info(f"✓ Profile verified at: {installed_profile_path}")
            else:
                logger.error(f"✗ Profile NOT found at: {installed_profile_path}")
            
            # CRITICAL: Verify that the signing certificate is included in the provisioning profile
            # This is the most common cause of "profile doesn't include certificate" errors
            is_cert_valid, cert_error = verify_certificate_in_profile(profile_path, keychain_path, ios_creds['team_id'])
            if not is_cert_valid:
                raise Exception(cert_error)
            
            # Update Xcode project signing
            logger.info("Updating Xcode project signing configuration...")
            update_xcode_project_signing(f"./{uuid}", ios_creds['bundle_id'], ios_creds['team_id'], profile_name, cert_hash)
            
            # Verify the pbxproj was updated
            pbxproj_path = os.path.join(f"./{uuid}", 'ios', 'Runner.xcodeproj', 'project.pbxproj')
            with open(pbxproj_path, 'r') as f:
                pbx_content = f.read()
            logger.info(f"Verification - Bundle ID in pbxproj: {ios_creds['bundle_id'] in pbx_content}")
            logger.info(f"Verification - Team ID in pbxproj: {ios_creds['team_id'] in pbx_content}")
            
            # Create ExportOptions.plist
            export_options_path = f"./{uuid}/ExportOptions.plist"
            create_export_options_plist(export_options_path, ios_creds['team_id'], ios_creds['bundle_id'], profile_name)
            
            # Log ExportOptions.plist content for debugging
            with open(export_options_path, 'rb') as f:
                export_options = plistlib.load(f)
            logger.info(f"ExportOptions.plist: {export_options}")
            
            # Run pod install
            logger.info("Running pod install...")
            os.system(f"cd {uuid}/ios && pod install")
            
            # Build iOS IPA using xcodebuild directly for more control
            logger.info("Building iOS IPA...")
            
            # First, build the app using Flutter to prepare dependencies
            logger.info("Step 1: Running flutter build ios --release --no-codesign")
            prep_result = os.system(f"cd {uuid} && flutter build ios --release --no-codesign")
            if prep_result != 0:
                raise Exception("Flutter iOS build preparation failed")
            
            # ========== Comprehensive Pre-Archive Verification ==========
            logger.info("=== Pre-Archive Verification ===")
            
            # 1. Verify keychain still exists and is accessible
            if not os.path.exists(keychain_path):
                raise Exception(f"Keychain no longer exists: {keychain_path}")
            logger.info(f"✓ Keychain exists: {keychain_path}")
            
            # 2. Verify keychain is in search list
            list_result = subprocess.run(['security', 'list-keychains', '-d', 'user'], capture_output=True, text=True)
            current_keychains = list_result.stdout.strip().replace('"', '').split('\n')
            current_keychains = [k.strip() for k in current_keychains if k.strip()]
            if keychain_path not in current_keychains:
                logger.error(f"✗ Keychain NOT in search list!")
                logger.error(f"Current search list: {current_keychains}")
                logger.info("Attempting to re-add keychain to search list...")
                current_keychains.insert(0, keychain_path)
                fix_result = subprocess.run(
                    ['security', 'list-keychains', '-d', 'user', '-s'] + current_keychains,
                    capture_output=True, text=True
                )
                if fix_result.returncode != 0:
                    raise Exception(f"Failed to re-add keychain to search list: {fix_result.stderr}")
                logger.info("✓ Keychain re-added to search list")
            else:
                logger.info(f"✓ Keychain verified in search list (position: {current_keychains.index(keychain_path)})")
            
            # 3. Verify keychain is unlocked
            unlock_result = subprocess.run(
                ['security', 'unlock-keychain', '-p', keychain_password, keychain_path],
                capture_output=True, text=True
            )
            if unlock_result.returncode != 0:
                logger.warning(f"Keychain unlock check failed: {unlock_result.stderr}")
            else:
                logger.info("✓ Keychain is unlocked")
            
            # 4. Verify certificate is still in keychain
            cert_identity_result = subprocess.run(
                ['security', 'find-identity', '-v', '-p', 'codesigning', keychain_path],
                capture_output=True, text=True
            )
            if cert_identity_result.returncode != 0:
                raise Exception(f"Failed to find identities in keychain: {cert_identity_result.stderr}")
            
            identities_output = cert_identity_result.stdout
            logger.info(f"Available signing identities in keychain:\n{identities_output}")
            
            if not identities_output or "0 valid identities found" in identities_output:
                raise Exception("No valid signing identities found in keychain before archive!")
            
            # 5. Verify iOS Distribution certificate exists and matches team ID
            if ios_creds['team_id'] not in identities_output:
                logger.error(f"✗ No certificate matching team ID {ios_creds['team_id']} found!")
                logger.error("Available identities:")
                logger.error(identities_output)
                raise Exception(f"No certificate matching team ID {ios_creds['team_id']} found in keychain")
            
            has_distribution_cert = any(keyword in identities_output for keyword in ["iPhone Distribution", "Apple Distribution"])
            if not has_distribution_cert:
                logger.error("✗ No iOS Distribution certificate found!")
                logger.error("Available identities:")
                logger.error(identities_output)
                raise Exception("No iOS Distribution certificate found in keychain")
            
            logger.info(f"✓ Found iOS Distribution certificate matching team ID {ios_creds['team_id']}")
            
            # 5b. Verify codesign can see the certificate
            logger.info("Verifying codesign can access the certificate...")
            codesign_result = subprocess.run(
                ['security', 'find-identity', '-v', '-p', 'codesigning'],
                capture_output=True, text=True
            )
            if codesign_result.returncode == 0:
                all_identities = codesign_result.stdout
                if ios_creds['team_id'] in all_identities:
                    logger.info("✓ codesign can see certificate with matching team ID")
                else:
                    logger.warning("⚠ codesign cannot see certificate with matching team ID in default search")
                    logger.warning("This may indicate a keychain search order issue")
                    logger.info(f"All identities visible to codesign:\n{all_identities}")
            else:
                logger.warning(f"Could not verify codesign access: {codesign_result.stderr}")
            
            # 6. Verify provisioning profile is still installed
            if not os.path.exists(installed_profile_path):
                raise Exception(f"Provisioning profile no longer exists: {installed_profile_path}")
            logger.info(f"✓ Provisioning profile verified: {installed_profile_path}")
            
            # 7. Verify ExportOptions.plist exists
            if not os.path.exists(export_options_path):
                raise Exception(f"ExportOptions.plist does not exist: {export_options_path}")
            logger.info(f"✓ ExportOptions.plist exists: {export_options_path}")
            
            # 8. Verify Xcode project signing configuration
            with open(pbxproj_path, 'r') as f:
                pbx_content = f.read()
            
            # Check for required settings - CODE_SIGN_IDENTITY can be either hash or "Apple Distribution"
            required_settings = [
                ('CODE_SIGN_STYLE = Manual', 'Manual signing style'),
                (f'DEVELOPMENT_TEAM = {ios_creds["team_id"]}', 'Team ID'),
                (f'PROVISIONING_PROFILE_SPECIFIER = "{profile_name}"', 'Provisioning profile specifier'),
            ]
            
            for setting, description in required_settings:
                if setting in pbx_content:
                    logger.info(f"✓ {description} found in project.pbxproj")
                else:
                    logger.error(f"✗ {description} NOT found in project.pbxproj!")
                    raise Exception(f"Missing {description} in project.pbxproj")
            
            # Check for CODE_SIGN_IDENTITY (can be hash or "Apple Distribution")
            if 'CODE_SIGN_IDENTITY =' in pbx_content:
                # Extract the value to log it
                code_sign_match = re.search(r'CODE_SIGN_IDENTITY = "([^"]+)";', pbx_content)
                if code_sign_match:
                    code_sign_value = code_sign_match.group(1)
                    logger.info(f"✓ Code sign identity found in project.pbxproj: {code_sign_value[:40]}...")
                else:
                    logger.info("✓ Code sign identity found in project.pbxproj")
            else:
                logger.error("✗ CODE_SIGN_IDENTITY NOT found in project.pbxproj!")
                raise Exception("Missing CODE_SIGN_IDENTITY in project.pbxproj")
            
            logger.info("=== Pre-Archive Verification Complete ===")
            # ============================================================
            
            # Set temporary keychain as default keychain so xcodebuild can find the certificate
            logger.info("Configuring keychain for xcodebuild access...")
            
            # Save current default keychain
            default_keychain_result = subprocess.run(
                ['security', 'default-keychain', '-d', 'user'],
                capture_output=True, text=True
            )
            original_default_keychain = None
            if default_keychain_result.returncode == 0:
                original_default_keychain = default_keychain_result.stdout.strip().replace('"', '')
                logger.info(f"Current default keychain: {original_default_keychain}")
            
            # Save current search list
            list_result = subprocess.run(['security', 'list-keychains', '-d', 'user'], capture_output=True, text=True)
            original_search_list = []
            if list_result.returncode == 0:
                original_search_list = [k.strip().replace('"', '') for k in list_result.stdout.strip().split('\n') if k.strip()]
                logger.info(f"Current keychain search list: {original_search_list}")
            
            # Set temporary keychain as default
            set_default_result = subprocess.run(
                ['security', 'default-keychain', '-d', 'user', '-s', keychain_path],
                capture_output=True, text=True
            )
            if set_default_result.returncode != 0:
                logger.error(f"Failed to set default keychain: {set_default_result.stderr}")
                raise Exception(f"Failed to set default keychain: {set_default_result.stderr}")
            logger.info(f"✓ Set temporary keychain as default: {keychain_path}")
            
            # Ensure temporary keychain is first in search list (and include system keychains)
            # We need to include login.keychain and System.keychain for xcodebuild to work properly
            system_keychains = ['/Library/Keychains/System.keychain', '/Library/Keychains/SystemRootCertificates.keychain']
            login_keychain = os.path.expanduser('~/Library/Keychains/login.keychain-db')
            if not os.path.exists(login_keychain):
                login_keychain = os.path.expanduser('~/Library/Keychains/login.keychain')
            
            new_search_list = [keychain_path]
            if os.path.exists(login_keychain):
                new_search_list.append(login_keychain)
            new_search_list.extend([k for k in system_keychains if os.path.exists(k)])
            
            # Add any other keychains that were in the original list (except our temp one)
            for kc in original_search_list:
                if kc != keychain_path and kc not in new_search_list:
                    new_search_list.append(kc)
            
            set_search_result = subprocess.run(
                ['security', 'list-keychains', '-d', 'user', '-s'] + new_search_list,
                capture_output=True, text=True
            )
            if set_search_result.returncode == 0:
                logger.info(f"✓ Updated keychain search list (temp keychain is first)")
                logger.info(f"New search list: {new_search_list[:3]}... (showing first 3)")
            else:
                logger.warning(f"⚠ Could not update search list: {set_search_result.stderr}")
            
            # Verify it's set as default
            verify_default_result = subprocess.run(
                ['security', 'default-keychain', '-d', 'user'],
                capture_output=True, text=True
            )
            if verify_default_result.returncode == 0:
                current_default = verify_default_result.stdout.strip().replace('"', '')
                if current_default == keychain_path:
                    logger.info(f"✓ Verified temporary keychain is now default")
                else:
                    logger.warning(f"⚠ Default keychain verification failed. Expected: {keychain_path}, Got: {current_default}")
            
            # Ensure keychain is unlocked (xcodebuild may need it unlocked)
            # Use -u flag to unlock for user session (not just temporarily)
            unlock_user_result = subprocess.run(
                ['security', 'unlock-keychain', '-u', '-p', keychain_password, keychain_path],
                capture_output=True, text=True
            )
            if unlock_user_result.returncode == 0:
                logger.info("✓ Keychain unlocked for user session")
            else:
                logger.warning(f"⚠ Could not unlock keychain for user session: {unlock_user_result.stderr}")
                # Fallback to regular unlock
                if ensure_keychain_unlocked(keychain_path, keychain_password):
                    logger.info("✓ Keychain unlocked (fallback method)")
            
            # Also set keychain settings to prevent auto-lock during build
            settings_result = subprocess.run(
                ['security', 'set-keychain-settings', '-lut', '21600', keychain_path],
                capture_output=True, text=True
            )
            if settings_result.returncode == 0:
                logger.info("✓ Keychain settings updated to prevent auto-lock")
            
            # Try to add xcodebuild as a trusted application for the keychain
            # This helps xcodebuild access the certificate
            logger.info("Configuring keychain trust for xcodebuild...")
            xcodebuild_path = '/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild'
            if os.path.exists(xcodebuild_path):
                # Add xcodebuild to keychain access list
                add_trust_result = subprocess.run(
                    ['security', 'add-trusted-app', '-k', keychain_path, xcodebuild_path],
                    capture_output=True, text=True
                )
                if add_trust_result.returncode == 0:
                    logger.info("✓ Added xcodebuild to keychain trusted apps")
                else:
                    logger.debug(f"Could not add xcodebuild to trusted apps (may not be necessary): {add_trust_result.stderr}")
            
            # Verify codesign can now see the certificate with default keychain
            logger.info("Re-verifying codesign can access certificate with default keychain...")
            codesign_check = subprocess.run(
                ['security', 'find-identity', '-v', '-p', 'codesigning'],
                capture_output=True, text=True
            )
            if codesign_check.returncode == 0:
                all_identities = codesign_check.stdout
                if ios_creds['team_id'] in all_identities:
                    logger.info("✓ codesign can now see certificate with matching team ID")
                else:
                    logger.warning("⚠ codesign still cannot see certificate even with default keychain")
                    logger.warning(f"All identities:\n{all_identities}")
                    
                    # Last resort: Try to explicitly add the keychain to the search again
                    logger.info("Attempting to force keychain refresh...")
                    # Remove and re-add to force refresh
                    remove_result = subprocess.run(
                        ['security', 'list-keychains', '-d', 'user', '-s'] + [k for k in new_search_list if k != keychain_path],
                        capture_output=True, text=True
                    )
                    add_back_result = subprocess.run(
                        ['security', 'list-keychains', '-d', 'user', '-s', keychain_path] + [k for k in new_search_list if k != keychain_path],
                        capture_output=True, text=True
                    )
                    if add_back_result.returncode == 0:
                        logger.info("✓ Forced keychain refresh")
                        # Verify again
                        codesign_check2 = subprocess.run(
                            ['security', 'find-identity', '-v', '-p', 'codesigning'],
                            capture_output=True, text=True
                        )
                        if codesign_check2.returncode == 0 and ios_creds['team_id'] in codesign_check2.stdout:
                            logger.info("✓ Certificate now visible after refresh")
                        else:
                            logger.warning("⚠ Certificate still not visible after refresh")
            
            # Final verification: Check that the certificate is accessible in the specific keychain
            logger.info("Final verification: Checking certificate in specific keychain...")
            final_check = subprocess.run(
                ['security', 'find-identity', '-v', '-p', 'codesigning', keychain_path],
                capture_output=True, text=True
            )
            if final_check.returncode == 0 and ios_creds['team_id'] in final_check.stdout:
                logger.info("✓ Certificate confirmed accessible in keychain")
                logger.info(f"Certificate details:\n{final_check.stdout}")
            else:
                logger.error("✗ Certificate NOT accessible in keychain!")
                raise Exception("Certificate not accessible in keychain before archive")
            
            # Archive using xcodebuild directly
            archive_path = f"./{uuid}/build/ios/archive/Runner.xcarchive"
            logger.info("Step 2: Archiving with xcodebuild")
            
            try:
                # Only pass signing parameters for the Runner target, not globally
                # The project.pbxproj has been updated with manual signing for Runner
                # Use subprocess instead of os.system to ensure keychain access
                archive_cmd = [
                    'xcodebuild', 'archive',
                    '-workspace', 'Runner.xcworkspace',
                    '-scheme', 'Runner',
                    '-configuration', 'Release',
                    '-archivePath', '../build/ios/archive/Runner.xcarchive',
                    '-destination', 'generic/platform=iOS',
                    'ONLY_ACTIVE_ARCH=NO'
                ]
                
                # Set up environment to ensure keychain is accessible
                env = os.environ.copy()
                # Ensure the keychain is unlocked in the environment
                # We'll unlock it right before running xcodebuild
                logger.info(f"Running xcodebuild archive with keychain: {keychain_path}")
                
                # Unlock keychain one more time right before xcodebuild
                pre_unlock = subprocess.run(
                    ['security', 'unlock-keychain', '-u', '-p', keychain_password, keychain_path],
                    capture_output=True, text=True
                )
                if pre_unlock.returncode == 0:
                    logger.info("✓ Keychain unlocked immediately before xcodebuild")
                
                # Create a wrapper script that ensures keychain is unlocked before xcodebuild
                # This is necessary because xcodebuild spawns processes that need keychain access
                wrapper_script = f"""#!/bin/bash
set -e
export KEYCHAIN_PATH='{keychain_path}'
export KEYCHAIN_PASSWORD='{keychain_password}'

# Function to unlock keychain
unlock_keychain() {{
    security unlock-keychain -u -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH" 2>/dev/null || true
    # Also try without -u flag
    security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH" 2>/dev/null || true
}}

# Unlock the keychain multiple times to ensure it stays unlocked
unlock_keychain

# Set keychain as default
security default-keychain -d user -s "$KEYCHAIN_PATH" 2>/dev/null || true

# Ensure keychain is first in search list
CURRENT_LIST=$(security list-keychains -d user | tr -d '"' | tr '\\n' ' ')
NEW_LIST="$KEYCHAIN_PATH $CURRENT_LIST"
security list-keychains -d user -s $NEW_LIST 2>/dev/null || true

# Set keychain settings to prevent auto-lock (no timeout, no lock when sleeping)
security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH" 2>/dev/null || true

# Unlock again
unlock_keychain

# Verify certificate is accessible
CERT_CHECK=$(security find-identity -v -p codesigning "$KEYCHAIN_PATH" 2>/dev/null | grep -c "valid identities" || echo "0")
if [ "$CERT_CHECK" = "0" ]; then
    echo "Error: Certificate not found in keychain before xcodebuild" >&2
    security find-identity -v -p codesigning "$KEYCHAIN_PATH" >&2
    exit 1
fi

# List all identities to verify access
echo "Available signing identities in keychain:" >&2
security find-identity -v -p codesigning "$KEYCHAIN_PATH" >&2

# Also check default search
echo "Identities in default search:" >&2
security find-identity -v -p codesigning 2>&1 | head -5 >&2

# Run xcodebuild with keychain unlocked
# Use a background process to keep keychain unlocked during build
(
    while true; do
        unlock_keychain
        sleep 30
    done
) &
UNLOCK_PID=$!

# Trap to kill the unlock process when xcodebuild exits
trap "kill $UNLOCK_PID 2>/dev/null || true" EXIT

# Run xcodebuild - it will inherit the keychain environment
# Use exec to ensure xcodebuild runs in the same process
exec xcodebuild "$@"
"""
                # Use absolute path for wrapper script
                wrapper_path = os.path.abspath(f"./{uuid}/ios/xcodebuild_wrapper.sh")
                wrapper_dir = os.path.dirname(wrapper_path)
                os.makedirs(wrapper_dir, exist_ok=True)
                
                with open(wrapper_path, 'w') as f:
                    f.write(wrapper_script)
                os.chmod(wrapper_path, 0o755)
                logger.info(f"Created wrapper script at: {wrapper_path}")
                
                # Use the wrapper script - use just the filename since we're changing to ios directory
                archive_cmd_wrapped = [
                    './xcodebuild_wrapper.sh',
                    'archive',
                    '-workspace', 'Runner.xcworkspace',
                    '-scheme', 'Runner',
                    '-configuration', 'Release',
                    '-archivePath', '../build/ios/archive/Runner.xcarchive',
                    '-destination', 'generic/platform=iOS',
                    'ONLY_ACTIVE_ARCH=NO'
                ]
                
                logger.info("Running xcodebuild with keychain unlock wrapper...")
                archive_result = subprocess.run(
                    archive_cmd_wrapped,
                    cwd=f"{uuid}/ios",
                    env=env,
                    capture_output=False,  # Let output go to stdout/stderr for real-time viewing
                    text=True
                )
                
                # Clean up wrapper script
                try:
                    os.remove(wrapper_path)
                    logger.info("Cleaned up wrapper script")
                except Exception as e:
                    logger.warning(f"Could not remove wrapper script: {e}")
                
                if archive_result.returncode != 0:
                    raise Exception("xcodebuild archive failed")
            finally:
                # Restore original default keychain if we changed it
                if original_default_keychain:
                    logger.info(f"Restoring original default keychain: {original_default_keychain}")
                    restore_result = subprocess.run(
                        ['security', 'default-keychain', '-d', 'user', '-s', original_default_keychain],
                        capture_output=True, text=True
                    )
                    if restore_result.returncode == 0:
                        logger.info("✓ Original default keychain restored")
                    else:
                        logger.warning(f"⚠ Failed to restore original default keychain: {restore_result.stderr}")
                
                # Restore original search list if we changed it
                if original_search_list:
                    logger.info("Restoring original keychain search list...")
                    restore_search_result = subprocess.run(
                        ['security', 'list-keychains', '-d', 'user', '-s'] + original_search_list,
                        capture_output=True, text=True
                    )
                    if restore_search_result.returncode == 0:
                        logger.info("✓ Original keychain search list restored")
                    else:
                        logger.warning(f"⚠ Failed to restore original search list: {restore_search_result.stderr}")
            
            # Export IPA using xcodebuild
            ipa_output_dir = f"./{uuid}/build/ios/ipa"
            os.makedirs(ipa_output_dir, exist_ok=True)
            logger.info("Step 3: Exporting IPA with xcodebuild")
            export_cmd = (
                f"xcodebuild -exportArchive "
                f"-archivePath {archive_path} "
                f"-exportPath {ipa_output_dir} "
                f"-exportOptionsPlist {export_options_path}"
            )
            logger.info(f"Export command: {export_cmd}")
            build_result = os.system(export_cmd)
            
            if build_result != 0:
                raise Exception("iOS build failed")
            
            # Find the IPA file
            ipa_dir = f"./{uuid}/build/ios/ipa"
            ipa_files = [f for f in os.listdir(ipa_dir) if f.endswith('.ipa')] if os.path.exists(ipa_dir) else []
            
            if not ipa_files:
                raise Exception("IPA file not found after build")
            
            ipa_path = os.path.join(ipa_dir, ipa_files[0])
            
            # Rename the IPA file
            new_ipa_name = f"{mobileApp['appCode']}_{client_code_lowercase}_{details['version']}.ipa"
            new_ipa_path = os.path.join(ipa_dir, new_ipa_name)
            os.rename(ipa_path, new_ipa_path)
            
            # Upload the IPA file
            fileUploadURL = f"api/files/secured/_withInClient/"
            
            with open(new_ipa_path, 'rb') as f:
                response = requests.post(f"{url_prefix}/{fileUploadURL}?clientCode={mobileApp['clientCode']}", headers=headers, files={'file': (new_ipa_name, f, 'application/octet-stream')}, timeout=180)
            
            if response.status_code != 200:
                raise Exception(f"Failed to upload iOS file to the server. Status code: {response.status_code}. Response: {response.json()}")
            
            logger.info(f"iOS file uploaded to the server. URL: {response.json()['url']}")
            ios_app_url = f"api/files/secured/file/{mobileApp['clientCode']}/_withInClient/{mobileApp['appCode']}_{client_code_lowercase}_{details['version']}.ipa"
            
        except Exception as ios_error:
            logger.error(f"iOS build error: {ios_error}")
            # If Android was successful but iOS failed, we'll still report partial success
            if android_app_url:
                logger.warning("iOS build failed but Android build succeeded. Continuing with partial success.")
            else:
                raise ios_error
        finally:
            # Cleanup: Remove certificate from login keychain if we imported it there
            if 'certificate_in_login_keychain' in locals() and certificate_in_login_keychain:
                logger.info("Cleaning up certificate from login keychain...")
                try:
                    login_keychain = os.path.expanduser('~/Library/Keychains/login.keychain-db')
                    if not os.path.exists(login_keychain):
                        login_keychain = os.path.expanduser('~/Library/Keychains/login.keychain')
                    
                    # Find and delete the certificate from login keychain
                    find_result = subprocess.run(
                        ['security', 'find-identity', '-v', '-p', 'codesigning', login_keychain],
                        capture_output=True, text=True
                    )
                    if find_result.returncode == 0 and ios_creds['team_id'] in find_result.stdout:
                        # Extract certificate hash
                        cert_match = re.search(r'\d+\)\s+([A-F0-9]{40})', find_result.stdout)
                        if cert_match:
                            cert_hash = cert_match.group(1)
                            # Delete the certificate
                            delete_result = subprocess.run(
                                ['security', 'delete-certificate', '-c', cert_hash, login_keychain],
                                capture_output=True, text=True
                            )
                            if delete_result.returncode == 0:
                                logger.info("✓ Removed certificate from login keychain")
                            else:
                                logger.warning(f"Could not remove certificate from login keychain: {delete_result.stderr}")
                except Exception as e:
                    logger.warning(f"Error cleaning up login keychain: {e}")
            
            # Don't cleanup persistent keychain - it's reused across builds
            # The persistent keychain allows xcodebuild to access certificates reliably
            if keychain_path and 'build.keychain-db' in keychain_path:
                logger.info(f"Persistent keychain will be reused: {keychain_path}")
            elif keychain_path:
                # Only cleanup if it's a temporary keychain (shouldn't happen now)
                cleanup_keychain(keychain_path)

    # ===================== Update Status =====================
    if android_app_url or ios_app_url:
        status_payload = {"status": "SUCCESS"}
        if android_app_url:
            status_payload["androidAppURL"] = android_app_url
        if ios_app_url:
            status_payload["iosAppURL"] = ios_app_url
        
        requests.post(f"{url_prefix}/api/ui/applications/mobileApps/status/{mobileApp['id']}", headers=headers, json=status_payload)
        logger.info(f"Updated the status to SUCCESS")
    else:
        raise Exception("No builds were successful")

    # Delete the folder (unless --keep-build is specified)
    if args.keep_build:
        logger.info(f"Keeping build folder (--keep-build): {uuid}")
    else:
        shutil.rmtree(uuid)
        logger.info(f"Deleted the folder: {uuid}")

except Exception as e:    
    stack_trace = traceback.format_exc()
    logger.error(f"Error: {e}")
    logger.error(f"Stack trace: {stack_trace}")
    requests.post(f"{url_prefix}/api/ui/applications/mobileApps/status/{mobileApp['id']}", headers=headers, json={"status": "FAILED", "errorMessage": str(e)})
    exit(1)