source nocode-mobile-venv/bin/activate

# iOS Platform Account Configuration (for PLATFORM_ACCOUNT mode)
# These are used by make.py when building iOS apps using Modlix's developer account

# Required: Path to the distribution certificate
export MODLIX_IOS_CERTIFICATE="../certs/modlix-distro2.p12"
export MODLIX_IOS_CERT_PASSWORD="Modlix@123!@#"

# Optional: Only needed if backend is NOT configured to auto-generate provisioning profiles
# When APPLE_CERTIFICATE_ID is set in backend, profiles are created automatically
export MODLIX_IOS_PROFILE_DIR="../provisioning-profiles"

python3 make.py --env=local --username=confuser --password='Pass@1234' --keep-build
