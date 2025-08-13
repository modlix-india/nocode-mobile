import argparse
import base64
import configparser
import uuid
import requests
import shutil
import logging
import os

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
    hex = str(uuid.uuid4()).replace('-', '')
    
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
        return extension
    else:
        logger.error(f"Failed to download file: {url}")
        exit(1)

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

mobileApp = requests.get(
    f"{url_prefix}/api/ui/applications/mobileApps/next",
    headers=headers
).json()

if 'exceptionId' in mobileApp:
    logger.error(f"Error: {mobileApp}")
    exit(1)

logger.info(f"Generating for mobile app: {mobileApp['name']}")

uuid = shortuuid()

logger.info(f"Creating the folder with uuid: {uuid}")

# Copy the ../flutter/nocodemobile to ./{uuid}
shutil.copytree('../flutter/nocodemobile', f'./{uuid}')

# Replace the app title in the app_properties.dart file
app_properties_file = f'./{uuid}/lib/app_properties.dart'

with open(app_properties_file, 'w') as f:
    f.write(f"class AppProperties {{\n")
    f.write(f"  static const String appTitle = '{mobileApp['name']}';\n")
    f.write(f"  static const String homePageTitle = '{mobileApp['name']}';\n")
    f.write(f"  static const String appVersion = '{mobileApp['version']}.0.0';\n")
    f.write(f"  static const String startURL = '{mobileApp['startURL']}';\n")
    f.write(f"}}\n")

logger.info(f"App properties file created: {app_properties_file}")

if mobileApp['icon']:
    # Download the icon
    icon_url = f"{url_prefix}/{mobileApp['icon']}"
    extension = download_file_withextension(icon_url, f'./{uuid}/assets/icon')
    mobileApp['icon'] = f"assets/icon.{extension}"

if 'splashScreen' in mobileApp:
    if 'image' in mobileApp['splashScreen']:
        extension = download_file_withextension(f"{url_prefix}/{mobileApp['splashScreen']['image']}", f'./{uuid}/assets/splash_screen')
        mobileApp['splashScreen']['image'] = f"assets/splash_screen.{extension}"
    if 'backgroundImage' in mobileApp['splashScreen']:
        extension = download_file_withextension(f"{url_prefix}/{mobileApp['splashScreen']['backgroundImage']}", f'./{uuid}/assets/splash_screen_background')
        mobileApp['splashScreen']['backgroundImage'] = f"assets/splash_screen_background.{extension}"
    if 'image_dark' in mobileApp['splashScreen']:
        extension = download_file_withextension(f"{url_prefix}/{mobileApp['splashScreen']['image_dark']}", f'./{uuid}/assets/splash_screen_dark')
        mobileApp['splashScreen']['image_dark'] = f"assets/splash_screen_dark.{extension}"
    if 'background_image_dark' in mobileApp['splashScreen']:
        extension = download_file_withextension(f"{url_prefix}/{mobileApp['splashScreen']['background_image_dark']}", f'./{uuid}/assets/splash_screen_background_dark')
        mobileApp['splashScreen']['background_image_dark'] = f"assets/splash_screen_background_dark.{extension}"

logger.info(f"After all the downloads, the mobileApp is: {mobileApp}")

# Appending the assets to the pubspec.yaml file
with open(f'./{uuid}/pubspec.yaml', 'a') as f:
    f.write(f"\n  assets:\n")
    if 'icon' in mobileApp:
        f.write(f"    - {mobileApp['icon']}\n")

    if 'splashScreen' in mobileApp:
        if 'image' in mobileApp['splashScreen']:
            f.write(f"    - {mobileApp['splashScreen']['image']}\n")
        if 'backgroundImage' in mobileApp['splashScreen']:
            f.write(f"    - {mobileApp['splashScreen']['backgroundImage']}\n")
        if 'image_dark' in mobileApp['splashScreen']:
            f.write(f"    - {mobileApp['splashScreen']['image_dark']}\n")
        if 'background_image_dark' in mobileApp['splashScreen']:
            f.write(f"    - {mobileApp['splashScreen']['background_image_dark']}\n")
        
        f.write(f"flutter_native_splash:\n")
        if 'color' in mobileApp['splashScreen']:
            f.write(f"  color: \"{mobileApp['splashScreen']['color']}\"\n")
        if 'image' in mobileApp['splashScreen']:
            f.write(f"  image: {mobileApp['splashScreen']['image']}\n")
        if 'backgroundImage' in mobileApp['splashScreen']:
            f.write(f"  backgroundImage: {mobileApp['splashScreen']['backgroundImage']}\n")
        if 'image_dark' in mobileApp['splashScreen']:
            f.write(f"  image_dark: {mobileApp['splashScreen']['image_dark']}\n")
        if 'background_image_dark' in mobileApp['splashScreen']:
            f.write(f"  background_image_dark: {mobileApp['splashScreen']['background_image_dark']}\n")
        if 'fullScreen' in mobileApp['splashScreen']:
            value = "true" if mobileApp['splashScreen']['fullScreen'] else "false"
            f.write(f"  fullscreen: {value}\n")
        if 'color_dark' in mobileApp['splashScreen']:
            f.write(f"  color_dark: {mobileApp['splashScreen']['color_dark']}\n")

        gravity = mobileApp['splashScreen']['gravity']
        if 'android' in mobileApp and mobileApp['android']:
            f.write(f"  android: true\n")
            f.write(f"  android_gravity: {gravity}\n")

        if 'ios' in mobileApp and mobileApp['ios']:
            f.write(f"  ios: true\n")

            ios_content_mode = {
                'center': 'center',
                'fill': 'scaleToFill',
                'fitCenter': 'scaleAspectFit',
                'centerCrop': 'scaleAspectFill'
            }[gravity]

            if ios_content_mode:
                f.write(f"  ios_content_mode: {ios_content_mode}\n")

    f.write(f"version: {mobileApp['version']}.0.0+1\n")
    lowercasename = mobileApp['name'].lower().replace(' ', '_')
    f.write(f"name: {lowercasename}\n")
    if 'description' in mobileApp:
        f.write(f"description: {mobileApp['description']}\n")

    if 'icon' in mobileApp:
        f.write(f"flutter_icons:\n")
        if 'android' in mobileApp and mobileApp['android']:
            f.write(f"  android: true\n")
        if 'ios' in mobileApp and mobileApp['ios']:
            f.write(f"  ios: true\n")
        f.write(f"  image_path: {mobileApp['icon']}\n")

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

content = content.replace("android:label=\"nocodemobile\"", f"android:label=\"{mobileApp['name']}\"")

with open(android_manifest, 'w') as f:
    f.write(content)

ios_info_plist = f"./{uuid}/ios/Runner/Info.plist"

with open(ios_info_plist, 'r') as f:
    content = f.read()

content = content.replace("<string>Nocodemobile</string>", f"<string>{mobileApp['name']}</string>")

with open(ios_info_plist, 'w') as f:
    f.write(content)

os.system(f"cd {uuid} && keytool -genkey -v -keystore android/app/keystore/release.keystore -alias modlix -keyalg RSA -keysize 2048 -validity 10000 -storepass modlix_778_231 -keypass modlix_778_231 -dname \"CN=Modlix Team, OU=Mobile Development, O=Modlix, L=Karnataka, ST=Karnataka, C=IN\" -noprompt")

os.system(f"cd {uuid} && flutter pub get && dart run flutter_native_splash:create && dart run flutter_launcher_icons && dart pub add rename --dev && dart run rename setAppName --value \"{mobileApp['name']}\"")

if 'android' in mobileApp and mobileApp['android']:
    os.system(f"cd {uuid} && flutter build appbundle --release")

# if 'ios' in mobileApp and mobileApp['ios']:
#     os.system(f"cd {uuid} && flutter build ipa --release")