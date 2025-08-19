import argparse
import base64
import configparser
import uuid
import requests
import shutil
import logging
import os
import traceback

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
        logger.info(f"Downloaded file: {url} to {path}.{extension}")
        return extension
    else:
        raise Exception(f"Failed to download file: {url} with status code: {response.status_code}")

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
        f.write(f"}}\n")

    logger.info(f"App properties file created: {app_properties_file}")

    if details['icon']:
        # Download the icon
        icon_url = f"{url_prefix}/{details['icon']}"
        extension = download_file_withextension(icon_url, f'./{uuid}/assets/icon')
        details['icon'] = f"assets/icon.{extension}"

    if 'splashScreen' in details:
        if 'image' in details['splashScreen']:
            extension = download_file_withextension(f"{url_prefix}/{details['splashScreen']['image']}", f'./{uuid}/assets/splash_screen')
            details['splashScreen']['image'] = f"assets/splash_screen.{extension}"
        if 'backgroundImage' in details['splashScreen']:
            extension = download_file_withextension(f"{url_prefix}/{details['splashScreen']['backgroundImage']}", f'./{uuid}/assets/splash_screen_background')
            details['splashScreen']['backgroundImage'] = f"assets/splash_screen_background.{extension}"
        if 'image_dark' in details['splashScreen']:
            extension = download_file_withextension(f"{url_prefix}/{details['splashScreen']['image_dark']}", f'./{uuid}/assets/splash_screen_dark')
            details['splashScreen']['image_dark'] = f"assets/splash_screen_dark.{extension}"
        if 'background_image_dark' in details['splashScreen']:
            extension = download_file_withextension(f"{url_prefix}/{details['splashScreen']['background_image_dark']}", f'./{uuid}/assets/splash_screen_background_dark')
            details['splashScreen']['background_image_dark'] = f"assets/splash_screen_background_dark.{extension}"

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

        f.write(f"version: {details['version']}.0.0+1\n")
        lowercasename = details['name'].lower().replace(' ', '_')
        f.write(f"name: {lowercasename}\n")
        if 'description' in details:
            f.write(f"description: {details['description']}\n")

        if 'icon' in details:
            f.write(f"flutter_icons:\n")
            if 'android' in details and details['android']:
                f.write(f"  android: true\n")
            if 'ios' in details and details['ios']:
                f.write(f"  ios: true\n")
            f.write(f"  image_path: {details['icon']}\n")

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

    os.system(f"cd {uuid} && keytool -genkey -v -keystore android/app/keystore/release.keystore -alias modlix -keyalg RSA -keysize 2048 -validity 10000 -storepass modlix_778_231 -keypass modlix_778_231 -dname \"CN=Modlix Team, OU=Mobile Development, O=Modlix, L=Karnataka, ST=Karnataka, C=IN\" -noprompt")

    os.system(f"cd {uuid} && flutter pub get && dart run flutter_native_splash:create && dart run flutter_launcher_icons && dart pub add rename --dev && dart run rename setAppName --value \"{details['name']}\"")

    if 'android' in details and details['android']:
        os.system(f"cd {uuid} && flutter build appbundle --release")

    # Check if the file is built in the output directory {uuid}/build/app/outputs/bundle/release/app-release.aab
    filePath = f"./{uuid}/build/app/outputs/bundle/release/app-release.aab";

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
        raise Exception(f"Failed to upload the file to the server.To the URL: {fileUploadURL}. Status code: {response.status_code}. Response: {response.json()}")

    logger.info(f"File uploaded to the server. URL: {response.json()['url']}")

    requests.post(f"{url_prefix}/api/ui/applications/mobileApps/status/{mobileApp['id']}", headers=headers, json={
        "status": "SUCCESS", 
        "androidAppURL": f"api/files/secured/file/{mobileApp['clientCode']}/_withInClient/{mobileApp['appCode']}_{client_code_lowercase}_{details['version']}.aab",
    })

    logger.info(f"Updated the status to SUCCESS")

    # Delete the folder
    shutil.rmtree(uuid)
    logger.info(f"Deleted the folder: {uuid}")

except Exception as e:    
    stack_trace = traceback.format_exc()
    logger.error(f"Error: {e}")
    logger.error(f"Stack trace: {stack_trace}")
    requests.post(f"{url_prefix}/api/ui/applications/mobileApps/status/{mobileApp['id']}", headers=headers, json={"status": "FAILED", "errorMessage": str(e)})
    exit(1)

# if 'ios' in mobileApp and mobileApp['ios']:
#     os.system(f"cd {uuid} && flutter build ipa --release")