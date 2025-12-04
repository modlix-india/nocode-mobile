# nocode-mobile
A mobile shell flutter application for the nocode-ui

It is two parts.

1. Flutter shell application to be built
1. Python Script CLI to setup/generate/test the application
    1. make.py is the cli script
    1. It checks for following arguments
        - --env=&lt;name&gt;
            - The environment specifies where the no-code application definition has to be fetched from to build the applications. The default env is local. 
            - local - calls the local server to see if any applications has to be built. Server URL - https://apps.local.modlix.com
            - dev - calls the dev server to see if any applications has to be built. Server URL - https://apps.dev.modlix.com
            - stage - calls the stage server. Server URL - https://apps.stage.modlix.com
            - prod - calls the prod server. Server URL - https://apps.modlix.com
        - --username=&lt;username&gt;
        - --password=&lt;password&gt;
        - --conffile=&lt;filepath&gt;
            - if a conf file is provided in the format of properties file that is considered to load all the arguments.
    1. JSON representation of the Mobile APP service.
    ```json
        {
            "id" : "<generated>"
            "appCode": "<AppCode>",
            "clientCode": "<ClientCode>",
            "details": {
                "name": "<name>",
                "description": "<description>",
                "startURL": "", //URL of the application to start. Not provided the default page will be loaded under the client's context.
                "ios": false, //Default is false. If true generates the ios file.
                "android": false, // Default is false. If true generates the android file.
                "icon": "", // URL for the 
                // when no splash screen is required then the following section is not required.
                "splashScreen": {
                    "image": "", // URL for the image, recommended resolution is 1024x1024 png.
                    "color": "", // HEX code for the color
                    "backgroundImage": "", // URL of the Image for the background like a full wall paper
                    "fullScreen": false, // Default is false
                    // "gravity": "center", // Default is center. "center", "fill", "fitCenter", "centerCrop"
                    "color_dark": "", // Color in darkmode
                    "background_image_dark": "", // URL of the Image for the background in dark mode
                    "image_dark": "" // URL of the Image in dark mode.
                }
            }
        }
    ```