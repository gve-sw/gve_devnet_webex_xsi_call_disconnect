# gve_devnet_webex_xsi_call_disconnect

This application serves as a monitoring tool for Webex calls, ensuring they do not overextend their allotted duration by proactively disconnecting them. It additionally logs both answered and released calls, presenting the data on a Flask-based dashboard. The application also generates adaptive cards corresponding to call events to send in a Webex room, offering a visually intuitive representation of the call data.

## Prerequisites

### Registering Your Integration

1. **Start with Webex Developer Portal**: Visit [developer.webex.com](https://developer.webex.com) and login with your credentials.

2. **Navigate to Your Apps**: Once logged in, select the "My Webex Apps" option from the dashboard.

3. **Initiate App Creation**: Click on the "Create new App" button. From the available app type options, select "Create an Integration".

4. **Fill in the App Details**:
   - **Name**: Provide a name for your integration.
   - **Icon**: Select or upload an icon that will be used on the developer portal.
   - **Description**: Give a brief description of the app you are building.
   - **Redirect URI**: Provide a Redirect URI. This is the address to which a user will be redirected after completing an OAuth grant flow. Typically, this should be the address where your Flask app is running.
   - **Scopes**: Define the level of access your integration will need. For this project, ensure you have the following scopes:
     - `spark:all, spark-admin:xsi, spark:xsi, spark-admin:locations_read, spark-admin:people_read, spark-admin:licenses_read
5. **Save Your Credentials**:
   - After creating the integration, Webex will provide a `Client ID` and `Client Secret`. Ensure you copy and save these details securely.
   - You will use the `Client ID` and `Client Secret` in your `.env` file.

### Environment Variables Setup

For security and ease of configuration, this application relies on a `.env` file to store sensitive information. Create a `.env` file in the root directory of the project and add the following entries:

```env
CLIENT_ID=your_client_id
CLIENT_SECRET=your_client_secret
APP_SECRET_KEY=your_app_secret_key
WEBEX_ROOM_ID=your_webex_room_id
SCOPE=spark:all,spark-admin:xsi,spark:xsi,spark-admin:locations_read,spark-admin:people_read,spark-admin:licenses_read
PUBLIC_URL=FLASK_ENDPOINT_URL
AUTHORIZATION_BASE_URL=https://api.ciscospark.com/v1/authorize
TOKEN_URL=https://api.ciscospark.com/v1/access_token
TIMESPAN_IN_SECONDS=your_allowance_for_call_duration_in_seconds
```
Ensure that the TIMESPAN_IN_SECONDS parameter is adjusted based on your application's requirements.

## Installation/Configuration

1. **Clone the Repository**: 
   - Execute the command `git clone URL` to clone the repository to your local machine.

2. **Set Up a Python Virtual Environment**: 
   - **Ensure Python 3 is Installed**: If not, [download Python here](https://www.python.org/downloads/).
   - **Activate the Virtual Environment**: Follow the [instructions here](https://docs.python.org/3/tutorial/venv.html) to set up and activate the virtual environment.

3. **Configure Environment Variables**: 
   - Set up your `.env` file as per the instructions provided in the prerequisites section.

4. **Install Dependencies**: 
   - Run the command `pip3 install -r requirements.txt` to install all the required packages for the project.



## Usage
To run the program, use the command:
```shell
docker-compose up --build
```

After exiting program:
```shell
docker-compose down
```


### Additional Info
* Webex Interaction: This application specifically tracks 'answered' and 'released' call events, and displays them using an adaptive card format for better clarity and user interaction. Doe more info: https://developer.webex.com/buttons-and-cards-designer
* Rich is used for terminal logging to enhance the output.
* A flask dashboard showing Call statistics is displayed at PUBLIC_URL/success

# Screenshots
**High-level design:**

**Console Output:**
![/IMAGES/cm_console1.png](/IMAGES/cm_console1.png) <br>
![/IMAGES/cm_console2.png](/IMAGES/cm_console2.png) <br>
![/IMAGES/cm_console3.png](/IMAGES/cm_console3.png) <br>
![/IMAGES/cm_console4.png](/IMAGES/cm_console4.png) <br>
![/IMAGES/cm_console5.png](/IMAGES/cm_console5.png) <br><br>
![/IMAGES/0image.png](/IMAGES/0image.png)

### LICENSE

Provided under Cisco Sample Code License, for details see [LICENSE](LICENSE.md)

### CODE_OF_CONDUCT

Our code of conduct is available [here](CODE_OF_CONDUCT.md)

### CONTRIBUTING

See our contributing guidelines [here](CONTRIBUTING.md)

#### DISCLAIMER:
<b>Please note:</b> This script is meant for demo purposes only. All tools/ scripts in this repo are released for use "AS IS" without any warranties of any kind, including, but not limited to their installation, use, or performance. Any use of these scripts and tools is at your own risk. There is no guarantee that they have been through thorough testing in a comparable environment and we are not responsible for any damage or data loss incurred with their use.
You are responsible for reviewing and testing any scripts you run thoroughly before use in any non-testing environment.
