import os
import logging
import rich.logging
from rich.table import Table
from rich import print as rprint
from rich.console import Console
from rich.text import Text
import requests
import wxcadm
import time
import threading
import queue
from dotenv import load_dotenv
import base64

# Load environment variables from .env file
load_dotenv()

GLOBAL_LOG_CONTROL = True  # Used to control the logging level globally
GLOBAL_LOG_LEVEL = logging.INFO  # default value


class EnvironmentManager:
    """
    The EnvironmentManager class is responsible for loading and validating the necessary environment variables
    that the application relies on.

    Attributes:
        CLIENT_ID (str): Client ID retrieved from the environment, corresponding to the Webex Integration.
        CLIENT_SECRET (str): Client Secret retrieved from the environment, specific to the Webex Integration.
        APP_SECRET_KEY (str): A secret key for Flask app session management.
        WEBEX_ROOM_ID (str): ID for the Webex room. The broader application context might use this for sending logs or messages.
        SCOPE (list): A list of scopes from the environment variable.
        PUBLIC_URL (str): Public URL retrieved from the environment.
        REDIRECT_URI (str): Constructed using the fetched PUBLIC_URL.
        AUTHORIZATION_BASE_URL (str): Authorization base URL retrieved from the environment.
        TOKEN_URL (str): Token URL retrieved from the environment.

    Methods:
        validate_env_variables() - Validates that all required environment variables are set,
                                   ignoring attributes related to the class internals or the os module.
    """

    CLIENT_ID = os.getenv('CLIENT_ID')
    CLIENT_SECRET = os.getenv('CLIENT_SECRET')
    APP_SECRET_KEY = os.getenv('APP_SECRET_KEY')
    WEBEX_ROOM_ID = os.getenv('WEBEX_ROOM_ID')
    SCOPE = os.getenv('SCOPE').split(',') if os.getenv('SCOPE') else []
    PUBLIC_URL = os.getenv('PUBLIC_URL')
    REDIRECT_URI = PUBLIC_URL + '/callback' if PUBLIC_URL else None
    AUTHORIZATION_BASE_URL = os.getenv('AUTHORIZATION_BASE_URL')
    TOKEN_URL = os.getenv('TOKEN_URL')
    try:
        TIMESPAN_IN_SECONDS = int(os.getenv('TIMESPAN_IN_SECONDS', '600'))
    except ValueError:
        TIMESPAN_IN_SECONDS = 600  # Default to 600 seconds (10 min) if left blank or if value is invalid

    @classmethod
    def validate_env_variables(cls):
        missing_vars = []
        console = Console()  # Instantiate a console object for rich

        table = Table(title="Environment Variables")
        table.add_column("Variable", justify="left", style="bright_white", width=30)
        table.add_column("Value", style="bright_white", width=50)

        for var_name, var_value in cls.__dict__.items():
            if "os" in var_name or "__" in var_name or isinstance(var_value, classmethod):  # ignore class documentation & methods
                continue
            table.add_row(var_name, str(var_value) if var_value is not None else "Not Set")
            if var_value in ("", None) and var_name != "TIMESPAN_IN_SECONDS":  # Exclude TIMESPAN_IN_SECONDS from this check
                missing_vars.append(var_name)

        # Display the table
        console.print(table)

        if missing_vars:
            raise EnvironmentError(f"The following environment variables are not set: {', '.join(missing_vars)}")

        # Check TIMESPAN_IN_SECONDS separately since we always have a default
        if not (1 <= cls.TIMESPAN_IN_SECONDS <= 1800):  # 30 mins in seconds
            raise ValueError(f"TIMESPAN_IN_SECONDS value ({cls.TIMESPAN_IN_SECONDS}) out of range. Please correct timespan in .env file.")


class LoggerManager:
    """
    The LoggerManager class handles logging functionalities for the application. It provides custom logging setups and
    offers functionalities to log messages with varying severity, suppress logging temporarily, log exceptions, and
    present complex data (like nested JSON) in a flattened and readable manner.

    Attributes:
        logger (logging.Logger): Instance of the logger set up for the application.
        original_log_level (int): The original logging level set for the logger.
        console (Console): Instance of the Console object to display rich content in the terminal.

    Methods:
        __init__() - Initializes the logger with console and file handlers and sets up the log format.
        setup() - Configures and returns the logger with appropriate handlers and log format.
        log(message, level) - Logs a message with the specified logging level.
        exception(message) - Logs an exception along with a custom message.
        suppress_logging() - Temporarily suppresses the logger output by setting it to a level higher than CRITICAL.
        restore_logging() - Restores the logger to its original log level.
        flatten_json(y) - Recursively flattens nested dictionaries into a one-level deep dictionary with concatenated keys.
        log_flattened_event_data(event) - Logs the provided event data in a structured two-column table format after flattening.
    """

    def __init__(self):
        self.logger = self.setup()
        self.original_log_level = self.logger.level
        self.console = Console()

    def setup(self):
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        console_handler = rich.logging.RichHandler()
        console_handler.setFormatter(logging.Formatter(log_format))

        file_handler = logging.FileHandler("app.log", mode='a')
        file_handler.setFormatter(logging.Formatter(log_format))

        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)  # default log level
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

        return logger

    def log(self, message, level=logging.INFO):
        if level == logging.DEBUG:
            self.logger.debug(message)
        elif level == logging.INFO:
            self.logger.info(message)
        elif level == logging.WARNING:
            self.logger.warning(message)
        elif level == logging.ERROR:
            self.logger.error(message)
        elif level == logging.CRITICAL:
            self.logger.critical(message)
        else:
            self.logger.info(message)

    def exception(self, message):
        """Log an exception along with a custom message."""
        self.logger.exception(message)

    def suppress_logging(self):
        """Temporarily set logger to a higher level to suppress output."""
        self.logger.setLevel(logging.CRITICAL + 1)  # This level is higher than any standard log levels

    def restore_logging(self):
        """Restore logger to its original level."""
        self.logger.setLevel(self.original_log_level)

    def flatten_json(self, y):
        """Recursively flatten nested dictionaries."""
        out = {}

        def flatten(x, name=''):
            if type(x) is dict:
                for a in x:
                    flatten(x[a], name + a + '.')
            else:
                out[name[:-1]] = x

        flatten(y)
        return out

    def log_flattened_event_data(self, event):
        """Log individual event data in a two-column table: Key, Value."""

        # Suppress any other logging for now
        self.suppress_logging()

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Key", width=100)
        table.add_column("Value", width=50)

        flattened_data = self.flatten_json(event)

        # Check for the access_token dictionary and handle it specially
        if "Token" in flattened_data:
            access_token_data = eval(flattened_data["Token"])  # Convert string representation back to dictionary
            for key, value in access_token_data.items():
                table.add_row("Token." + key, str(value))
            del flattened_data["Token"]  # Remove it from the flattened_data since we've handled it

        for key, value in flattened_data.items():
            table.add_row(key, str(value))

        rprint(table)

        # Restore logging level after table is printed
        self.restore_logging()


logger_manager = LoggerManager()  # Instantiate custom logger

# Global counters to maintain the number of answered and released calls
answered_calls_count = 0
released_calls_count = 0


def get_answered_calls_count():
    """ Retrieves the count of answered calls (int). """
    return answered_calls_count


def get_released_calls_count():
    """ Retrieves the count of released calls (int). """
    return released_calls_count


def image_to_base64(image_path):
    """
    Converts an image at the provided path to a base64 encoded string.
    Args:
        image_path (str): The path to the image file.
    Returns:
        str: The base64 encoded string of the image in PNG format.
    """
    with open(image_path, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read()).decode()
    return f"data:image/png;base64,{encoded_string}"


def strip_repetitive_prefixes(key):
    """
    Removes repetitive prefixes from the provided key string. It is particularly useful
    for cleaning up XML-derived JSON keys.
    Args:
        key (str): The input string that may contain repetitive prefixes.
    Returns:
        str: The cleaned-up key without the repetitive prefixes.
    """
    prefixes = [
        "xsi:Event.@xsi1:",
        "xsi:Event.@xmlns:",
        "xsi:Event.xsi:eventData.@xsi1:",
        "xsi:Event.xsi:eventData.xsi:call.xsi:releaseCause.xsi:",
        "xsi:Event.xsi:eventData.xsi:call.xsi:endpoint.@xsi1:",
        "xsi:Event.xsi:eventData.xsi:call.xsi:remoteParty.xsi:",
        "xsi:eventData.xsi.call.xsi",
        "xsi:Event.xsi:eventData.xsi:call.xsi:endpoint.xsi:",
        "xsi:Event.xsi:eventData.xsi:call.xsi:",
        "xsi:Event.xsi:",

    ]
    for prefix in prefixes:
        if key.startswith(prefix):
            key = key[len(prefix):]
    return key


def generate_adaptive_card_payload(event_name, flattened_data):
    """
    Generates the payload for an adaptive card based on the provided event name and data. The adaptive card
    is structured to display event information in a visually appealing manner.

    Args:
        event_name (str): The name of the event (e.g., 'answered', 'released').
        flattened_data (dict): A dictionary containing event data with flat keys (i.e., no nested structures).

    Returns:
        dict: A dictionary representing the adaptive card payload.
    """
    # Decide the event text based on the event name
    event_text = "Call Answered Event" if event_name == "answered" else "Call Released Event"

    webex_logo = image_to_base64("static/images/webex_logo.png")
    link_icon = image_to_base64("static/images/link_icon.png")

    # Generate key-value pairs for the card content after stripping unnecessary prefixes
    cleaned_keys = [strip_repetitive_prefixes(key) for key in flattened_data.keys()]

    # Create the key-value pairs inside their own ColumnSets to ensure accuracy
    data_columns = []
    for key, value in zip(cleaned_keys, flattened_data.values()):
        key_block = {"type": "TextBlock", "text": key, "color": "Light"}
        value_block = {"type": "TextBlock", "text": value, "color": "Light", "weight": "Lighter", "spacing": "Small"}

        column_set = {
            "type": "ColumnSet",
            "columns": [
                {"type": "Column", "width": 35, "items": [key_block]},
                {"type": "Column", "width": 90, "items": [value_block]}
            ]
        }
        data_columns.append(column_set)

    # Base card template
    card_payload = {
        "type": "AdaptiveCard",
        "body": [
            {
                "type": "ColumnSet",
                "columns": [
                    {
                        "type": "Column",
                        "items": [
                            {
                                "type": "Image",
                                "style": "Person",
                                "url": webex_logo,  # Using a base64 string to use local images
                                "size": "Medium",
                                "height": "50px"
                            }
                        ],
                        "width": "auto"
                    },
                    {
                        "type": "Column",
                        "items": [
                            {
                                "type": "TextBlock",
                                "text": "Webex Call Monitoring and Disconnect App",
                                "weight": "Lighter",
                                "color": "Accent"
                            },
                            {
                                "type": "TextBlock",
                                "weight": "Bolder",
                                "text": event_text,  # This is dynamic
                                "horizontalAlignment": "Left",
                                "wrap": True,
                                "color": "Light",
                                "size": "Large",
                                "spacing": "Small"
                            }
                        ],
                        "width": "stretch"
                    }
                ]
            },
            *data_columns,  # Unpack the data_columns directly into the body of the card
            {
                "type": "ColumnSet",
                "columns": [
                    {
                        "type": "Column",
                        "width": "auto",
                        "items": [
                            {
                                "type": "Image",
                                "altText": "",
                                "url": link_icon,
                                "size": "Small",
                                "width": "30px"
                            }
                        ],
                        "spacing": "Small"
                    },
                    {
                        "type": "Column",
                        "width": "auto",
                        "items": [
                            {
                                "type": "TextBlock",
                                "text": "[Call Statistics Dashboard](http://127.0.0.1:9001/success)",
                                "horizontalAlignment": "Left",
                                "size": "Medium"
                            }
                        ],
                        "verticalContentAlignment": "Center",
                        "horizontalAlignment": "Left",
                        "spacing": "Small"
                    }
                ]
            }
        ],
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.3"
    }

    return card_payload


class CallMonitor:
    """
    The CallMonitor class handles the monitoring of calls for the Webex organization. It initializes and maintains
    a mapping between Webex users and their corresponding call sessions and tracks active and ended calls.

    Methods:
        get_email_by_user_id(user_id) - Fetches the email associated with a given Webex user ID.
        register_call(call_id, user_id) - Associates a call ID with a specific user ID.
        monitor_calls(events_queue) - Continuously monitors and processes incoming call events.
        handle_call_released_event(event_data) - Processes and logs information about a call that was released.
        handle_answered_call(call_id, event_data) - Handles and logs information about an answered call.
        schedule_call_end(call_id) - Schedules a call to end after a certain time.
        end_call(call_id) - Attempts to end a call based on the provided call ID.
        setup_xsi_events() - Initializes the CallMonitor instance and starts the call monitoring process.
        send_info_to_webex_room(message) - Sends a specified message to a Webex room.
    """

    def __init__(self, access_token):
        """
        Initialize CallMonitor with given access token.
        Args:
            access_token (str): Webex API access token.
        """
        self.access_token = access_token
        self.webex = wxcadm.Webex(access_token, get_xsi=True, fast_mode=True)
        self.all_people = self.webex.org.get_people()

        self.xsi_user_map = {}  # Mapping of person ID to their display name and ID
        self.answered_calls = set()  # Track call IDs of answered calls
        self.call_to_user_map = {}  # Track / map call to user
        self.ended_call_ids = set()  # Track Call Ids of released calls

        # Initialize the xsi_user_map with users and their respective details.
        for person in self.all_people:
            person.start_xsi()
            person_id = person.id
            self.xsi_user_map[person_id] = {
                "display_name": person.display_name.lower(),
                "id": person_id,
            }
        logger_manager.logger.info(f"xsi_user_map initialized with {len(self.xsi_user_map)} users.")

    def setup_xsi_events(self):
        """ Initialize XSI events and set up a thread to monitor calls continuously. """
        console = Console()

        try:
            # Setting up XSI event listening.
            logger_manager.logger.debug("Initializing CallMonitor with provided access token.")

            events = wxcadm.XSIEvents(self.webex.org)
            events_queue = queue.Queue()
            channel = events.open_channel(events_queue)
            channel.subscribe("Advanced Call")

            # Starting a separate thread to monitor calls.
            logger_manager.logger.debug("Starting monitor thread.")
            monitor_thread = threading.Thread(target=self.monitor_calls, args=(events_queue,), daemon=True)  # Use self.monitor_calls
            monitor_thread.start()

            logger_manager.logger.info("Webex setup complete. Ready for calls.")
            message = Text("Call Monitoring has been started for the organization...", style="bold red")
            console.print("\n\n", Text("Call Monitoring has been started for the organization...", style="bold red"), "\n\n")


        except Exception as e:
            logger_manager.logger.exception("Failed to setup webex call monitoring: ", exc_info=e)

    def register_call(self, call_id, user_id):
        """
        Associate a given call_id with a user_id.
        Args:
            call_id (str): The unique ID of the call.
            user_id (str): The ID of the user.
        """
        logger_manager.logger.debug(f"Associating Call ID {call_id} with User ID {user_id}")
        self.call_to_user_map[call_id] = user_id

    def extract_event_details(self, event):
        """
        Extract essential details from the provided event.
        Args:
            event (dict): The event payload.
        Returns:
            dict: Extracted details.
        """
        try:
            event_details = {
                "event_type": event.get('xsi:Event', {}).get('xsi:eventData', {}).get('@xsi1:type'),
                "personality": event.get('xsi:Event', {}).get('xsi:eventData', {}).get('xsi:call', {}).get('xsi:personality'),
                "state": event.get('xsi:Event', {}).get('xsi:eventData', {}).get('xsi:call', {}).get('xsi:state'),
                "channelId": event.get('xsi:Event', {}).get('xsi:channelId'),
                "call_id": event.get('xsi:Event', {}).get('xsi:eventData', {}).get('xsi:call', {}).get('xsi:callId'),
                "remote_party_name": event.get('xsi:Event', {}).get('xsi:eventData', {}).get('xsi:call', {}).get('xsi:remoteParty', {}).get('xsi:name', '').lower()
            }
            return event_details
        except Exception as e:
            logger_manager.logger.error(f"Error extracting event details: {e}")
            return {}

    def process_event(self, event, event_details):
        """
        Process the extracted event details.
        Args:
            event (dict): The actual event payload.
            event_details (dict): Extracted event details.
        """
        global answered_calls_count
        global released_calls_count
        console = Console()

        # Handling CallReleasedEvent
        if event_details["event_type"] == 'xsi:CallReleasedEvent' and event_details["personality"] == 'Originator':
            self.ended_call_ids.add(event_details["call_id"])
            released_calls_count += 1
            self.handle_call_released_event(event)  # call the event handler for CallReleasedEvent
            logger_manager.logger.info(f"The call has been ended for Call ID: {event_details['call_id']}")
            call_id = event_details["call_id"]
            message = Text(f"The call has been ended for Call ID: {call_id}", style="bold red")
            console.print("\n\n")
            console.print(message)
            console.print("\n\n")

        # Handling CallAnsweredEvent
        if event_details["event_type"] == 'xsi:CallAnsweredEvent' and event_details["state"] == 'Active' and event_details["personality"] == 'Originator':
            logger_manager.logger.info(f"Extracted remote_party_name: {event_details['remote_party_name']}")
            answered_calls_count += 1
            self.handle_answered_call(event)
            matched_user_entry = next((entry for entry in self.xsi_user_map.values() if entry.get('display_name') == event_details["remote_party_name"]), None)

            if matched_user_entry:
                matched_user_entry['channelId'] = event_details["channelId"]
                matched_user_id = matched_user_entry.get('id')
                logger_manager.logger.info(f"Assigned channelId: {event_details['channelId']} to user_id: {matched_user_id}")
                logger_manager.logger.info(f"Registering call with call_id: {event_details['call_id']} and user_id: {matched_user_id}")
                self.register_call(event_details["call_id"], matched_user_id)
                self.schedule_call_end(event_details["call_id"])
            else:
                logger_manager.logger.debug(f"No matching user found for remote_party_name: {event_details['remote_party_name']}")

    def monitor_calls(self, events_queue):
        """
        Monitor all calls for the Webex organization.
        Args:
            events_queue (queue.Queue): The queue storing the events.
        """
        global answered_calls_count
        global released_calls_count
        logger_manager.logger.info("STARTING TO MONITOR ALL CALLS FOR YOUR WEBEX ORGANIZATION...")
        self.send_info_to_webex_room("The calls are now being monitored for the organization...")

        while True:  # Start an infinite loop to get the messages as they are placed in Queue
            try:
                event = events_queue.get()
                logger_manager.logger.debug(f"Received event from queue: {event}")
                # Extract event details and then process them
                event_details = self.extract_event_details(event)
                if event_details:
                    self.process_event(event, event_details)  # Fixed the call to include the event itself
                    time.sleep(2)
            except Exception as e:
                logger_manager.logger.error(f"Error in the monitoring loop: {e}")

    def handle_answered_call(self, event_data):
        """
        Handle actions upon receiving an answered call event.
        Args:
            event_data (dict): Event data payload.
        """
        try:
            flattened_data = logger_manager.flatten_json(event_data)

            card_payload = generate_adaptive_card_payload("answered", flattened_data)

            # Send the adaptive card to Webex room
            self.send_info_to_webex_room(card_payload)
        except Exception as e:
            logger_manager.logger.info(f"Error handling answered call event: {e}")

    def handle_call_released_event(self, event_data):
        """
        Handle actions upon receiving a call released event.
        Args:
            event_data (dict): Event data payload.
        """
        try:
            logger_manager.logger.debug("Handling call released event")

            flattened_data = logger_manager.flatten_json(event_data)

            logger_manager.log_flattened_event_data(flattened_data)  # Log event data in a table format

            # Check if the originator is 'originator'; if not, return early
            personality = flattened_data.get('xsi:Event.xsi:eventData.xsi:call.xsi:personality', '').lower()
            if personality != 'originator':
                logger_manager.logger.debug(f"Personality not 'originator'. Found: {personality}")
                return

            card_payload = generate_adaptive_card_payload("released", flattened_data)

            # Send the adaptive card to Webex room
            self.send_info_to_webex_room(card_payload)
        except Exception as e:
            logger_manager.logger.error(f"Error handling call released event: {e}")

    def schedule_call_end(self, call_id):
        """
        Schedule the end of a call after a fixed duration.
        Args:
            call_id (str): The unique ID of the call.
        """
        timer = threading.Timer(EnvironmentManager.TIMESPAN_IN_SECONDS, self.end_call, args=[call_id])
        timer.start()

    def end_call(self, call_id):
        """
        Attempt to end a call by its ID.
        Args:
            call_id (str): The unique ID of the call.
        """
        user_id = self.call_to_user_map.get(call_id)
        if not user_id:
            logger_manager.logger.error(f"No user ID found for Call ID: {call_id}")
            return

        logger_manager.logger.debug(f"Attempting to get person instance for user_id: {user_id}")
        person = self.webex.get_person_by_id(user_id)

        if person:
            active_calls = person.xsi.calls
            for call in active_calls:
                try:
                    call.hangup()
                    logger_manager.logger.info(f"Ended call with Call ID: {call.id}")
                except Exception as e:
                    logger_manager.logger.error(f"Failed to end the call with Call ID: {call.id}. Error: {e}")
        else:
            logger_manager.logger.debug(f"Attributes of person with Email {user_id}: {dir(person)}")
            logger_manager.logger.error(f"No person or active call instance found for user_id: {user_id}")

    def send_info_to_webex_room(self, message_or_payload):
        """
        Send a message or an adaptive card payload to a specific Webex room.
        Args:
            message_or_payload ([str, dict]): Either a plain message or an adaptive card payload.
        """
        url = "https://webexapis.com/v1/messages"
        headers = {
            'Authorization': f"Bearer {self.access_token}",
            'Content-Type': 'application/json'
        }
        # Determine if the input is a message string or an adaptive card payload
        if isinstance(message_or_payload, str):
            payload = {
                'roomId': EnvironmentManager.WEBEX_ROOM_ID,
                'text': message_or_payload
            }
        elif isinstance(message_or_payload, dict):
            payload = {
                'roomId': EnvironmentManager.WEBEX_ROOM_ID,
                'text': 'Event Message',  # Adding default text
                'attachments': [{
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": message_or_payload
                }]
            }

        else:
            logger_manager.logger.error("Unsupported message or payload format.")
            return
        response = requests.post(url, headers=headers, json=payload)
        # Check if response has a JSON body, to prevent potential errors when calling response.json()

        if response.status_code in [200, 201, 202]:
            logger_manager.logger.info("Message successfully sent to Webex room.")
        else:
            logger_manager.logger.error(f"Error sending message to Webex room. Status Code: {response.status_code}. Response: {response.text}")

            # Handling specific error codes (if required)
            if response.status_code == 400:  # Bad Request
                logger_manager.logger.error("Check the request payload. Maybe missing required fields.")
            elif response.status_code == 401:  # Unauthorized
                logger_manager.logger.error("Invalid or expired access token.")
            elif response.status_code == 403:  # Forbidden
                logger_manager.logger.error("The authenticated user doesn't have access to the requested resource.")
            elif response.status_code == 404:  # Not Found
                logger_manager.logger.error("Requested resource (like room) not found.")
            elif response.status_code == 429:  # Too Many Requests
                logger_manager.logger.error("Rate limit exceeded.")
