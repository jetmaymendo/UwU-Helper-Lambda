import requests
import json
import boto3
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

# Get secret values from AWS secret manager
client = boto3.client("secretsmanager", region_name="us-east-1")

# Get Discord Token
secret = client.get_secret_value(SecretId="Discord-Token")
TOKEN = json.loads(secret["SecretString"])["DISCORD_TOKEN"]

# Get Discord Public Key
secret = client.get_secret_value(SecretId="Discord-Public-Key")
PUBLIC_KEY = json.loads(secret["SecretString"])["DISCORD_PUBLIC_KEY"]

# Get PHP Session ID
secret = client.get_secret_value(SecretId="PHP-Session-ID")
SESSION_ID = json.loads(secret["SecretString"])["PHP_SESSION_ID"]

# Get player table from DynamoDB
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table('UwUHelper_HunterBoardLocations')

PvP_Playfields = ["Phoenix", 
                  "Black Hole", 
                  "Golden Globe",
                  "Golden Sphere Mission",
                  "Eton",
                  "Armageddon",
                  "Homeworld PvP System [Sun Right]",
                  "Homeworld PvP System [Sun Left]",
                  "Homeworld PvP System [Sun Up]",
                  "Homeworld PvP System [Sun Bottom]",
                  "Homeworld PvP System [Sun Front]",
                  "Homeworld PvP System [Sun Back]"]

PvP_Message = ""

# Append message to PvP_Message
def add_message(Player_Name, Playfield_Name):
    message = f"Player {Player_Name} has entered {Playfield_Name}!\n "
    global PvP_Message
    PvP_Message += message

# Send message to specific channel as a bot
def send_message_to_channel(channelId, message):
    url = f"https://discord.com/api/channels/{channelId}/messages"
    headers = {"Authorization": f"Bot {TOKEN}",
            "Content-Type": "application/json"}
    data = {"content": message}
    requests.post(url, json=data, headers=headers)

def region_update(Data, Region_Name):
    for player in Data[Region_Name]["hunterBoard"]:
        # Check if player is in PvP area
        if player["Playfield"] in PvP_Playfields:
            # Try getting players old location
            value = table.get_item(Key={"Server": Region_Name, "PlayerName": player["Name"]})
            if "Item" in value:
                old_location = value.get('Item').get('Location')
                # Check if player switched locations
                if old_location != player["Playfield"]:
                    add_message(player["Name"], player["Playfield"])
            # Player was not in database
            else:
                add_message(player["Name"], player["Playfield"])
        table.put_item(Item={'Server': Region_Name,'PlayerName': player["Name"],'Location': player["Playfield"]})
       

def main_tick():
    resp = requests.get("https://empyrion-homeworld.net/re/hws-connect/api/user.php?onlinePlayers", cookies={"PHPSESSID": SESSION_ID})
    json_data = resp.json()
    # Check for error in response
    if "error" in json_data:
        print("Wrong Session ID")
        return

    global PvP_Message

    # Update EU
    PvP_Message = ""
    region_update(json_data, "re")
    if PvP_Message:
        send_message_to_channel(1434584925163491469, PvP_Message)
        print(f"EU {PvP_Message}")

    # Update NA
    PvP_Message = ""
    region_update(json_data, "rn")
    if PvP_Message:
        send_message_to_channel(1434585294144929913, PvP_Message)
        print(f"NA {PvP_Message}")


# Verify Signature for requests coming from discord
def verify_signature(event):
    raw_body = event.get("rawBody")
    auth_sig = event['params']['header'].get('x-signature-ed25519')
    auth_ts  = event['params']['header'].get('x-signature-timestamp')    
    message = auth_ts.encode() + raw_body.encode()
    verify_key = VerifyKey(bytes.fromhex(PUBLIC_KEY))
    verify_key.verify(message, bytes.fromhex(auth_sig)) # raises an error if unequal


# Main Lambda function
def lambda_handler(event, context):

    print(f"event {event}") # debug print    
    body = event.get('body-json')

    # Check if it's schedule request
    if body.get("type") == 69:
        main_tick()
        return {"type": 69}

    # Verify the signature
    try:
        verify_signature(event)
    except Exception as e:
        raise Exception(f"[UNAUTHORIZED] Invalid request signature: {e}")

    # Confirm Verification
    print("Signature verified")

    # Check if message is a ping
    if body.get("type") == 1:
        print("Ping Pong")
        return {"type": 1}

    # Check specific command
    data = body.get("data")
    commandName = data.get("name")
    if commandName == "update":
        print("Command: Update")
        return {"type": 4,
                "data": {"content": "UPDATE (will be implemented some day UwU)"}}
    elif commandName == "echo":
        echo = data["options"][0]["value"]
        print(f"Echo: {echo}")
        return {"type": 4,
                "data": {"content": f"Echoed message: {echo}"}}


    return {"type": 1}
