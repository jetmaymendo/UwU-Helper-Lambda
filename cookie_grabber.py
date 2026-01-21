from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from dotenv import load_dotenv
import os
import time
import boto3

# Load environment variables from .env file
load_dotenv()

# Initialize AWS Secrets Manager client
client = boto3.client("secretsmanager", region_name="us-east-1")

# Initialize WebDriver and open website
driver = webdriver.Chrome()
driver.get("https://empyrion-homeworld.net/re/hws-connect.html")

# Wait for the page to load and click the Steam Login button
for attempt in range(10):
    try:
        steam_button = driver.find_element(by=By.CLASS_NAME, value = "steam-login")
        # Not sure why but button gets restarted on startup and it sometimes messes click(). 
        # Waiting here makes sure, that restarted button would get stale and click() would lead to except
        time.sleep(0.5) 
        steam_button.click() 
        break
    except:
        print(f"Attempt {attempt + 1} failed, retrying...")

# Grab credentials from environment variables
login = os.environ.get("LOG", "none")
password = os.environ.get("PASS", "none")

# Wait for the page to be loaded and fill in the login
login_textbox = WebDriverWait(driver, 10).until(
    EC.element_to_be_clickable((By.XPATH, "//input[@type='text']"))
)
login_textbox.send_keys(login)

# Fill in the password
password_textbox = driver.find_element(by=By.XPATH, value = "//input[@type='password']")
password_textbox.send_keys(password)

# Click Login button
submit_button = driver.find_element(by=By.XPATH, value = "//button[@type='submit']")
submit_button.click()

# Wait for the final login button to be clickable and click it
final_login = WebDriverWait(driver, 120).until(
    EC.element_to_be_clickable((By.ID, "imageLogin"))
)
final_login.click()

# Wait for HWS Connect page to load
WebDriverWait(driver, 120).until(
    EC.element_to_be_clickable((By.CLASS_NAME, "p-ok"))
)

# Get the new PHPSESSID cookie and update AWS Secrets Manager
new_session_id = driver.get_cookie("PHPSESSID")
client.update_secret(
        SecretId="PHP-Session-ID",
        SecretString="""{"PHP_SESSION_ID":"%s"}""" % new_session_id['value'],
)

# Close the browser
driver.quit()
