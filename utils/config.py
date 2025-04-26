from dotenv import load_dotenv
import os

# load .env file
load_dotenv()

# read API Key
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY")

# optional: check API Key
if not GOOGLE_API_KEY:
    raise ValueError("GOOGLE_API_KEY is missing in .env")

if not DASHSCOPE_API_KEY:
    raise ValueError("DASHSCOPE_API_KEY is missing in .env")