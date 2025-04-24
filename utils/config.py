from dotenv import load_dotenv
import os

# 加载 .env 文件中的内容
load_dotenv()

# 读取 API Key
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY")

# 可选：校验
if not GOOGLE_API_KEY:
    raise ValueError("GOOGLE_API_KEY is missing in .env")

if not DASHSCOPE_API_KEY:
    raise ValueError("DASHSCOPE_API_KEY is missing in .env")