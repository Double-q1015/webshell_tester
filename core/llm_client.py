import os
import openai
import google.generativeai as genai
from dashscope import Generation
from typing import Literal
from utils.config import GOOGLE_API_KEY, DASHSCOPE_API_KEY

SupportedProvider = Literal["openai", "gemini", "qwen"]

class LLMClient:
    def __init__(self, provider: SupportedProvider = "openai", api_key: str = None):
        self.provider = provider
        self.api_key = api_key or os.getenv("LLM_API_KEY")

        if self.provider == "openai":
            openai.api_key = self.api_key
        elif self.provider == "gemini":            
            genai.configure(api_key=self.api_key)
            self.genai = genai
        elif self.provider == "qwen":
            
            self.qwen = Generation
        else:
            raise ValueError(f"不支持的 LLM 提供商: {self.provider}")

    def chat(self, messages: list[dict[str, str]], model: str = None) -> str:
        if self.provider == "openai":
            response = openai.ChatCompletion.create(
                model=model or "gpt-3.5-turbo",
                messages=messages
            )
            return response.choices[0].message.content.strip()

        elif self.provider == "gemini":
            model = self.genai.GenerativeModel(model or "gemini-pro")
            convo = model.start_chat()
            for m in messages:
                if m["role"] == "user":
                    convo.send_message(m["content"])
            return convo.last.text.strip()

        elif self.provider == "qwen":
            response = self.qwen.call(
                model=model or "qwen-turbo",
                messages=messages
            )
            return response.output.choices[0].message.content.strip()

        else:
            raise ValueError("未知的 LLM 提供商")
