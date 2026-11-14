import os

from anthropic import Anthropic
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
claude = Anthropic()  # reads ANTHROPIC_API_KEY from the environment


def ask(prompt: str) -> str:
    return client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}]).choices[0].message.content
