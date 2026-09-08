from openai import OpenAI


client = OpenAI(base_url="http://localhost:8080/v1", api_key="not-used-by-lsdf")

response = client.chat.completions.create(
    model="local-model",
    messages=[{"role": "user", "content": "Summarize this customer note."}],
)
print(response.choices[0].message.content)
