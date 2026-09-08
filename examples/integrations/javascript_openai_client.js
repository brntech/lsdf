import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://localhost:8080/v1",
  apiKey: "not-used-by-lsdf",
});

const response = await client.chat.completions.create({
  model: "local-model",
  messages: [{ role: "user", content: "Summarize this customer note." }],
});

console.log(response.choices[0].message.content);
