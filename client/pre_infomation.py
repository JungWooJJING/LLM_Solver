from openai import OpenAI
from templates.prompting import CTFSolvePrompt

class PreInformationClient:
    def __init__(self, api_key: str, model: str = "gpt-5"):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def ask_PreInformation(self, title: str, description: str, category: str):
        user_prompt = self.build_prompt(title, description, category)

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "developer", "content": CTFSolvePrompt.pre_information_prompt},
                    {"role": "user", "content": user_prompt}
                ],
            )
            return response.choices[0].message.content
        except Exception as e:
            raise RuntimeError(f"Failed to get response from LLM: {e}")

    def build_prompt(self, title: str, description: str, category: str):
        return (
            f"Title: {title.strip()}\n"
            f"Category: {category.strip()}\n"
            f"Description:\n{description.strip()}\n"
        )
        