import json
from langchain.prompts import ChatPromptTemplate
from langchain.chat_models import ChatOpenAI
from langchain.schema.output_parser import StrOutputParser
from langchain.output_parsers.openai_functions import JsonOutputFunctionsParser
from pydantic import BaseModel, Field
from langchain.utils.openai_functions import convert_pydantic_to_openai_function
import warnings
import pandas as pd
from langchain.vectorstores import FAISS


# Ignore all warnings
warnings.filterwarnings("ignore")


class Overview(BaseModel):
    """Overview of a section of text."""
    id: str = Field(description="The CVE-ID of the vulnerability.")
    cvss: str = Field(description="The CVSS score of the vulnerability.")
    summary: str = Field(description="High-level overview and a step-by-step description of the procedure.")
    mitigation: str = Field(description="Detailed mitigation strategies for the vunlerability.")

if __name__ == "__main__":
    data = pd.read_csv('./data/cve_2024_critical_hyper.csv')
    openai_api_key = "YOUR_API_KEY"  # Replace with your OpenAI API key
    model_name = "gpt-4o-mini"

    model = ChatOpenAI(api_key=openai_api_key, model=model_name, temperature=0.0)
    output_parser = StrOutputParser()


    CVE_IDs = data['CVE_ID'].values
    all_responses = []
    for CVE_ID in CVE_IDs:
        overview_tagging_function = [
            convert_pydantic_to_openai_function(Overview)
        ]
        main_prompt = ChatPromptTemplate.from_template(
            """You are a cybersecurity expert.

            Query: CVE-ID: {CVE}
            Given the specified CVE-ID, please provide detailed answers to the following questions:

            1. How can an attacker exploit this vulnerability? Provide a step-by-step description.
           
            2. What are the recommended mitigation strategies for this vulnerability?

            """
        )
        tagging_model = model.bind(
            functions=overview_tagging_function,
            function_call={"name": "Overview"}
        )
        tagging_chain = main_prompt | tagging_model | JsonOutputFunctionsParser()
        main_res = tagging_chain.invoke({"CVE": CVE_ID})
        print(main_res)


        all_responses.append(main_res) 

    with open(f'./results/prompt_only.json', 'w') as f:
        json.dump(all_responses, f, indent=4)





