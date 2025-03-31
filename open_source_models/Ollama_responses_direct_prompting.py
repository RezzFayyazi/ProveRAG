from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama.llms import OllamaLLM
from langchain.document_loaders import WebBaseLoader
import pandas as pd
import random
import time

if __name__ == "__main__":
    data = pd.read_csv('./data/cve_2024_critical_hyper.csv')
    model = OllamaLLM(model="llama3.1")
    all_responses = []
    filtered_cves = list(zip(data['CVE_ID'], data['NVD'], data['CWE']))
    all_docs_summary_hyperlinks = []
    all_docs_mitigation_hyperlinks = []
    for i, (CVE_ID, NVD_URL, CWE_URL) in enumerate(filtered_cves):

        main_prompt = ChatPromptTemplate.from_template(
            """
            You are a cybersecurity expert.

            
            Query: CVE-ID: {CVE}
            Given the specified CVE-ID, please provide detailed answers to the following questions:

            1. How can an attacker exploit this vulnerability? Provide a step-by-step description.
         
            2. What are the recommended mitigation strategies for this vulnerability?

            """
        )

        tagging_chain = main_prompt | model
        main_res = tagging_chain.invoke({"CVE": CVE_ID})
        print(main_res)
        print('\n')
        all_responses.append(main_res)  # Step 2: Append the response to the list

    # Convert all_responses to a DataFrame and save to CSV
    df_responses = pd.DataFrame(all_responses)
    df_responses.to_csv("all_responses_llama31_prompt_only.csv", index=False)