from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama.llms import OllamaLLM
from langchain.document_loaders import WebBaseLoader
import pandas as pd
import random
import time

if __name__ == "__main__":
    data = pd.read_csv('./data/cve_2024_critical_hyper.csv')
    data_exploitation = pd.read_csv('./llama31_docs_exploitation_hyperlinks_postprocessed.csv')
    data_mitigation = pd.read_csv('./llama31_docs_mitigation_hyperlinks_postprocessed.csv')
    model = OllamaLLM(model="llama3.1")
    all_summaries = []

    #data = data[:3]
    all_responses = []
    filtered_cves = list(zip(data['CVE_ID'], data['NVD'], data['CWE']))
    all_docs_summary_hyperlinks = []
    all_docs_mitigation_hyperlinks = []
    for i, (CVE_ID, NVD_URL, CWE_URL) in enumerate(filtered_cves):
        all_summaries = []
        specific_cve_data = data[data['CVE_ID'] == CVE_ID]

        exploitation_data = data_exploitation.iloc[i].values
        mitigation_data = data_mitigation.iloc[i].values
        
        # Remove NaN values from the arrays
        exploitation_data = [x for x in exploitation_data if pd.notna(x)]
        mitigation_data = [x for x in mitigation_data if pd.notna(x)]
        
        all_summaries.extend([exploitation_data, mitigation_data])
        print(all_summaries)

        main_prompt = ChatPromptTemplate.from_template(
            """You are a cybersecurity expert. Consider the Relevant Information provided below and answer the Query.

        --------------------------
            Relevant Information: {context}
        --------------------------  

            Query: CVE-ID: {CVE}
            Given the specified CVE-ID, please provide detailed answers to the following questions:

            1. How can an attacker exploit this vulnerability? Provide a step-by-step description.
         
            2. What are the recommended mitigation strategies for this vulnerability?

            """
        )


        tagging_chain = main_prompt | model
        main_res = tagging_chain.invoke({"CVE": CVE_ID, "context": all_summaries})
        print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
        print(main_res)
        print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
        print('\n')
        all_responses.append(main_res)  # Step 2: Append the response to the list

    # Convert all_responses to a DataFrame and save to CSV
    df_responses = pd.DataFrame(all_responses)
    df_responses.to_csv("all_responses.csv", index=False)