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
    #data = data[:3]
    filtered_cves = list(zip(data['CVE_ID'], data['NVD'], data['CWE']))
    all_docs_summary_hyperlinks = []
    all_docs_mitigation_hyperlinks = []
    for CVE_ID, NVD_URL, CWE_URL in filtered_cves:
        specific_cve_data = data[data['CVE_ID'] == CVE_ID]
        
        cot_prompt_summary = ChatPromptTemplate.from_template(
        """You are a cybersecurity expert. Your task is to analyze the provided URL content for the {CVE} and provide a detailed summary.

        ----------------------
        Content: {content}
        ----------------------  

        Please follow the steps below:

        Step 1: Assess Relevancy
        - Does the content provide relevant information to describe how this vulnerability can be exploited?
        - Answer: [Yes/No]

        Step 2: Summarize Relevant Information
        - If the answer is "Yes" in Step 1:
            - Summarize the content with step-by-step description to exploit this vulnerability.
        - If the answer is "No" in Step 1:
            - Summary: NONE
        
        """
    )

        cot_prompt_mitigation = ChatPromptTemplate.from_template(
        """You are a cybersecurity expert. Your task is to analyze the provided URL content for the {CVE} and provide a detailed summary.

        ----------------------
        Content: {content}
        ----------------------  

        Please follow the steps below:

        Step 1: Assess Relevancy
        - Does the content provide relevant information to describe the recommended mitigation strategies for this vulnerability?
        - Answer: [Yes/No]
      
        Step 2: Summarize Relevant Information
        - If the answer is "Yes" in Step 1:
            - Summarize the content to describe the recommended mitigation strategies for this vulnerability.
        - If the answer is "No" in Step 1:
            - Summary: NONE
        
        """
    )
        hyperlinks = specific_cve_data['hyperlinks'].apply(lambda x: x.split(',') if pd.notna(x) else []).tolist()
        flattened_hyperlinks = [url for sublist in hyperlinks for url in sublist]
        NVD_URL = [NVD_URL]
        CWE_URL = [CWE_URL]
        #AQUA_URL = [AQUA_URL]
        all_urls = NVD_URL + CWE_URL + flattened_hyperlinks
        docs_hyperlinks = []
        docs_files_summary = []
        docs_files_mitigation = []
        tagging_chain_hyper_summary = cot_prompt_summary | model 
        tagging_chain_hyper_mitigation = cot_prompt_mitigation | model 
        for link in all_urls:
            try:
                loader = WebBaseLoader(link)
                documents = loader.load()
                doc = documents[0]
                page_content_hyperlink = doc.page_content
                delay = random.randint(1, 2)
                time.sleep(delay)
                hyper_res_sum = tagging_chain_hyper_summary.invoke({"CVE": CVE_ID, "content": page_content_hyperlink})
                print(hyper_res_sum)
                print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
                delay = random.randint(1, 2)
                time.sleep(delay)
                hyper_res_mit = tagging_chain_hyper_mitigation.invoke({"CVE": CVE_ID, "content": page_content_hyperlink})
                print(hyper_res_mit)
                docs_files_summary.append(hyper_res_sum)
                docs_files_mitigation.append(hyper_res_mit)
            except Exception as e:
                print(f"Error loading {link}: {e}")
                continue
        
        

        print('\n')
        all_docs_summary_hyperlinks.append(docs_files_summary)
        all_docs_mitigation_hyperlinks.append(docs_files_mitigation)



    # Convert all_docs_summary_hyperlinks to a DataFrame and save to CSV
    df_summary_links = pd.DataFrame(all_docs_summary_hyperlinks)
    df_summary_links.to_csv("llama31_docs_exploitation_hyperlinks.csv", index=False)

    # Convert all_docs_mitigation_hyperlinks to a DataFrame and save to CSV
    df_mitigation_links = pd.DataFrame(all_docs_mitigation_hyperlinks)
    df_mitigation_links.to_csv("llama31_docs_mitigation_hyperlinks.csv", index=False)