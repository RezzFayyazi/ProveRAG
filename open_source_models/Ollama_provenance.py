from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama.llms import OllamaLLM
from langchain.document_loaders import WebBaseLoader
import pandas as pd
import random
import time
from langchain_ollama import OllamaEmbeddings
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.vectorstores import FAISS
import json

if __name__ == "__main__":
    data = pd.read_csv('./data/cve_2024_critical_hyper.csv')
    type_eval = 'mitigation'
    responses = pd.read_csv('./all_responses.csv')


    response = responses['mitigation'].values
    data_exploitation = pd.read_csv('./llama31_docs_exploitation_hyperlinks_postprocessed.csv')
    #data_exploitation = data_exploitation[240:]
    data_mitigation = pd.read_csv('./llama31_docs_mitigation_hyperlinks_postprocessed.csv')
    #data_mitigation = data_mitigation[240:]
    model = OllamaLLM(model="llama3.1")
    embeddings = OllamaEmbeddings(model="llama3.1")
    all_final_docs = []
    filtered_cves = list(zip(data['CVE_ID'], data['NVD'], data['CWE']))
    all_docs_summary_hyperlinks = []
    all_docs_mitigation_hyperlinks = []
    final_res = dict()
    for i, (CVE_ID, NVD_URL, CWE_URL) in enumerate(filtered_cves):
        specific_cve_data = data[data['CVE_ID'] == CVE_ID]

        # Convert the data into a pandas Series to easily identify non-NaN indices
        exploitation_data_series = pd.Series(data_exploitation.iloc[i].values)
        mitigation_data_series = pd.Series(data_mitigation.iloc[i].values)

        # Get indices of non-NaN values
        non_nan_indices_exploitation = exploitation_data_series[exploitation_data_series.notna()].index.tolist()
        non_nan_indices_mitigation = mitigation_data_series[mitigation_data_series.notna()].index.tolist()

        print(f"Non-NaN indices in exploitation_data: {non_nan_indices_exploitation}")
        print(f"Non-NaN indices in mitigation_data: {non_nan_indices_mitigation}")

        print('-------------------------------------------------')
        relevant_urls = []
        for relevant in non_nan_indices_mitigation:
            """
            if relevant == 0:
                nvd_url = specific_cve_data['NVD'].tolist()[0]
                relevant_urls.append(nvd_url)
            if relevant == 1:
                cwe_url = specific_cve_data['CWE'].tolist()[0]
                relevant_urls.append(cwe_url)
            """
            if relevant >= 2:
                hyperlinks = specific_cve_data['hyperlinks'].apply(lambda x: x.split(',') if pd.notna(x) else []).tolist()
                flattened_hyperlinks = [url for sublist in hyperlinks for url in sublist]
                relevant_urls.append(flattened_hyperlinks[relevant-2])
    
        print(relevant_urls)
        print("*************************************************")
        nvd_urls = specific_cve_data['NVD'].tolist()
        cwe_urls = specific_cve_data['CWE'].tolist()
        #source_url = [source_url]
        if relevant_urls != []:
            all_urls = nvd_urls + cwe_urls + relevant_urls
        else:
            all_urls = nvd_urls + cwe_urls
        all_urls = [url.strip() for url in all_urls]
        print(all_urls)
        prefix_prompt = f"""For the **{type_eval}** information of {CVE_ID}: 
        
        """

        provenance = f"""
        **value**:
            - Description: This attribute represents the accuracy of the response based on the provided context about the CVE-ID.

            - Allowed Values: 
                - 'TP' (True Positive): The response fully and accurately reflects the information in the context.
                - 'FP' (False Positive): The response contains inaccurate or incorrect information that are not supported by the context.
                - 'FN' (False Negative): The response omits information that is present in the context.

            - Requirements:
                - Must strictly be one of the allowed values: 'TP', 'FP', or 'FN'.
                - The selection must be based on an objective comparison between the response and the context.
                - Must follow the guidelines for **Provenance**.

                
        **Rationale**:
            - Description: This attribute provides the reasoning behind the selected **value** for the evaluation of the response.

            
        **Provenance**:
        - Detailed Instructions for Provenance based on the selected **value**:

            - If **value** is 'TP':
                1. Carefully compare the response with the context.
                2. Identify and extract the key segments from both the response and the context that align perfectly.
                3. Format the provenance as follows:
                    - `response: "[Extracted segment from the **response** that matches the **context**]".'
                    - `context: "[Corresponding segment from the **context**]".'

            - If **value** is 'FP':
                1. Review the response thoroughly to identify parts that are incorrect or not present in the context.
                2. Format the provenance as follows:
                    - `response: "[Incorrect or unsupported segment from the **response**]".'
                    - `context: "[The closest matching part from the **context**, or indicate 'No corresponding information in context' if none exists]".'

            - If **value** is 'FN':
                1. Examine the context to find essential information that is present but omitted in the response.
                2. Format the provenance as follows:
                    - `response: "[The entire **response**]".'
                    - `context: "[Relevant segment from the **context** that should have been matched]".'
            
            Guidelines:
                - In all cases, ensure the provenance provided is clear, concise, and directly supports the selected **value**.
                - The provenance should be an **exact match** or a **direct comparison** between the response and the context, following the formatting rules strictly.      
                
                
                
                
                """

        Answer_Correctness = """Given the **response** and the **context**: 
        
        -------------------------
        
        **response**: {response}

        -------------------------

        **context**: {context}

        -------------------------

        Output in the following format:

            "value": TP or FP or FN (ONLY ONE VALUE FOR THE ENTIRE RESPONSE)
            "rationale": [the **rationale** segment for the selected **value**]
            "provenance":
                    - `response: [extract the relevant segment from the **response** segment]'
                    - `context: [extract the relevant segment from the **context** segment]' 
        
        
        """

        main_p = provenance + prefix_prompt + Answer_Correctness
        main_prompt = ChatPromptTemplate.from_template(main_p)
        results = []
        docs = []
        for url in all_urls:
            print(url)
            loader = WebBaseLoader(url)
            documents = loader.load()
            #doc = documents[0]
            #page_content = doc.page_content
            #page_content_list = [page_content]
            docs.extend(documents)
        tagging_chain = main_prompt | model

        text_splitter = RecursiveCharacterTextSplitter(
        chunk_size = 15000,
        separators=["\n\n", "\n", " ", ""]
    )
        splits = text_splitter.split_documents(docs)
        print(len(splits))
        
        vectordb = FAISS.from_documents(
            documents=splits,
            embedding=embeddings,            
        )
        prefix_question = f"""For the **{type_eval}** information of {CVE_ID}: 
        
        """
        question = f"""Given the **response** and the **context**: 
        
        -------------------------
        
        **response**: {response[i]}

        -------------------------

        **context**:  ...

        -------------------------
            """
        main_q = prefix_question + question
        final_docs = vectordb.similarity_search(main_q, k=10)
        all_final_docs.append(final_docs)
        while True:
            try:
                print(response[i])
                result = tagging_chain.invoke({"response": response[i], "context": final_docs})
                results.append(result)
                delay = random.randint(1, 2)
                time.sleep(delay)
                break
            except Exception as e:  # This will catch any exception
                delay = random.randint(1, 2)
                time.sleep(delay)
        final_res[CVE_ID] = results
        print("*************************************************")
        print(final_res[CVE_ID])
        print("*************************************************")

    final_final_docs = pd.DataFrame(all_final_docs)


    final_final_docs = pd.DataFrame(all_final_docs)
    final_final_docs.to_csv(f'./results/final_docs_llama31_{type_eval}.csv', index=False)
    with open(f'./results/final_evals_llama31_{type_eval}.json', 'w') as f:
        json.dump(final_res, f, indent=4)