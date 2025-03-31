import json
import random
import time
import warnings
import pandas as pd
from langchain.chat_models import ChatOpenAI
from langchain.document_loaders import WebBaseLoader
from langchain.output_parsers.openai_functions import JsonOutputFunctionsParser
from langchain.prompts import ChatPromptTemplate
from langchain.utils.openai_functions import convert_pydantic_to_openai_function
from langchain.vectorstores import FAISS
from pydantic import BaseModel, Field

# Suppress warnings for cleaner execution
warnings.filterwarnings("ignore")


class Overview(BaseModel):
    """Structured overview of a CVE vulnerability."""

    id: str = Field(description="The CVE-ID of the vulnerability.")
    cvss: str = Field(description="The CVSS score of the vulnerability.")
    exploitation: str = Field(description="High-level overview and a step-by-step description of the procedure.")
    mitigation: str = Field(description="Detailed mitigation strategies for the vulnerability.")


class URLAnalysis(BaseModel):
    """Analysis of URL content for relevancy and information extraction."""

    id: str = Field(description="The CVE-ID of the vulnerability.")
    relevancy: str = Field(description="Indicates if the content is relevant to the question with respect to the CVE-ID (Yes/No).")
    summary: str = Field(description="Summary of the essential information regarding the question, or 'NONE' if not relevant.")


def load_cve_data(file_path: str) -> pd.DataFrame:
    return pd.read_csv(file_path)


def create_prompt_templates():
    # Prompt for extracting exploitation steps
    exploitation_prompt = ChatPromptTemplate.from_template(
        """You are a cybersecurity expert. Your task is to analyze the provided URL content for the {CVE} and provide a detailed summary.

        Please follow the steps below:

        Content: {content}

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

    # Prompt for extracting mitigation strategies
    mitigation_prompt = ChatPromptTemplate.from_template(
        """You are a cybersecurity expert. Your task is to analyze the provided URL content for the {CVE} and provide a detailed summary.

        Please follow the steps below:

        Content: {content}

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

    # Main prompt for comprehensive analysis
    main_prompt = ChatPromptTemplate.from_template(
        """You are a cybersecurity expert. Consider the Relevant Information provided below and answer the Query.

        Relevant Information: {context}

        Query: CVE-ID: {CVE}
        Given the specified CVE-ID, please provide detailed answers to the following questions:

        1. How can an attacker exploit this vulnerability? Provide a step-by-step description.

        2. What are the recommended mitigation strategies for this vulnerability?
        """
    )

    return exploitation_prompt, mitigation_prompt, main_prompt


def setup_llm_chains(model, exploitation_prompt, mitigation_prompt, main_prompt):
    """
    Set up language model chains for different analysis tasks.

    Args:
        model: The language model to use
        exploitation_prompt: Prompt template for summarizing exploitation information
        mitigation_prompt: Prompt template for summarizing mitigation strategies
        main_prompt: Prompt template for main analysis (Gen. LLM)

    Returns:
        Tuple of chains for summary, mitigation, and main analysis
    """
    # Convert Pydantic models to OpenAI functions
    hyperlink_tagging_function = [convert_pydantic_to_openai_function(URLAnalysis)]
    overview_tagging_function = [convert_pydantic_to_openai_function(Overview)]

    # Bind functions to models
    tagging_model_hyper = model.bind(
        functions=hyperlink_tagging_function,
        function_call={"name": "URLAnalysis"}
    )

    tagging_model_main = model.bind(
        functions=overview_tagging_function,
        function_call={"name": "Overview"}
    )

    # Create chains
    exploitation_chain = exploitation_prompt | tagging_model_hyper | JsonOutputFunctionsParser()
    mitigation_chain = mitigation_prompt | tagging_model_hyper | JsonOutputFunctionsParser()
    main_chain = main_prompt | tagging_model_main | JsonOutputFunctionsParser()

    return exploitation_chain, mitigation_chain, main_chain


def extract_content_from_url(url, cve_id, summary_chain, mitigation_chain):
    """
    Extract and analyze content from a URL.

    Args:
        url: The URL to analyze
        cve_id: The CVE ID being analyzed
        summary_chain: Chain for summary analysis
        mitigation_chain: Chain for mitigation analysis

    Returns:
        Tuple of summary and mitigation analysis results
    """
    try:
        # Load and extract content from URL
        loader = WebBaseLoader(url)
        documents = loader.load()
        page_content = documents[0].page_content

        # Add random delay to avoid rate limiting
        time.sleep(random.randint(1, 2))

        # Analyze for exploitation steps
        summary_result = summary_chain.invoke({
            "CVE": cve_id, 
            "content": page_content
        })

        # Add random delay to avoid rate limiting
        time.sleep(random.randint(1, 2))

        # Analyze for mitigation strategies
        mitigation_result = mitigation_chain.invoke({
            "CVE": cve_id, 
            "content": page_content
        })

        return summary_result, mitigation_result

    except Exception as e:
        print(f"Error processing {url}: {e}")
        return None, None


def analyze_cve(cve_id, nvd_url, cwe_url, hyperlinks, exploitation_chain, mitigation_chain, main_chain):
    """
    Perform comprehensive analysis of a CVE.

    Args:
        cve_id: The CVE ID to analyze
        nvd_url: URL to the NVD page for this CVE
        cwe_url: URL to the CWE page for this CVE
        hyperlinks: Additional URLs related to this CVE
        exploitation_chain: Chain for exploitaiton analysis
        mitigation_chain: Chain for mitigation analysis
        main_chain: Chain for main analysis

    Returns:
        Tuple of main analysis result, exploitation results, and mitigation results
    """
    # Combine all URLs
    all_urls = [nvd_url, cwe_url] + hyperlinks

    # Initialize containers for results
    exploitation_results = []
    mitigation_results = []
    relevant_information = []

    # Process each URL
    for url in all_urls:
        exploitation_result, mitigation_result = extract_content_from_url(
            url, cve_id, exploitation_chain, mitigation_chain
        )

        if exploitation_result:
            exploitation_results.append(exploitation_result)
            if exploitation_result['relevancy'] == 'Yes':
                relevant_information.append(exploitation_result['summary'])

        if mitigation_result:
            mitigation_results.append(mitigation_result)
            if mitigation_result['relevancy'] == 'Yes':
                relevant_information.append(mitigation_result['summary'])

    # Generate comprehensive analysis
    main_result = main_chain.invoke({
        "CVE": cve_id, 
        "context": relevant_information
    })

    return main_result, exploitation_results, mitigation_results


def generation_main(api_key, model_name, data_path, mode):
    """
    # Configuration
    data_path = './data/cve_2024_critical_hyper.csv'
    api_key = "YOUR_API_KEY"
    model_name = "gpt-4o-mini"
    """
    # Load data
    data = load_cve_data(data_path)

    # Initialize model
    model = ChatOpenAI(api_key=api_key, model=model_name, temperature=0.0)

    # Create prompt templates
    summary_prompt, mitigation_prompt, main_prompt = create_prompt_templates()

    # Setup chains
    summary_chain, mitigation_chain, main_chain = setup_llm_chains(
        model, summary_prompt, mitigation_prompt, main_prompt
    )

    # Filter and prepare data
    filtered_df = data
    filtered_cves = list(zip(
        filtered_df['CVE_ID'], 
        filtered_df['NVD'], 
        filtered_df['CWE'], 
        filtered_df['CVE_URL']
    ))

    # Initialize result containers
    all_responses = []
    all_exploitation_results = []
    all_mitigation_results = []

    # Process each CVE
    for cve_id, nvd_url, cwe_url, aqua_url in filtered_cves:
        # Get hyperlinks for this CVE
        specific_cve_data = data[data['CVE_ID'] == cve_id]
        hyperlinks = specific_cve_data['hyperlinks'].apply(
            lambda x: x.split(',') if pd.notna(x) else []
        ).tolist()
        flattened_hyperlinks = [url for sublist in hyperlinks for url in sublist]

        if mode == "ProveRAG-Aqua":
            # Add Aqua URL to the list of hyperlinks
            flattened_hyperlinks.insert(0, aqua_url)
        # Analyze CVE
        main_result, summary_results, mitigation_results = analyze_cve(
            cve_id, 
            nvd_url, 
            cwe_url, 
            flattened_hyperlinks,
            summary_chain, 
            mitigation_chain, 
            main_chain
        )

        # Store results
        all_responses.append(main_result)
        all_exploitation_results.append(summary_results)
        all_mitigation_results.append(mitigation_results)

        # Print results for monitoring
        print(f"Completed analysis for {cve_id}")
        print(main_result)
        print('\n')

    
    path_to_save_exploitation_relevancy = f'./results/relevancy_exploitation_{mode}.json'
    path_to_save_mitigation_relevancy = f'./results/relevancy_mitigation_{mode}.json'
    path_to_save_generation_results = f'./results/generation_{mode}.json'
    # Save results to files
    with open(path_to_save_exploitation_relevancy, 'w') as f:
        json.dump(all_exploitation_results, f, indent=4)

    with open(path_to_save_mitigation_relevancy, 'w') as f:
        json.dump(all_mitigation_results, f, indent=4)

    with open(path_to_save_generation_results, 'w') as f:
        json.dump(all_responses, f, indent=4)

    print("Analysis complete. files saved to Results.")

    return path_to_save_exploitation_relevancy, path_to_save_mitigation_relevancy, path_to_save_generation_results

