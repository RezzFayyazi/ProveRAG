import json
import random
import time
import warnings
from typing import Dict, List
import pandas as pd
from langchain.chat_models import ChatOpenAI
from langchain.document_loaders import WebBaseLoader
from langchain.embeddings.openai import OpenAIEmbeddings
from langchain.output_parsers.openai_functions import JsonOutputFunctionsParser
from langchain.prompts import ChatPromptTemplate
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.utils.openai_functions import convert_pydantic_to_openai_function
from langchain.vectorstores import FAISS
from pydantic import BaseModel, Field

# Suppress warnings for cleaner execution
warnings.filterwarnings("ignore")


class Evaluation(BaseModel):
    value: str = Field(
        description=("""
        **value**:
            - Description: This attribute represents the accuracy of the response based on the provided context about the CVE-ID.
            - Allowed Values: 
                - 'TP' (True Positive): The response fully and accurately reflects the information in the context.
                - 'FP' (False Positive): The response contains inaccurate or incorrect information that are not supported by the context.
                - 'FN' (False Negative): The response omits information that is present in the context.
            - Requirements:
                - Must strictly be one of the allowed values: 'TP', 'FP', or 'FN'.
                - The selection must be based on an objective comparison between the response and the context.
                - Must follow the guidelines for Provenance.
                """
        )
    )

    rationale: str = Field(
        description=("""
        **Rationale**:
            - Description: This attribute provides the reasoning behind the selected **value** for the evaluation of the response.
                     """
        )
    )       

    provenance: List[str] = Field(
        description=("""
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
                - The provenance should be an **exact match** or a **direct comparison** between the response and the context, following the formatting rules strictly."""
        )
    )



class CVEEvaluator:
    """
    This class provides methods to load data, process CVEs, and evaluate the accuracy
    of vulnerability analysis by comparing against authoritative sources.
    """

    def __init__(
        self, 
        api_key: str, 
        model_name: str = "gpt-4o-mini", 
        eval_type: str = "mitigation",
        mode: str = "ProveRAG"
    ):
        """
        Initialize the CVE evaluator.

        Args:
            api_key: OpenAI API key
            model_name: Name of the language model to use
            eval_type: Type of evaluation to perform ('mitigation' or 'exploitation')
            mode: Evaluation mode
        """
        self.api_key = api_key
        self.model_name = model_name
        self.eval_type = eval_type
        self.not_eval_type = "exploitation" if eval_type == "mitigation" else "mitigation"
        self.mode = mode

        # Initialize LLM and embeddings
        self.model = ChatOpenAI(api_key=api_key, model=model_name, temperature=0.0)
        self.embeddings = OpenAIEmbeddings(openai_api_key=api_key)

        # Create evaluation function
        self.eval_tagging_function = [
            convert_pydantic_to_openai_function(Evaluation)
        ]

        # Bind function to model
        self.tagging_model = self.model.bind(
            functions=self.eval_tagging_function,
            function_call={"name": "Evaluation"}
        )

    def load_data(
        self, 
        results_path: str, 
        relevancy_path: str, 
        cve_data_path: str
    ) -> tuple:

        try:
            with open(results_path, 'r') as f:
                main_results = json.load(f)
        except json.JSONDecodeError as e:
            print(f"JSON decode error in results file: {e}")
            raise

        try:
            with open(relevancy_path, 'r') as f:
                relevancies = json.load(f)
        except json.JSONDecodeError as e:
            print(f"JSON decode error in relevancy file: {e}")
            raise

        cve_data = pd.read_csv(cve_data_path)

        return main_results, relevancies, cve_data

    def build_relevancy_map(self, relevancies: List[dict]) -> Dict[str, List[int]]:
        relevant_dict = {}
        for relevancy in relevancies:
            for i in range(len(relevancy)):
                if relevancy[i]['relevancy'] == 'Yes':
                    cve_id = relevancy[i]['id']
                    if cve_id not in relevant_dict:
                        relevant_dict[cve_id] = []
                    relevant_dict[cve_id].append(i)
        return relevant_dict

    def extract_main_texts(self, item: dict) -> List[str]:
        main_texts = []
        for key, value in item.items():
            if key == 'id' or key == 'cvss' or key == self.not_eval_type:
                continue
            if isinstance(value, str):
                main_texts.append(value)
            elif isinstance(value, list):
                main_texts.extend(value)
        return main_texts

    def get_relevant_urls(
        self, 
        cve_id: str, 
        relevant_indices: List[int], 
        cve_data: pd.DataFrame
    ) -> List[str]:

        specific_cve_data = cve_data[cve_data['CVE_ID'] == cve_id]
        relevant_urls = []

        if self.mode == "ProveRAG-Aqua":
            for relevant in relevant_indices:
                if relevant == 2:
                    aqua_url = specific_cve_data['CVE_URL'].tolist()[0]
                    relevant_urls.append(aqua_url)
                if relevant >= 3:
                    hyperlinks = specific_cve_data['hyperlinks'].apply(
                        lambda x: x.split(',') if pd.notna(x) else []
                    ).tolist()
                    flattened_hyperlinks = [url for sublist in hyperlinks for url in sublist]
                    relevant_urls.append(flattened_hyperlinks[relevant - 3])
        else:
            for relevant in relevant_indices:
                if relevant >= 2:
                    hyperlinks = specific_cve_data['hyperlinks'].apply(
                        lambda x: x.split(',') if pd.notna(x) else []
                    ).tolist()
                    flattened_hyperlinks = [url for sublist in hyperlinks for url in sublist]
                    if relevant - 2 < len(flattened_hyperlinks):
                        relevant_urls.append(flattened_hyperlinks[relevant - 2])

        return relevant_urls

    def load_documents_from_urls(self, urls: List[str]) -> List:
        docs = []
        for url in urls:
            try:
                loader = WebBaseLoader(url)
                documents = loader.load()
                docs.extend(documents)
            except Exception as e:
                print(f"Error loading URL {url}: {e}")
        return docs

    def create_evaluation_prompt(self, cve_id: str) -> ChatPromptTemplate:

        prefix_prompt = f"""For the **{self.eval_type}** information of {cve_id}: 

        """
        answer_correctness = """Given the **response** and the **context**: 

        -------------------------

        **response**: {response}

        -------------------------

        **context**: {context}

        -------------------------
        """

        main_p = prefix_prompt + answer_correctness
        return ChatPromptTemplate.from_template(main_p)

    def evaluate_cve(self, item: dict, cve_data: pd.DataFrame, relevant_dict: dict) -> tuple:

        cve_id = item['id']
        main_texts = self.extract_main_texts(item)

        # Get specific CVE data
        specific_cve_data = cve_data[cve_data['CVE_ID'] == cve_id]

        # Get relevant URLs
        relevant_urls = []
        if cve_id in relevant_dict:
            relevant_urls = self.get_relevant_urls(
                cve_id, 
                relevant_dict[cve_id], 
                cve_data
            )

        # Get NVD and CWE URLs
        nvd_urls = specific_cve_data['NVD'].tolist()
        cwe_urls = specific_cve_data['CWE'].tolist()

        # Combine all URLs
        all_urls = nvd_urls + cwe_urls + relevant_urls
        all_urls = [url.strip() for url in all_urls]

        # Create evaluation prompt
        main_prompt = self.create_evaluation_prompt(cve_id)
        tagging_chain = main_prompt | self.tagging_model | JsonOutputFunctionsParser()

        # Load documents from URLs
        docs = self.load_documents_from_urls(all_urls)

        # Split documents into chunks
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=15000,
            separators=["\n\n", "\n", " ", ""]
        )
        splits = text_splitter.split_documents(docs)

        # Create vector database
        vectordb = FAISS.from_documents(
            documents=splits,
            embedding=self.embeddings,            
        )

        # Create query for similarity search
        prefix_question = f"""For the **{self.eval_type}** information of {cve_id}: 

        """
        question = f"""Given the **response** and the **context**: 

        -------------------------

        **response**: {main_texts}

        -------------------------

        **context**:  ...

        -------------------------
            """
        main_q = prefix_question + question

        # Perform similarity search
        final_docs = vectordb.similarity_search(main_q, k=10)

        # Evaluate response against context
        results = []
        max_retries = 3
        retry_count = 0

        while retry_count < max_retries:
            try:
                result = tagging_chain.invoke({"response": main_texts, "context": final_docs})
                print(result)
                results.append(result)
                break
            except Exception as e:
                print(f"Error evaluating {cve_id}, retry {retry_count + 1}: {e}")
                retry_count += 1
                delay = random.randint(1, 2)
                time.sleep(delay)

        return results, final_docs

    def evaluate_all_cves(
        self, 
        main_results: List[dict], 
        relevancies: List[dict], 
        cve_data: pd.DataFrame
    ) -> tuple:
        """
        Evaluate all CVEs in the dataset.

        Args:
            main_results: List of dictionaries containing main results
            relevancies: List of dictionaries containing relevancy information
            cve_data: DataFrame containing CVE data

        Returns:
            Tuple of (evaluation_results, all_final_docs)
        """
        # Build relevancy map
        relevant_dict = self.build_relevancy_map(relevancies)

        # Initialize results
        final_res = {}
        all_final_docs = []

        # Evaluate each CVE
        for item in main_results:
            results, final_docs = self.evaluate_cve(item, cve_data, relevant_dict)
            final_res[item['id']] = results
            all_final_docs.append(final_docs)

            # Add delay to avoid rate limiting
            delay = random.randint(1, 2)
            time.sleep(delay)

        return final_res, all_final_docs

    def save_results(
        self, 
        evaluation_results: dict, 
        all_final_docs: List
    ) -> None:

        # Save evaluation results
        with open(f'./results/final_evals_{self.mode}_{self.eval_type}_{self.model_name}.json', 'w') as f:
            json.dump(evaluation_results, f, indent=4)

        # Save documents used for evaluation
        final_final_docs = pd.DataFrame(all_final_docs)
        final_final_docs.to_csv(
            f'./results/all_final_docs_{self.mode}_{self.eval_type}_{self.model_name}.csv', 
            index=False
        )

        print(f"Results saved successfully for {self.eval_type} evaluation using {self.model_name}.")


def evaluation_main(api_key, model_name, eval_type, results_path, relevancy_path, cve_data_path, mode):
    """
    # Configuration
    api_key = "YOUR_API_KEY"
    model_name = "gpt-4o-mini"
    eval_type = "mitigation"  # or "summary"
    mode = "ProveRAG"

    # File paths
    results_path = './results/1.json'
    relevancy_path = './results/1.json'
    cve_data_path = './data/1.csv'

    """
    # Initialize evaluator
    evaluator = CVEEvaluator(
        api_key=api_key,
        model_name=model_name,
        eval_type=eval_type,
        mode=mode
    )

    # Load data
    main_results, relevancies, cve_data = evaluator.load_data(
        results_path, 
        relevancy_path, 
        cve_data_path
    )

    # Evaluate CVEs
    evaluation_results, all_final_docs = evaluator.evaluate_all_cves(
        main_results, 
        relevancies, 
        cve_data
    )

    # Save results
    evaluator.save_results(evaluation_results, all_final_docs)

