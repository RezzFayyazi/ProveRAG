# ProveRAG
ProveRAG: Provenance-Driven Vulnerability Analysis with Automated Retrieval-Augmented LLMs
[arxiv](https://arxiv.org/abs/2410.17406)  

## Overview

This repo offers ProveRAG, an LLM-powered framework that emulates an analyst’s approach to vulnerability analysis while self-critiquing its own responses with evidence. By integrating a summarizing retrieval technique of up-to-date web data and a self-critique mechanism, ProveRAG reveals and alleviates the omission and hallucination problem of state-of-the-art LLMs. 

![Alt text](images/proveRAG_methodology.png)

## Setup
Create a virtual environment and install the libraries:
```python
pyhton -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Repository Structure

### Data Folder
**cve_2024_critical_hyper.csv**
   - **Description**: The curated dataset of CVEs in 2024 with critical vunlerability (up until July 25)

### baseline.py 

This is the baseline file of directly prompting the GPT models about a specifc CVE.

### generation.py

This file represents the Generation Module of the proposed ProveRAG framework. The Retr. LLM will summarize the content of the sources with respect to the exploitaion/mitigation information and then will pass it to the Gen. LLM to provide the response. 

### evaluation.py 

This file represents the Evaluation Module of the proposed ProveRAG framework. The Eval. LLM will self-critique its response with verifiable sources be predicting a value (TP/FP/FN), rationale for the selected value, and provenance by showing pieces of text where it got the information (or where it hallucinated or omitted information). 

### classification_performance.py 

This file represents the predicted number of TPs, FPs, and FNs for a selected model for ProveRAG.

### relevancy_count.py

This file contains the number of relevant CVEs for each reputable source predicted by the LLM (shown in Table 2 of the paper).

### provenance_quality.py

This file will use Embedding Similarity and Rouge-L metrics to assess the quality of provenance (i.e., the LLMs' response and the evidence) for TPs, FPs, and FNs

### main.py

This is the main file to run ProveRAG by leveraging the entire pipeline.

### Open Source Models Folder

This folder contains the code for leveraging ProveRAG with open-source LLMs using Ollama. The "ollama_relevacncy.py" will summarize the content retrieved from web data, the "ollama_generation.py" will generate the response for mitigation/exploitation information after postprocessing of the summaries (postprocess is just to keeping those summaries that LLM found relevant for a specific CVE), and the "Ollama_provenance.py" is the evaluation part to provide value, rationale, and provenance attributes. Finally, "Ollama_responses_direct_prompting.py" is to use an open-source model and directly querying it for a specific CVE.


## How to Run

Run the "main.py" file by passing the following arguments (you can change to any OpenAI models):
```python
 api_key = "YOUR_API_KEY"  # Replace with your OpenAI API key
 model_name = "gpt-4o-mini"
 data_path = './data/cve_2024_critical_hyper.csv'
 eval_type = "mitigation"  # or "exploitation"
 mode = "ProveRAG"  # or "ProveRAG-Aqua"

```

## Citation

```bibtex
@article{fayyazi2024proverag,
  title={ProveRAG: Provenance-Driven Vulnerability Analysis with Automated Retrieval-Augmented LLMs},
  author={Fayyazi, Reza and Trueba, Stella Hoyos and Zuzak, Michael and Yang, Shanchieh Jay},
  journal={arXiv preprint arXiv:2410.17406},
  year={2024}
}
