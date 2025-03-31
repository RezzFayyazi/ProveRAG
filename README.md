# ProveRAG
ProveRAG: Provenance-Driven Vulnerability Analysis with Automated Retrieval-Augmented LLMs

## Overview

This repo offers ProveRAG, an LLM-powered system that emulates an analyst’s approach to vulnerability analysis while self-critiquing its own responses with evidence. By integrating a summarizing retrieval technique of up-to-date web data and a self-critique mechanism, ProveRAG reveals and alleviates the omission and hallucination problem of state-of-the-art LLMs. 

## Setup
Create a conda environment and install the libraries:
```python
conda create --name TTP-LLM python=3.10
conda activate TTP-LLM
pip install -r requirements.txt
```

## Repository Structure

### Data Folder

1. **MITRE_Tactic_and_Techniques_Descriptions.csv**
   - **Description**: Training dataset crawled from the MITRE ATT&CK framework.
   - **Purpose**: Used for training encoder-only models to understand and classify tactics.


### generation file

This file represents the Generation of 
