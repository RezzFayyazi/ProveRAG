import json
import numpy as np
import pandas as pd
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from rouge_score import rouge_scorer
import matplotlib.pyplot as plt
import seaborn as sns

# Function to compute cosine similarity
def calculate_embedding_similarity(reference_texts: str, candidate_texts: str, model) -> float:
    embedding1 = model.encode(reference_texts)
    embedding2 = model.encode(candidate_texts)
    similarity = cosine_similarity([embedding1], [embedding2])[0][0]
    return similarity

# Function to compute ROUGE scores
def compute_rouge(reference_texts: str, candidate_texts: str, scorer) -> float:
    scores = scorer.score(reference_texts, candidate_texts)
    return scores['rougeL'].fmeasure  # Return ROUGE-L F-measure


# Function to compute average and standard deviation for the scores
def compute_stats(scores):
    if len(scores) > 0:
        return np.mean(scores), np.std(scores)
    else:
        return 0, 0  # Return 0 if the list is empty to avoid errors

# Function to process a JSON file and calculate the metrics for TPs, FPs, FNs
def process_file(file_path, model, scorer):
    # Load provenance data from JSON
    with open(file_path, "r") as f:
        provenance_data = json.load(f)
    
    # Initialize lists to store cosine similarity and ROUGE-L for TPs, FPs, and FNs
    cosine_tp, cosine_fp, cosine_fn = [], [], []
    rougeL_tp, rougeL_fp, rougeL_fn = [], [], []
    
    # Iterate through the CVE data and calculate cosine similarity and ROUGE-L
    for cve_id in provenance_data:
        cve_value = provenance_data[cve_id][0]["value"]
        provenance_list = provenance_data[cve_id][0].get("provenance", [])

        # Skip if provenance is missing or less than 2 elements
        if len(provenance_list) < 2:
            continue

        # Initialize strings to store the concatenated responses and contexts for this CVE
        concatenated_responses = ""
        concatenated_contexts = ""

        for i in range(0, len(provenance_list), 2):  # Loop through the list in steps of 2
            if i + 1 >= len(provenance_list):
                print(f"Missing context for response in {cve_id}")
                break  # Ensure there's a matching "context" for each "response"

            response = provenance_list[i].replace("response: ", "")
            context = provenance_list[i+1].replace("context: ", "")

            # Concatenate the response and context to create a single block of text
            concatenated_responses += response + " "
            concatenated_contexts += context + " "

        # Trim any extra whitespace
        concatenated_responses = concatenated_responses.strip()
        concatenated_contexts = concatenated_contexts.strip()

        # Compute cosine similarity and ROUGE-L for the concatenated responses and contexts
        cosine_similarity_score = calculate_embedding_similarity(concatenated_responses, concatenated_contexts, model)
        rougeL_score = compute_rouge(concatenated_responses, concatenated_contexts, scorer)

        # Append to the appropriate list based on the value (TP, FP, FN)
        if cve_value == "TP":
            cosine_tp.append(cosine_similarity_score)
            rougeL_tp.append(rougeL_score)
        elif cve_value == "FP":
            cosine_fp.append(cosine_similarity_score)
            rougeL_fp.append(rougeL_score)
        elif cve_value == "FN":
            cosine_fn.append(cosine_similarity_score)
            rougeL_fn.append(rougeL_score)

    # Return the raw data lists for further analysis
    return {
        'cosine_tp': cosine_tp,
        'cosine_fp': cosine_fp,
        'cosine_fn': cosine_fn,
        'rougeL_tp': rougeL_tp,
        'rougeL_fp': rougeL_fp,
        'rougeL_fn': rougeL_fn
    }

# Function to plot the results using seaborn boxplots
def plot_results(summary_data, mitigation_data, save_path="./results/provenance_quality.png"):

    # Create a combined DataFrame
    data_list = []

    # Summary data (Exploitation)
    for metric in ['cosine', 'rougeL']:
        for score_list, label in zip([summary_data[f'{metric}_tp'], summary_data[f'{metric}_fp'], summary_data[f'{metric}_fn']], ['TP', 'FP', 'FN']):
            for s in score_list:
                data_list.append({'Score': s, 'Type': label, 'Metric': metric.capitalize(), 'Category': 'Exploitation'})

    # Mitigation data
    for metric in ['cosine', 'rougeL']:
        for score_list, label in zip([mitigation_data[f'{metric}_tp'], mitigation_data[f'{metric}_fp'], mitigation_data[f'{metric}_fn']], ['TP', 'FP', 'FN']):
            for s in score_list:
                data_list.append({'Score': s, 'Type': label, 'Metric': metric.capitalize(), 'Category': 'Mitigation'})

    df = pd.DataFrame(data_list)

    # Set the plotting style
    sns.set(style="whitegrid")

    # Create separate plots for Cosine and ROUGE-L
    metrics = df['Metric'].unique()
    num_metrics = len(metrics)

    fig, axes = plt.subplots(1, num_metrics, figsize=(16, 8), sharey=True)
    for ax, metric in zip(axes, metrics):
        sns.boxplot(data=df[df['Metric'] == metric], x='Type', y='Score', hue='Category', ax=ax)
        ax.set_xlabel('', fontsize=18)
        ax.set_ylabel('Scores', fontsize=26)
        ax.tick_params(axis='both', which='major', labelsize=26)
        ax.legend(fontsize=21)
        if metric == 'Cosine':
            ax.set_title(f'{metric} Similarity', fontsize=28)
        else:
            ax.set_title(f'Rouge-L', fontsize=28)
        

    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.show()

# Main function to process both summary and mitigation data
def main(summary_file, mitigation_file):
    # Load the sentence transformer model for cosine similarity
    model_name = 'multi-qa-mpnet-base-dot-v1'
    model = SentenceTransformer(model_name)

    # Initialize ROUGE scorer
    scorer = rouge_scorer.RougeScorer(['rougeL'], use_stemmer=True)

    # Process the summary and mitigation files
    summary_data = process_file(summary_file, model, scorer)
    mitigation_data = process_file(mitigation_file, model, scorer)

    # Plot the cosine similarity and ROUGE-L results using boxplots
    plot_results(summary_data, mitigation_data)

# Example usage
if __name__ == "__main__":
    exploitation_file = "./results/final_evals_ProveRAG_exploitation_gpt-4o-mini.json"  
    mitigation_file = "./results/final_evals_ProveRAG_mitigation_gpt-4o-mini.json" 
    main(exploitation_file, mitigation_file)
