from generation import *
from evaluation import *


if __name__ == "__main__":
    api_key = "YOUR_API_KEY"  # Replace with your OpenAI API key
    model_name = "gpt-4o-mini"
    data_path = './data/cve_2024_critical_hyper.csv'
    eval_type = "mitigation"  # or "exploitation"
    mode = "ProveRAG"  # or "ProveRAG-Aqua"
    
    # GENERATION MODULE
    # If you only want to test the provenance part, you can comment the generation part and only give the path of the generation results to the evaluation module
    path_to_exploitation_relevancy, path_to_mitigation_relevancy, path_to_generation_results =  generation_main(api_key, model_name, data_path, mode)


    # EVALUATION MODULE
    #path_to_exploitation_relevancy = "./results/relevancy_exploitation_ProveRAG.json"
    #path_to_mitigation_relevancy = "./results/relevancy_mitigation_ProveRAG.json"
    #path_to_generation_results = "./results/generation_ProveRAG.json"
    # File paths
    if eval_type == "exploitation":
        relevancy_path = path_to_exploitation_relevancy
    elif eval_type == "mitigation":
        relevancy_path = path_to_mitigation_relevancy
    
    evaluation_main(api_key, model_name, eval_type, path_to_generation_results, relevancy_path, data_path, mode)

    print("Evaluation completed successfully. Refer to the output files in the `results' folder.")
