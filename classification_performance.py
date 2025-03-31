import json
import os
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
from typing import Dict, List, Tuple

def load_evaluation_data(filepath: str) -> Dict:
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File {filepath} not found")
        return {}
    except json.JSONDecodeError:
        print(f"Error: File {filepath} contains invalid JSON")
        return {}

def analyze_evaluation_results(data: Dict) -> Tuple[pd.DataFrame, Counter]:

    # Find all unique classification types in the data
    all_values = set()
    max_position = 0

    for cve in data.values():
        for i, entry in enumerate(cve):
            all_values.add(entry["value"])
            max_position = max(max_position, i)

    # Initialize counters for each position and classification type
    position_counts = {pos: Counter() for pos in range(max_position + 1)}
    total_counter = Counter()

    # Count occurrences
    for cve in data.values():
        for i, entry in enumerate(cve):
            if i <= max_position:
                classification = entry["value"]
                position_counts[i][classification] += 1
                total_counter[classification] += 1


    return total_counter


def main():
    current_dir = os.getcwd()
    print(f"Current working directory: {current_dir}")

    filepath = './results/final_evals_final_evals_ProveRAG_mitigation_gpt-4o-mini.json'

    data = load_evaluation_data(filepath)
    if not data:
        return

    # Analyze results
    total_counter = analyze_evaluation_results(data)

    print("\nTotal Counts:")
    for classification, count in total_counter.items():
        print(f"{classification}: {count}")

if __name__ == "__main__":
    main()
