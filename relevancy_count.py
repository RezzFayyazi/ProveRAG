import json
import os

print(os.getcwd())
with open(f'./results/relevancy_mitigation_ProveRAG.json', 'r') as f:
    data = json.load(f)

# Initialize counters for each position
tp_counts = 0
total_counts = 0

for i, cve_list in enumerate(data):
    entry = cve_list[0] 
    if entry["relevancy"].lower() == "yes":
        tp_counts += 1
    total_counts += 1

"""
tp_counts = 0
total_counts = 0
# Iterate through each CVE list
for i, cve_list in enumerate(data):
    for entry in cve_list[1:]:
        # Check if the entry is a dictionary before accessing keys
        if isinstance(entry, dict):
            if entry.get("relevancy", "").lower() == "yes":  # Safely check 'relevancy' key
                tp_counts += 1
            total_counts += 1
        else:
            print(f"Skipping non-dictionary entry at index {i}")
"""

print(f"Position: {tp_counts} out of {total_counts}")