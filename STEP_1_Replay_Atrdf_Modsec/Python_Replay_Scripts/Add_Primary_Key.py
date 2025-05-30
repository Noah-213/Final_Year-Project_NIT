import json

# --- Path to the original file (without primary_key) ---
INPUT_PATH = "/home/Tarek/Documents/Atrdf_Dataset/dataset_4_train.json"
# --- Output path (with primary_key) ---
OUTPUT_PATH = "/home/Tarek/Documents/Atrdf_Dataset/atrdf.json"

# Load the original ATRDF dataset
with open(INPUT_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)

# Add a unique primary_key field to each entry
for i, entry in enumerate(data):
    entry["primary_key"] = f"ATRDF-{i}"

# Save the enriched file
with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print(f"File enriched with 'primary_key' saved as: {OUTPUT_PATH}")
