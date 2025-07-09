import os
import json
import logging

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename="logs/errors.log",
    level=logging.ERROR,
    format="%(asctime)s %(module)s:%(levelname)s - %(message)s"
)

def save_result(module_name, result_data):
    os.makedirs("results", exist_ok=True)
    filename = f"results/{module_name}_results.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(result_data, f, indent=4, ensure_ascii=False)
