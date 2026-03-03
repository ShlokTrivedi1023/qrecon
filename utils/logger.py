
import os, json
from datetime import datetime

class QLogger:
    def __init__(self, target, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(output_dir, "qrecon_" + target.replace(".","_") + "_" + ts + ".log")
    def log_module_result(self, name, result):
        with open(self.log_file, "a") as f:
            f.write(json.dumps({"module": name, "result": result}) + "\n")
