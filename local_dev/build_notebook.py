"""Generate notebook.ipynb from attack.py for Kaggle submission."""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ATTACK_PATH = REPO_ROOT / "attack.py"
NOTEBOOK_PATH = REPO_ROOT / "notebook.ipynb"


def main() -> None:
    if not ATTACK_PATH.exists():
        print(f"error: {ATTACK_PATH} not found", file=sys.stderr)
        sys.exit(1)

    attack_code = ATTACK_PATH.read_text(encoding="utf-8")
    print(f"Embedding attack.py ({len(attack_code.encode('utf-8'))} bytes)")

    cells = [
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "import sys, glob\n",
                "from pathlib import Path\n",
                "sys.argv = [sys.argv[0]]\n",
                "for candidate in glob.glob('/kaggle/input/**/kaggle_evaluation', recursive=True):\n",
                "    dataset_root = str(Path(candidate).parent)\n",
                "    if dataset_root not in sys.path:\n",
                "        sys.path.insert(0, dataset_root)\n",
                "    print(f'Dataset root: {dataset_root}')\n",
                "    break\n",
            ],
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "from pathlib import Path\n",
                "attack_code = ",
                repr(attack_code),
                "\n",
                "Path('/kaggle/working/attack.py').write_text(attack_code)\n",
                "print('attack.py written')\n",
            ],
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "import kaggle_evaluation.jed_attack_134815.jed_attack_inference_server\n",
                "server = kaggle_evaluation.jed_attack_134815.jed_attack_inference_server\n",
                "server.JEDAttackInferenceServer().serve()\n",
            ],
        },
    ]

    nb = {
        "cells": cells,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3",
            },
            "language_info": {
                "name": "python",
                "version": "3.11",
            },
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }

    NOTEBOOK_PATH.write_text(json.dumps(nb, indent=2), encoding="utf-8")
    print(f"Wrote {NOTEBOOK_PATH}")


if __name__ == "__main__":
    main()
