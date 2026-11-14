from datasets import load_dataset
from transformers import AutoModelForCausalLM, AutoTokenizer

base = "meta-llama/Meta-Llama-3-8B"
tokenizer = AutoTokenizer.from_pretrained("meta-llama/Meta-Llama-3-8B")
model = AutoModelForCausalLM.from_pretrained("meta-llama/Meta-Llama-3-8B")
reviews = load_dataset("example-org/product-reviews-nc")
