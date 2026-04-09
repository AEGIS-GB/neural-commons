#!/usr/bin/env python3
"""v7 fine-tune: v6 base + social engineering + jailbreak prompts + benign override.

RAG-aware LoRA training on Gemma3-4B-it.
Run inside kyuz0/amd-strix-halo-llm-finetuning container.

Usage (inside container):
  python3 /workspace/scripts/train_v7.py
"""

import json
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, TrainingArguments, Trainer
from peft import LoraConfig, get_peft_model, TaskType
from torch.utils.data import Dataset

# ─── Config ──────────────────────────────────────────────────────
MODEL_NAME = "google/gemma-3-4b-it"
OUTPUT_DIR = "/workspace/output/gemma3-v7"
DATASET_PATH = "/workspace/data/v7_dataset.json"
EPOCHS = 3
BATCH_SIZE = 1
GRAD_ACCUM = 8
LR = 2e-4
LORA_R = 16
LORA_ALPHA = 32
MAX_LENGTH = 512

# ─── Dataset ─────────────────────────────────────────────────────
class ScreeningDataset(Dataset):
    def __init__(self, data, tokenizer, max_length=MAX_LENGTH):
        self.examples = []
        for item in data:
            text = item["prompt"] + item["completion"]
            encoded = tokenizer(
                text,
                truncation=True,
                max_length=max_length,
                padding="max_length",
                return_tensors="pt",
            )
            input_ids = encoded["input_ids"].squeeze()
            attention_mask = encoded["attention_mask"].squeeze()
            labels = input_ids.clone()

            # Mask the prompt tokens — only train on the completion
            prompt_encoded = tokenizer(
                item["prompt"],
                truncation=True,
                max_length=max_length,
                return_tensors="pt",
            )
            prompt_len = prompt_encoded["input_ids"].shape[1]
            labels[:prompt_len] = -100

            self.examples.append({
                "input_ids": input_ids,
                "attention_mask": attention_mask,
                "labels": labels,
            })

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, idx):
        return self.examples[idx]

# ─── Main ────────────────────────────────────────────────────────
def main():
    print(f"Loading dataset from {DATASET_PATH}...")
    with open(DATASET_PATH) as f:
        data = json.load(f)
    print(f"  {len(data)} examples")

    # Count labels
    labels = {}
    sources = {}
    for item in data:
        lab = item["label"]
        src = item["source"]
        labels[lab] = labels.get(lab, 0) + 1
        sources[src] = sources.get(src, 0) + 1
    print(f"  Labels: {labels}")
    print(f"  Sources: {sources}")

    print(f"\nLoading tokenizer and model: {MODEL_NAME}...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        torch_dtype=torch.bfloat16,
        attn_implementation="eager",
        device_map="auto",
    )

    print("Configuring LoRA...")
    lora_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=LORA_R,
        lora_alpha=LORA_ALPHA,
        lora_dropout=0.05,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    )
    model = get_peft_model(model, lora_config)
    model.enable_input_require_grads()
    model.print_trainable_parameters()

    print("Tokenizing dataset...")
    dataset = ScreeningDataset(data, tokenizer)
    print(f"  {len(dataset)} tokenized examples")

    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        gradient_accumulation_steps=GRAD_ACCUM,
        learning_rate=LR,
        bf16=True,
        logging_steps=10,
        save_strategy="epoch",
        gradient_checkpointing=True,
        optim="adamw_torch",
        warmup_ratio=0.03,
        report_to="none",
        dataloader_pin_memory=False,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
    )

    print(f"\nStarting training: {EPOCHS} epochs, {len(dataset)} examples...")
    print(f"  Effective batch size: {BATCH_SIZE * GRAD_ACCUM}")
    print(f"  Steps per epoch: {len(dataset) // (BATCH_SIZE * GRAD_ACCUM)}")
    print(f"  Total steps: {(len(dataset) * EPOCHS) // (BATCH_SIZE * GRAD_ACCUM)}")

    trainer.train()

    print(f"\nSaving adapter to {OUTPUT_DIR}...")
    model.save_pretrained(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    print("Done!")

if __name__ == "__main__":
    main()
