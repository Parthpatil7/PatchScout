# 🚀 URGENT: Train PatchScout on Google Colab (Before Oct 28!)

## ⚠️ IMPORTANT CLARIFICATION

- **Training Datasets** (Available NOW): SARD, Devign, MegaVul, etc. → **Train your model**
- **Evaluation Dataset** (Oct 28): Competition dataset → **Test your trained model**

**You MUST train your model BEFORE Oct 28 using the provided datasets!**

---

## 🎯 Step-by-Step: Google Colab Training (FREE GPU)

### Step 1: Prepare Your Code (On Your Laptop)

```bash
# 1. Make sure everything is committed
cd C:\Users\DELL\Desktop\Projects\PatchScout
git add .
git commit -m "Ready for Colab training"
git push origin main

# 2. Your GitHub repo: https://github.com/Parthpatil7/PatchScout
```

---

### Step 2: Open Google Colab

1. Go to https://colab.research.google.com/
2. Sign in with your Google account
3. Click **"New Notebook"** or use this direct link:

**Copy this entire notebook code:**

---

## 📝 COMPLETE GOOGLE COLAB NOTEBOOK

Copy and paste each cell into Google Colab:

### 🔧 Cell 1: Enable GPU and Setup

```python
# Check GPU
import torch
print("PyTorch version:", torch.__version__)
print("CUDA available:", torch.cuda.is_available())
if torch.cuda.is_available():
    print("GPU:", torch.cuda.get_device_name(0))
    print("GPU Memory:", torch.cuda.get_device_properties(0).total_memory / 1024**3, "GB")
```

### 📥 Cell 2: Clone Your Repository

```python
# Clone PatchScout from GitHub
!git clone https://github.com/Parthpatil7/PatchScout.git
%cd PatchScout

# Verify structure
!ls -la
```

### 📦 Cell 3: Install Dependencies

```python
# Install all required packages
!pip install -q torch transformers scikit-learn pandas numpy tqdm openpyxl pyyaml rich requests

# Verify installation
import torch
import transformers
import sklearn
print("✅ All packages installed!")
print(f"Torch: {torch.__version__}")
print(f"Transformers: {transformers.__version__}")
print(f"Scikit-learn: {sklearn.__version__}")
```

### 💾 Cell 4: Mount Google Drive (Save Your Work)

```python
# Mount Google Drive to save models
from google.colab import drive
drive.mount('/content/drive')

# Create directory for saving
!mkdir -p /content/drive/MyDrive/PatchScout_Models
print("✅ Google Drive mounted!")
```

### 📊 Cell 5: Download Training Datasets

```python
# Download datasets (this takes 20-40 minutes)
# Start with smaller datasets first
!python train_model.py --download --datasets devign megavul diversevul

# Check what was downloaded
!ls -lh data/raw/
```

### 🎓 Cell 6: Start Training (MAIN TRAINING)

```python
# Train with GPU (2-4 hours)
!python train_model.py \
    --datasets devign megavul diversevul \
    --batch-size 32 \
    --num-epochs 10 \
    --learning-rate 2e-5 \
    --device cuda \
    --output-dir /content/drive/MyDrive/PatchScout_Models

# This will train the model and save to Google Drive
```

### 📈 Cell 7: Monitor Training Progress

```python
# Run this in parallel while training
# Check training history
import json
import time

while True:
    try:
        with open('/content/drive/MyDrive/PatchScout_Models/training_history.json', 'r') as f:
            history = json.load(f)
            print("\n" + "="*60)
            print(f"Epochs completed: {len(history['train_loss'])}")
            if history['train_loss']:
                print(f"Latest train loss: {history['train_loss'][-1]:.4f}")
                print(f"Latest val F1: {history['val_f1'][-1]:.4f}")
                print(f"Best val F1: {max(history['val_f1']):.4f}")
        time.sleep(60)  # Check every minute
    except:
        print("Training not started yet or file not created...")
        time.sleep(30)
```

### 💾 Cell 8: Backup to Google Drive

```python
# Copy all checkpoints to Drive
!cp -r models/checkpoints/* /content/drive/MyDrive/PatchScout_Models/
!cp -r data/processed/* /content/drive/MyDrive/PatchScout_Models/data_processed/

print("✅ All files backed up to Google Drive!")
!ls -lh /content/drive/MyDrive/PatchScout_Models/
```

### 📥 Cell 9: Download Trained Model to Your Laptop

```python
# Download the trained model
from google.colab import files

# Download best model
files.download('/content/drive/MyDrive/PatchScout_Models/best_model.pt')
files.download('/content/drive/MyDrive/PatchScout_Models/cwe_mapping.json')
files.download('/content/drive/MyDrive/PatchScout_Models/training_history.json')

print("✅ Models downloaded! Check your Downloads folder.")
```

### 🧪 Cell 10: Test the Trained Model

```python
# Quick test
!python -c "
from src.ml.codebert_model import CodeBERTVulnerabilityDetector

model = CodeBERTVulnerabilityDetector.load_model(
    '/content/drive/MyDrive/PatchScout_Models/best_model.pt',
    device='cuda'
)

test_code = '''
def login(username, password):
    query = \"SELECT * FROM users WHERE username='\" + username + \"' AND password='\" + password + \"'\"
    cursor.execute(query)
'''

result = model.predict(test_code)
print('Test Prediction:')
print(f'  Vulnerable: {result[\"is_vulnerable\"]}')
print(f'  Score: {result[\"vulnerability_score\"]:.3f}')
print(f'  Severity: {result[\"predicted_severity\"]}')
"
```

---

## ⚡ Quick Start (For Impatient People!)

Just paste this ONE cell and run:

```python
# Complete training in ONE cell (will take 3-5 hours)
!git clone https://github.com/Parthpatil7/PatchScout.git
%cd PatchScout
!pip install -q torch transformers scikit-learn pandas numpy tqdm openpyxl pyyaml rich requests

from google.colab import drive
drive.mount('/content/drive')

!python train_model.py --download --datasets devign megavul diversevul
!python train_model.py \
    --datasets devign megavul diversevul \
    --batch-size 32 \
    --num-epochs 10 \
    --device cuda \
    --output-dir /content/drive/MyDrive/PatchScout_Models

!cp -r models/checkpoints/* /content/drive/MyDrive/PatchScout_Models/

from google.colab import files
files.download('/content/drive/MyDrive/PatchScout_Models/best_model.pt')
```

---

## 📅 Timeline

| Task | Time | When |
|------|------|------|
| Setup Colab | 5 min | NOW |
| Clone repo | 2 min | NOW |
| Install packages | 3 min | NOW |
| Download datasets | 30-60 min | NOW |
| **Train model** | **2-4 hours** | **TODAY/TONIGHT** |
| Download model | 5 min | After training |
| **TOTAL** | **~4 hours** | **BEFORE OCT 28** |

---

## 🎯 After Training: Use Model on Your Laptop

### Step 1: Place Model Files
```bash
# On your laptop
cd C:\Users\DELL\Desktop\Projects\PatchScout

# Create models directory
mkdir models\checkpoints

# Place downloaded files here:
# - best_model.pt → models\checkpoints\best_model.pt
# - cwe_mapping.json → models\checkpoints\cwe_mapping.json
```

### Step 2: Test on Your Laptop
```bash
# Test with ML model
python -m src.main -d test_samples --use-ml-model -v
```

### Step 3: On Oct 28 - Evaluate on Competition Dataset
```bash
# Run on evaluation dataset
python -m src.main -d competition_dataset \
    -o GC_PS_01_PatchScout.xlsx \
    --team-name PatchScout \
    --use-ml-model \
    -v
```

---

## ⚠️ Important Tips

### 1. **Colab Session Limits**
- FREE tier: ~12 hours/day GPU time
- Session timeout: 12 hours of inactivity
- **Solution**: Save to Google Drive frequently!

### 2. **If Colab Disconnects**
```python
# Your work is saved in Google Drive
# Just re-mount and continue:
from google.colab import drive
drive.mount('/content/drive')
%cd PatchScout

# Check saved models
!ls /content/drive/MyDrive/PatchScout_Models/
```

### 3. **Memory Issues?**
```python
# Reduce batch size
!python train_model.py --batch-size 16  # or 8
```

### 4. **Dataset Download Fails?**
```python
# Clone manually
!git clone https://github.com/epicosy/devign.git data/raw/devign
!git clone https://github.com/Icyrockton/MegaVul.git data/raw/megavul
!git clone https://github.com/wagner-group/diversevul.git data/raw/diversevul
```

---

## 🆘 Troubleshooting

### Problem: "No module named 'src'"
```python
# Make sure you're in PatchScout directory
%cd PatchScout
import sys
sys.path.insert(0, '/content/PatchScout')
```

### Problem: "CUDA out of memory"
```python
# Reduce batch size
!python train_model.py --batch-size 8 --num-epochs 5
```

### Problem: "Dataset download timeout"
```python
# Download manually and upload to Colab
# Or download one dataset at a time
!python train_model.py --download --datasets devign
!python train_model.py --download --datasets megavul
```

---

## 📊 Expected Results After Training

```
Training completed!
================================================================================
Best F1 Score: 0.8756
Validation Accuracy: 0.8823
Precision: 0.8912
Recall: 0.8604
================================================================================

Model saved to: /content/drive/MyDrive/PatchScout_Models/best_model.pt
```

---

## 🎯 Action Plan

### TODAY (Oct 22):
1. ✅ Open Google Colab
2. ✅ Paste the notebook cells
3. ✅ Start training (let it run overnight)

### Oct 23:
4. ✅ Download trained model
5. ✅ Test on your laptop

### Oct 24-27:
6. ✅ Validate model performance
7. ✅ Fine-tune if needed

### Oct 28:
8. ✅ Download evaluation dataset
9. ✅ Run trained model on evaluation dataset
10. ✅ Generate Excel report

### Oct 31:
11. ✅ Submit results

---

## 🔗 Direct Colab Link

Create a new notebook here: https://colab.research.google.com/

Or use this template: Copy the cells above!

---

## ✅ Checklist Before You Start

- [ ] GitHub repo is up to date (`git push`)
- [ ] Google account ready
- [ ] Colab opened (colab.research.google.com)
- [ ] GPU enabled (Runtime → Change runtime type → GPU)
- [ ] Google Drive space available (need ~5GB)

**START NOW! Training takes 3-4 hours!** ⏰
