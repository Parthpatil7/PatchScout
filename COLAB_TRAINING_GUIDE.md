# PatchScout Training on Google Colab (FREE GPU)

## 🚀 Quick Setup (15 minutes)

### Step 1: Open Google Colab
1. Go to https://colab.research.google.com/
2. Sign in with Google account
3. Click "New Notebook"

### Step 2: Enable GPU
1. Click **Runtime** → **Change runtime type**
2. Select **Hardware accelerator**: **GPU** (T4)
3. Click **Save**

### Step 3: Upload PatchScout Code

Run this in first cell:
```python
# Clone your repository
!git clone https://github.com/Parthpatil7/PatchScout.git
%cd PatchScout

# Or upload ZIP file manually:
# 1. Zip your PatchScout folder
# 2. Upload to Colab
# 3. Unzip: !unzip PatchScout.zip
```

### Step 4: Install Dependencies
```python
# Install ML dependencies
!pip install torch transformers scikit-learn pandas numpy tqdm openpyxl pyyaml rich
```

### Step 5: Download Datasets
```python
# Download datasets (this may take 30-60 minutes)
!python train_model.py --download --datasets devign megavul diversevul
```

### Step 6: Train Model
```python
# GPU training (2-4 hours)
!python train_model.py \
    --datasets devign megavul diversevul \
    --batch-size 32 \
    --num-epochs 10 \
    --device cuda \
    --learning-rate 2e-5
```

### Step 7: Download Trained Model
```python
# Download the trained model to your laptop
from google.colab import files

# Download best model
files.download('models/checkpoints/best_model.pt')
files.download('models/checkpoints/cwe_mapping.json')
files.download('models/checkpoints/training_history.json')
```

---

## 📊 Expected Timeline

| Task | Time |
|------|------|
| Setup Colab + Upload code | 15 min |
| Install dependencies | 5 min |
| Download datasets | 30-60 min |
| Train model (GPU) | 2-4 hours |
| Download results | 5 min |
| **TOTAL** | **~4 hours** |

---

## 💾 Save Your Work

**Important:** Colab sessions expire after 12 hours of inactivity!

### To prevent data loss:

```python
# Mount Google Drive
from google.colab import drive
drive.mount('/content/drive')

# Save checkpoints to Drive
!mkdir -p /content/drive/MyDrive/PatchScout
!cp -r models/checkpoints/* /content/drive/MyDrive/PatchScout/

# Copy datasets too (optional)
!cp -r data/processed/* /content/drive/MyDrive/PatchScout/data/
```

---

## 🔍 Monitor Training

```python
# Watch training progress
!tail -f models/checkpoints/training_history.json

# Check GPU usage
!nvidia-smi
```

---

## ⚠️ Troubleshooting

### Out of Memory Error
```python
# Reduce batch size
!python train_model.py --batch-size 16  # or even 8
```

### Session Disconnected
```python
# Your work is saved in /content/drive/MyDrive/PatchScout/
# Just re-run from Step 3
```

### Download Datasets Manually
If auto-download fails:
```python
# Clone datasets directly
!git clone https://github.com/epicosy/devign.git data/raw/devign
!git clone https://github.com/Icyrockton/MegaVul.git data/raw/megavul
```

---

## 🎯 After Training (Use on Your Laptop)

1. Download `best_model.pt` from Colab
2. Place in `models/checkpoints/` on your laptop
3. Run with ML model:

```bash
python -m src.main -d test_samples --use-ml-model -v
```

---

## 💡 Pro Tips

1. **Free GPU limits**: Colab gives ~12 hours/day of GPU time
2. **Train overnight**: Start training before bed
3. **Save frequently**: Copy checkpoints to Drive every few epochs
4. **Use TPU**: For even faster training (Runtime → TPU)

---

## 🆚 Colab vs Laptop

| Feature | Laptop (CPU) | Colab (GPU) |
|---------|--------------|-------------|
| Training Time | 20-40 hours | 2-4 hours |
| Cost | Free | Free |
| Usability | Laptop locked | Work normally |
| Memory | 8 GB | 15 GB |
| GPU | None | Tesla T4 |

**Winner:** Google Colab 🏆

---

## 📝 Complete Colab Notebook Template

```python
# Cell 1: Setup
!git clone https://github.com/Parthpatil7/PatchScout.git
%cd PatchScout
!pip install torch transformers scikit-learn pandas numpy tqdm openpyxl pyyaml rich

# Cell 2: Mount Drive (for saving)
from google.colab import drive
drive.mount('/content/drive')

# Cell 3: Download Datasets
!python train_model.py --download --datasets devign megavul diversevul

# Cell 4: Start Training
!python train_model.py \
    --datasets devign megavul diversevul \
    --batch-size 32 \
    --num-epochs 10 \
    --device cuda

# Cell 5: Save to Drive
!mkdir -p /content/drive/MyDrive/PatchScout
!cp -r models/checkpoints/* /content/drive/MyDrive/PatchScout/

# Cell 6: Download locally
from google.colab import files
files.download('models/checkpoints/best_model.pt')
```

Just copy-paste these cells one by one! ✅
