import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import LabelEncoder, label_binarize
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    roc_curve, auc, precision_recall_curve, average_precision_score,
    precision_recall_fscore_support
)
from xgboost import XGBClassifier
import joblib
import warnings
import time

warnings.filterwarnings('ignore')

sns.set_style('whitegrid')
plt.rcParams['figure.figsize'] = (12, 8)

print("=" * 70)
print("🚀 XGBoost Network Attack Classification - NetGuardian")
print("=" * 70)

# ═══════════════════════════════════════════════════════
# 1. LOAD DATA
# ═══════════════════════════════════════════════════════
print("\n📂 Loading dataset...")
df = pd.read_csv('agg_edited.csv')
print(f"✅ Dataset loaded: {df.shape[0]} samples, {df.shape[1]} features")

print("\n📊 Dataset Overview:")
print(df.head())
print(f"\n📈 Class Distribution:")
print(df['label'].value_counts())

# ═══════════════════════════════════════════════════════
# 2. PREPARE DATA
# ═══════════════════════════════════════════════════════
X = df.drop(['label', 'src_ip', 'window_start', 'window_end'], axis=1)
y = df['label']

label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

attack_names = label_encoder.classes_
num_classes = len(attack_names)

print(f"\n🎯 Attack Types ({num_classes} classes):")
for idx, attack in enumerate(attack_names):
    print(f"   {idx}: {attack}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

print(f"\n✂️ Data Split:")
print(f"   Training: {len(X_train)} | Testing: {len(X_test)}")
print(f"   Features: {X_train.shape[1]}")

# ═══════════════════════════════════════════════════════
# 3. BUILD MODEL
# ═══════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("🔧 Building XGBoost Model...")
print("=" * 70)

xgb_model = XGBClassifier(
    objective="multi:softprob",
    num_class=num_classes,
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    n_jobs=-1,
    eval_metric="mlogloss",
    verbosity=1
)

# ═══════════════════════════════════════════════════════
# 4. TRAIN MODEL
# ═══════════════════════════════════════════════════════
print("\n🎓 Training XGBoost Model...")
start = time.time()

xgb_model.fit(
    X_train,
    y_train,
    eval_set=[(X_train, y_train), (X_test, y_test)],
    verbose=False
)

train_time = time.time() - start
print(f"✅ Training completed in {train_time:.2f} seconds")

# ═══════════════════════════════════════════════════════
# 5. EVALUATE
# ═══════════════════════════════════════════════════════
print("\n🔮 Evaluating model...")
y_pred = xgb_model.predict(X_test)
y_pred_proba = xgb_model.predict_proba(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n🎯 Overall Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")

print("\n" + "=" * 70)
print("📊 CLASSIFICATION REPORT")
print("=" * 70)
print(classification_report(y_test, y_pred, target_names=attack_names, digits=4))

# ═══════════════════════════════════════════════════════
# 6. VISUALIZATIONS
# ═══════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("📊 GENERATING VISUALIZATIONS")
print("=" * 70)

# 6.1 Confusion Matrix
print("\n📉 1/10 Generating Confusion Matrix...")
cm = confusion_matrix(y_test, y_pred)

plt.figure(figsize=(14, 12))
sns.heatmap(
    cm, annot=True, fmt='d', cmap='RdYlGn',
    xticklabels=attack_names, yticklabels=attack_names,
    linewidths=0.5, linecolor='gray'
)
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('XGBoost Confusion Matrix - NetGuardian')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig('1_confusion_matrix.png', dpi=300)
plt.close()
print("   ✅ Saved: 1_confusion_matrix.png")

# 6.2 Feature Importance
print("\n🔍 2/10 Generating Feature Importance...")
feat_imp = pd.DataFrame({
    'Feature': X_train.columns,
    'Importance': xgb_model.feature_importances_
}).sort_values('Importance', ascending=False)

print("\n🏆 Top 20 Features:")
print(feat_imp.head(20).to_string(index=False))

plt.figure(figsize=(12, 8))
top_features = feat_imp.head(20)
sns.barplot(data=top_features, x='Importance', y='Feature', palette='viridis')
plt.title('Top 20 Most Important Features', fontsize=16, fontweight='bold')
plt.xlabel('Importance Score', fontsize=12)
plt.ylabel('Feature', fontsize=12)
plt.tight_layout()
plt.savefig('2_feature_importance.png', dpi=300)
plt.close()
print("   ✅ Saved: 2_feature_importance.png")

# 6.3 Learning Curves
print("\n📈 3/10 Generating Learning Curves...")
results = xgb_model.evals_result()

plt.figure(figsize=(12, 6))
plt.plot(results['validation_0']['mlogloss'], label='Train Loss', linewidth=2)
plt.plot(results['validation_1']['mlogloss'], label='Test Loss', linewidth=2)
plt.xlabel('Iterations', fontsize=12)
plt.ylabel('Log Loss', fontsize=12)
plt.title('XGBoost Learning Curves', fontsize=16, fontweight='bold')
plt.legend(fontsize=11)
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('3_learning_curves.png', dpi=300)
plt.close()
print("   ✅ Saved: 3_learning_curves.png")

# 6.4 ROC Curves
print("\n📊 4/10 Generating ROC Curves...")
y_test_bin = label_binarize(y_test, classes=range(num_classes))

plt.figure(figsize=(12, 10))
for i in range(num_classes):
    fpr, tpr, _ = roc_curve(y_test_bin[:, i], y_pred_proba[:, i])
    roc_auc = auc(fpr, tpr)
    plt.plot(fpr, tpr, linewidth=2, label=f'{attack_names[i]} (AUC = {roc_auc:.3f})')

plt.plot([0, 1], [0, 1], 'k--', linewidth=2, label='Random Classifier')
plt.xlabel('False Positive Rate', fontsize=12)
plt.ylabel('True Positive Rate', fontsize=12)
plt.title('ROC Curves for All Attack Types', fontsize=16, fontweight='bold')
plt.legend(loc='lower right', fontsize=9)
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('4_roc_curves.png', dpi=300)
plt.close()
print("   ✅ Saved: 4_roc_curves.png")

# 6.5 Precision-Recall Curves
print("\n📉 5/10 Generating Precision-Recall Curves...")
plt.figure(figsize=(12, 10))
for i in range(num_classes):
    precision, recall, _ = precision_recall_curve(y_test_bin[:, i], y_pred_proba[:, i])
    ap = average_precision_score(y_test_bin[:, i], y_pred_proba[:, i])
    plt.plot(recall, precision, linewidth=2, label=f'{attack_names[i]} (AP = {ap:.3f})')

plt.xlabel('Recall', fontsize=12)
plt.ylabel('Precision', fontsize=12)
plt.title('Precision-Recall Curves', fontsize=16, fontweight='bold')
plt.legend(loc='best', fontsize=9)
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('5_precision_recall_curves.png', dpi=300)
plt.close()
print("   ✅ Saved: 5_precision_recall_curves.png")

# 6.6 Class Distribution Comparison
print("\n📊 6/10 Generating Class Distribution...")
fig, axes = plt.subplots(1, 2, figsize=(16, 6))

df['label'].value_counts().plot(kind='bar', ax=axes[0], color='skyblue', edgecolor='black')
axes[0].set_title('Original Class Distribution', fontsize=14, fontweight='bold')
axes[0].set_ylabel('Count', fontsize=12)
axes[0].set_xlabel('Attack Type', fontsize=12)
axes[0].tick_params(axis='x', rotation=45)
axes[0].grid(True, alpha=0.3, axis='y')

pd.Series([attack_names[i] for i in y_pred]).value_counts().plot(
    kind='bar', ax=axes[1], color='lightcoral', edgecolor='black'
)
axes[1].set_title('Predicted Class Distribution', fontsize=14, fontweight='bold')
axes[1].set_ylabel('Count', fontsize=12)
axes[1].set_xlabel('Attack Type', fontsize=12)
axes[1].tick_params(axis='x', rotation=45)
axes[1].grid(True, alpha=0.3, axis='y')

plt.tight_layout()
plt.savefig('6_class_distribution.png', dpi=300)
plt.close()
print("   ✅ Saved: 6_class_distribution.png")

# 6.7 Per-Class Metrics
print("\n📈 7/10 Generating Per-Class Metrics...")
precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average=None)

fig, ax = plt.subplots(figsize=(14, 8))
x = np.arange(len(attack_names))
width = 0.25

bars1 = ax.bar(x - width, precision, width, label='Precision', color='#2ecc71', edgecolor='black')
bars2 = ax.bar(x, recall, width, label='Recall', color='#3498db', edgecolor='black')
bars3 = ax.bar(x + width, f1, width, label='F1-Score', color='#e74c3c', edgecolor='black')

ax.set_xlabel('Attack Type', fontsize=12)
ax.set_ylabel('Score', fontsize=12)
ax.set_title('Per-Class Performance Metrics', fontsize=16, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(attack_names, rotation=45, ha='right')
ax.legend(fontsize=11)
ax.grid(True, alpha=0.3, axis='y')
ax.set_ylim([0, 1.1])
plt.tight_layout()
plt.savefig('7_per_class_metrics.png', dpi=300)
plt.close()
print("   ✅ Saved: 7_per_class_metrics.png")

# 6.8 Prediction Confidence Distribution
print("\n📊 8/10 Generating Confidence Distribution...")
confidence = np.max(y_pred_proba, axis=1)

plt.figure(figsize=(12, 6))
plt.hist(confidence, bins=50, color='purple', alpha=0.7, edgecolor='black')
plt.xlabel('Prediction Confidence', fontsize=12)
plt.ylabel('Frequency', fontsize=12)
plt.title('Distribution of Prediction Confidence', fontsize=16, fontweight='bold')
plt.axvline(confidence.mean(), color='red', linestyle='--', linewidth=2,
            label=f'Mean: {confidence.mean():.3f}')
plt.axvline(np.median(confidence), color='green', linestyle='--', linewidth=2,
            label=f'Median: {np.median(confidence):.3f}')
plt.legend(fontsize=11)
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('8_confidence_distribution.png', dpi=300)
plt.close()
print("   ✅ Saved: 8_confidence_distribution.png")

# 6.9 Error Analysis
print("\n🔍 9/10 Generating Error Analysis...")
misclassified = y_test != y_pred
if misclassified.sum() > 0:
    error_types = pd.DataFrame({
        'True': [attack_names[i] for i in y_test[misclassified]],
        'Predicted': [attack_names[i] for i in y_pred[misclassified]]
    })
    
    error_counts = error_types.groupby(['True', 'Predicted']).size().reset_index(name='Count')
    error_counts = error_counts.sort_values('Count', ascending=False).head(10)
    
    plt.figure(figsize=(12, 8))
    error_labels = error_counts['True'] + ' → ' + error_counts['Predicted']
    sns.barplot(data=error_counts, x='Count', y=error_labels, palette='Reds_r')
    plt.title('Top 10 Misclassification Patterns', fontsize=16, fontweight='bold')
    plt.xlabel('Number of Misclassifications', fontsize=12)
    plt.ylabel('True → Predicted', fontsize=12)
    plt.tight_layout()
    plt.savefig('9_error_analysis.png', dpi=300)
    plt.close()
    print("   ✅ Saved: 9_error_analysis.png")
else:
    print("   ⚠️ No misclassifications found!")

# 6.10 Cross-Validation Scores
print("\n✅ 10/10 Running Cross-Validation & Plotting...")
cv_scores = cross_val_score(
    XGBClassifier(**xgb_model.get_params()),
    X_train,
    y_train,
    cv=5,
    scoring='accuracy',
    n_jobs=-1
)

print(f"CV Scores: {[f'{s:.4f}' for s in cv_scores]}")
print(f"Mean: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

plt.figure(figsize=(10, 6))
bars = plt.bar(range(1, len(cv_scores) + 1), cv_scores, color='teal', alpha=0.7, edgecolor='black')
plt.axhline(cv_scores.mean(), color='red', linestyle='--', linewidth=2,
            label=f'Mean: {cv_scores.mean():.4f}')
for i, (bar, score) in enumerate(zip(bars, cv_scores)):
    plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.005,
             f'{score:.4f}', ha='center', va='bottom', fontsize=10)
plt.xlabel('Fold Number', fontsize=12)
plt.ylabel('Accuracy Score', fontsize=12)
plt.title('Cross-Validation Scores (5-Fold)', fontsize=16, fontweight='bold')
plt.xticks(range(1, len(cv_scores) + 1))
plt.ylim([min(cv_scores) - 0.02, 1.0])
plt.legend(fontsize=11)
plt.grid(True, alpha=0.3, axis='y')
plt.tight_layout()
plt.savefig('10_cv_scores.png', dpi=300)
plt.close()
print("   ✅ Saved: 10_cv_scores.png")

print("\n" + "=" * 70)
print("✅ ALL VISUALIZATIONS COMPLETED!")
print("=" * 70)

# ═══════════════════════════════════════════════════════
# 7. SAVE MODEL
# ═══════════════════════════════════════════════════════
print("\n💾 SAVING MODEL")

xgb_model.get_booster().save_model("xgboost_model.json")
joblib.dump(xgb_model, "xgb_model.pkl")
joblib.dump(label_encoder, "label_encoder.pkl")
joblib.dump(X_train.columns.tolist(), "feature_names.pkl")

print("✅ Saved: xgboost_model.json")
print("✅ Saved: xgb_model.pkl")
print("✅ Saved: label_encoder.pkl")
print("✅ Saved: feature_names.pkl")

# ═══════════════════════════════════════════════════════
# 8. SUMMARY
# ═══════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("📋 MODEL SUMMARY")
print("=" * 70)
print(f"""
Model: XGBoost Classifier
Classes: {num_classes}
Training Samples: {len(X_train)}
Testing Samples: {len(X_test)}
Features: {X_train.shape[1]}
Training Time: {train_time:.2f}s
Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)
CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})
Avg Confidence: {confidence.mean():.4f}
Misclassifications: {misclassified.sum()}
""")

print("\n📁 Generated Files:")
files = [
    "1_confusion_matrix.png",
    "2_feature_importance.png",
    "3_learning_curves.png",
    "4_roc_curves.png",
    "5_precision_recall_curves.png",
    "6_class_distribution.png",
    "7_per_class_metrics.png",
    "8_confidence_distribution.png",
    "9_error_analysis.png",
    "10_cv_scores.png",
    "xgboost_model.json",
    "xgb_model.pkl",
    "label_encoder.pkl",
    "feature_names.pkl"
]

for f in files:
    print(f"   ✅ {f}")

print("\n" + "=" * 70)
print("🎉 TRAINING COMPLETE!")
print("=" * 70)