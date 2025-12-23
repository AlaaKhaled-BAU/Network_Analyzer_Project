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
df = pd.read_csv('agg_new_ports_count12.csv')
print(f"✅ Dataset loaded: {df.shape[0]} samples, {df.shape[1]} features")

print("\n📊 Dataset Overview:")
print(df.head())
print(f"\n📈 Class Distribution:")
print(df['label'].value_counts())

# ═══════════════════════════════════════════════════════
# 2. PREPARE DATA
# ═══════════════════════════════════════════════════════
X = df.drop(['label', 'src_ip', 'window_start', 'window_end','variation','suspicious_mac_changes','duplicate_mac_ips','pct_high_entropy_queries','udp_ports_hit','request_completion_ratio','avg_answer_size'], axis=1)
y = df['label']

label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

attack_names = label_encoder.classes_
num_classes = len(attack_names)

print(f"\n🎯 Attack Types ({num_classes} classes):")
for idx, attack in enumerate(attack_names):
    print(f"   {idx}: {attack}")

# ═══════════════════════════════════════════════════════
# 3. MULTIPLE RUNS SETUP
# ═══════════════════════════════════════════════════════
NUM_RUNS = 10
print("\n" + "=" * 70)
print(f"🔄 RUNNING {NUM_RUNS} ITERATIONS FOR ROBUST EVALUATION")
print("=" * 70)

# Storage for metrics across runs
all_accuracies = []
all_train_times = []
all_cv_scores = []
all_confidences = []
all_misclassifications = []
all_feature_importances = []
all_confusion_matrices = []
all_y_pred_all = []
all_y_test_all = []
all_y_pred_proba_all = []
all_precisions = []
all_recalls = []
all_f1s = []

# Store results from best run for visualization
best_run_idx = 0
best_accuracy = 0

for run in range(NUM_RUNS):
    print(f"\n{'=' * 70}")
    print(f"📊 RUN {run + 1}/{NUM_RUNS}")
    print(f"{'=' * 70}")
    
    # Split data with different random state for each run
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42 + run, stratify=y_encoded
    )
    
    print(f"✂️ Data Split: Training: {len(X_train)} | Testing: {len(X_test)}")
    
    # Build model
    xgb_model = XGBClassifier(
        objective="multi:softprob",
        num_class=num_classes,
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42 + run,
        n_jobs=-1,
        eval_metric="mlogloss",
        verbosity=0
    )
    
    # Train model
    print("🎓 Training XGBoost Model...")
    start = time.time()
    xgb_model.fit(
        X_train,
        y_train,
        eval_set=[(X_train, y_train), (X_test, y_test)],
        verbose=False
    )
    train_time = time.time() - start
    all_train_times.append(train_time)
    print(f"✅ Training completed in {train_time:.2f} seconds")
    
    # Evaluate
    print("🔮 Evaluating model...")
    y_pred = xgb_model.predict(X_test)
    y_pred_proba = xgb_model.predict_proba(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    all_accuracies.append(accuracy)
    
    # Store predictions for averaging later
    all_y_pred_all.append(y_pred)
    all_y_test_all.append(y_test)
    all_y_pred_proba_all.append(y_pred_proba)
    
    # Calculate per-class metrics
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average=None)
    all_precisions.append(precision)
    all_recalls.append(recall)
    all_f1s.append(f1)
    
    # Store confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    all_confusion_matrices.append(cm)
    
    # Store feature importance
    all_feature_importances.append(xgb_model.feature_importances_)
    
    # Calculate confidence
    confidence = np.max(y_pred_proba, axis=1)
    all_confidences.append(confidence.mean())
    
    # Count misclassifications
    misclassified = (y_test != y_pred).sum()
    all_misclassifications.append(misclassified)
    
    # Cross-validation
    print("✅ Running Cross-Validation...")
    cv_scores = cross_val_score(
        XGBClassifier(**xgb_model.get_params()),
        X_train,
        y_train,
        cv=5,
        scoring='accuracy',
        n_jobs=-1,
        verbose=0
    )
    all_cv_scores.append(cv_scores.mean())
    
    print(f"🎯 Run {run + 1} Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"📊 Run {run + 1} CV Score: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    
    # Track best run
    if accuracy > best_accuracy:
        best_accuracy = accuracy
        best_run_idx = run
        best_model = xgb_model
        best_X_train = X_train
        best_X_test = X_test
        best_y_train = y_train
        best_y_test = y_test
        best_y_pred = y_pred
        best_y_pred_proba = y_pred_proba
        best_confidence = confidence
        best_cm = cm
        best_cv_scores = cv_scores

# ═══════════════════════════════════════════════════════
# 4. AGGREGATE RESULTS
# ═══════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("📈 AGGREGATED RESULTS FROM 10 RUNS")
print("=" * 70)

mean_accuracy = np.mean(all_accuracies)
std_accuracy = np.std(all_accuracies)
mean_train_time = np.mean(all_train_times)
std_train_time = np.std(all_train_times)
mean_cv_score = np.mean(all_cv_scores)
std_cv_score = np.std(all_cv_scores)
mean_confidence = np.mean(all_confidences)
std_confidence = np.std(all_confidences)
mean_misclassifications = np.mean(all_misclassifications)
std_misclassifications = np.std(all_misclassifications)

# Average feature importance
avg_feature_importance = np.mean(all_feature_importances, axis=0)

# Average per-class metrics
avg_precision = np.mean(all_precisions, axis=0)
avg_recall = np.mean(all_recalls, axis=0)
avg_f1 = np.mean(all_f1s, axis=0)

# Average confusion matrix
avg_confusion_matrix = np.mean(all_confusion_matrices, axis=0)

print(f"\n🎯 Average Accuracy: {mean_accuracy:.4f} ± {std_accuracy:.4f} ({mean_accuracy*100:.2f}%)")
print(f"⏱️  Average Training Time: {mean_train_time:.2f} ± {std_train_time:.2f} seconds")
print(f"📊 Average CV Score: {mean_cv_score:.4f} ± {std_cv_score:.4f}")
print(f"🔮 Average Confidence: {mean_confidence:.4f} ± {std_confidence:.4f}")
print(f"❌ Average Misclassifications: {mean_misclassifications:.1f} ± {std_misclassifications:.1f}")
print(f"\n🏆 Best Run: #{best_run_idx + 1} with accuracy {best_accuracy:.4f}")

# ═══════════════════════════════════════════════════════
# 5. CLASSIFICATION REPORT (Best Run)
# ═══════════════════════════════════════════════════════
print("\n" + "=" * 70)
print(f"📊 CLASSIFICATION REPORT (Best Run #{best_run_idx + 1})")
print("=" * 70)
print(classification_report(best_y_test, best_y_pred, target_names=attack_names, digits=4))

# ═══════════════════════════════════════════════════════
# 6. VISUALIZATIONS
# ═══════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("📊 GENERATING VISUALIZATIONS")
print("=" * 70)

# 6.1 Average Confusion Matrix (NEW!)
print("\n📉 1/14 Generating Average Confusion Matrix (10 Runs)...")
plt.figure(figsize=(14, 12))
sns.heatmap(
    avg_confusion_matrix, annot=True, fmt='.1f', cmap='RdYlGn',
    xticklabels=attack_names, yticklabels=attack_names,
    linewidths=0.5, linecolor='gray'
)
plt.xlabel('Predicted', fontsize=12)
plt.ylabel('Actual', fontsize=12)
plt.title(f'XGBoost Average Confusion Matrix (10 Runs)', fontsize=16, fontweight='bold')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig('1_avg_confusion_matrix.png', dpi=300)
plt.close()
print("   ✅ Saved: 1_avg_confusion_matrix.png")

# 6.2 Confusion Matrix (Best Run)
print("\n📉 2/14 Generating Confusion Matrix (Best Run)...")
plt.figure(figsize=(14, 12))
sns.heatmap(
    best_cm, annot=True, fmt='d', cmap='RdYlGn',
    xticklabels=attack_names, yticklabels=attack_names,
    linewidths=0.5, linecolor='gray'
)
plt.xlabel('Predicted', fontsize=12)
plt.ylabel('Actual', fontsize=12)
plt.title(f'XGBoost Confusion Matrix - Best Run #{best_run_idx + 1}', fontsize=16, fontweight='bold')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig('2_confusion_matrix_best.png', dpi=300)
plt.close()
print("   ✅ Saved: 2_confusion_matrix_best.png")

# 6.3 Average Feature Importance
print("\n🔍 3/14 Generating Average Feature Importance...")
feat_imp = pd.DataFrame({
    'Feature': X.columns,
    'Importance': avg_feature_importance
}).sort_values('Importance', ascending=False)

print("\n🏆 Top 20 Features (Averaged):")
print(feat_imp.head(20).to_string(index=False))

plt.figure(figsize=(12, 8))
top_features = feat_imp.head(20)
sns.barplot(data=top_features, x='Importance', y='Feature', palette='viridis')
plt.title('Top 20 Most Important Features (Avg of 10 Runs)', fontsize=16, fontweight='bold')
plt.xlabel('Average Importance Score', fontsize=12)
plt.ylabel('Feature', fontsize=12)
plt.tight_layout()
plt.savefig('3_feature_importance.png', dpi=300)
plt.close()
print("   ✅ Saved: 3_feature_importance.png")

# 6.4 ALL FEATURES CONTRIBUTION PERCENTAGE
print("\n📊 4/14 Generating Complete Feature Contribution Percentage...")
feat_imp_pct = feat_imp.copy()
total_importance = feat_imp_pct['Importance'].sum()
feat_imp_pct['Contribution %'] = (feat_imp_pct['Importance'] / total_importance) * 100
feat_imp_pct['Cumulative %'] = feat_imp_pct['Contribution %'].cumsum()

feat_imp_pct.to_csv('all_features_contribution.csv', index=False)
print(f"   ✅ Saved: all_features_contribution.csv ({len(feat_imp_pct)} features)")

print("\n🎯 Top 30 Features by Contribution Percentage:")
print(feat_imp_pct.head(30)[['Feature', 'Contribution %', 'Cumulative %']].to_string(index=False))

fig, axes = plt.subplots(2, 1, figsize=(16, 20))

colors = plt.cm.viridis(np.linspace(0, 1, len(feat_imp_pct)))
axes[0].barh(range(len(feat_imp_pct)), feat_imp_pct['Contribution %'], color=colors, edgecolor='black', linewidth=0.5)
axes[0].set_yticks(range(len(feat_imp_pct)))
axes[0].set_yticklabels(feat_imp_pct['Feature'], fontsize=6)
axes[0].set_xlabel('Contribution Percentage (%)', fontsize=12, fontweight='bold')
axes[0].set_ylabel('Feature', fontsize=12, fontweight='bold')
axes[0].set_title(f'All Features Contribution % ({len(feat_imp_pct)} Features) - Avg of 10 Runs', 
                  fontsize=16, fontweight='bold', pad=20)
axes[0].grid(True, alpha=0.3, axis='x')
axes[0].invert_yaxis()

for i in range(min(20, len(feat_imp_pct))):
    pct = feat_imp_pct.iloc[i]['Contribution %']
    axes[0].text(pct + 0.1, i, f'{pct:.2f}%', va='center', fontsize=7, fontweight='bold')

axes[1].plot(range(len(feat_imp_pct)), feat_imp_pct['Cumulative %'], 
             linewidth=3, color='#e74c3c', marker='o', markersize=3, markeredgecolor='darkred')
axes[1].fill_between(range(len(feat_imp_pct)), feat_imp_pct['Cumulative %'], 
                      alpha=0.3, color='#e74c3c')
axes[1].axhline(y=50, color='green', linestyle='--', linewidth=2, label='50% Contribution')
axes[1].axhline(y=80, color='orange', linestyle='--', linewidth=2, label='80% Contribution')
axes[1].axhline(y=95, color='red', linestyle='--', linewidth=2, label='95% Contribution')
axes[1].set_xlabel('Number of Features', fontsize=12, fontweight='bold')
axes[1].set_ylabel('Cumulative Contribution (%)', fontsize=12, fontweight='bold')
axes[1].set_title('Cumulative Feature Contribution (Avg of 10 Runs)', fontsize=16, fontweight='bold', pad=20)
axes[1].grid(True, alpha=0.3)
axes[1].legend(fontsize=11, loc='lower right')
axes[1].set_xlim([0, len(feat_imp_pct)])
axes[1].set_ylim([0, 105])

for threshold in [50, 80, 95]:
    n_features = (feat_imp_pct['Cumulative %'] <= threshold).sum()
    axes[1].annotate(f'{n_features} features\n→ {threshold}%',
                     xy=(n_features, threshold),
                     xytext=(n_features + 5, threshold - 10),
                     fontsize=9, fontweight='bold',
                     bbox=dict(boxstyle='round,pad=0.5', facecolor='yellow', alpha=0.7),
                     arrowprops=dict(arrowstyle='->', color='black', lw=1.5))

plt.tight_layout()
plt.savefig('4_all_features_contribution.png', dpi=300, bbox_inches='tight')
plt.close()
print("   ✅ Saved: 4_all_features_contribution.png")

print("\n📈 Feature Contribution Statistics:")
print(f"   Total Features: {len(feat_imp_pct)}")
print(f"   Features for 50% contribution: {(feat_imp_pct['Cumulative %'] <= 50).sum()}")
print(f"   Features for 80% contribution: {(feat_imp_pct['Cumulative %'] <= 80).sum()}")
print(f"   Features for 95% contribution: {(feat_imp_pct['Cumulative %'] <= 95).sum()}")
print(f"   Top feature contribution: {feat_imp_pct.iloc[0]['Contribution %']:.2f}%")
print(f"   Top 5 features contribution: {feat_imp_pct.head(5)['Contribution %'].sum():.2f}%")
print(f"   Top 10 features contribution: {feat_imp_pct.head(10)['Contribution %'].sum():.2f}%")

# 6.5 Accuracy Across 10 Runs
print("\n📊 5/14 Generating Accuracy Across Runs...")
plt.figure(figsize=(12, 6))
runs = range(1, NUM_RUNS + 1)
bars = plt.bar(runs, all_accuracies, color='steelblue', alpha=0.7, edgecolor='black')
bars[best_run_idx].set_color('gold')
bars[best_run_idx].set_edgecolor('darkgoldenrod')
bars[best_run_idx].set_linewidth(3)

plt.axhline(mean_accuracy, color='red', linestyle='--', linewidth=2, 
            label=f'Mean: {mean_accuracy:.4f}')
plt.fill_between(runs, mean_accuracy - std_accuracy, mean_accuracy + std_accuracy, 
                 alpha=0.2, color='red', label=f'Std Dev: ±{std_accuracy:.4f}')

for i, (bar, acc) in enumerate(zip(bars, all_accuracies)):
    plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.002,
             f'{acc:.4f}', ha='center', va='bottom', fontsize=9, fontweight='bold')

plt.xlabel('Run Number', fontsize=12)
plt.ylabel('Accuracy', fontsize=12)
plt.title(f'Accuracy Across {NUM_RUNS} Runs (Gold = Best Run)', fontsize=16, fontweight='bold')
plt.legend(fontsize=11)
plt.grid(True, alpha=0.3, axis='y')
plt.ylim([min(all_accuracies) - 0.01, max(all_accuracies) + 0.02])
plt.tight_layout()
plt.savefig('5_accuracy_across_runs.png', dpi=300)
plt.close()
print("   ✅ Saved: 5_accuracy_across_runs.png")

# 6.6 Learning Curves (Best Run)
print("\n📈 6/14 Generating Learning Curves (Best Run)...")
results = best_model.evals_result()

plt.figure(figsize=(12, 6))
plt.plot(results['validation_0']['mlogloss'], label='Train Loss', linewidth=2)
plt.plot(results['validation_1']['mlogloss'], label='Test Loss', linewidth=2)
plt.xlabel('Iterations', fontsize=12)
plt.ylabel('Log Loss', fontsize=12)
plt.title(f'XGBoost Learning Curves - Best Run #{best_run_idx + 1}', fontsize=16, fontweight='bold')
plt.legend(fontsize=11)
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('6_learning_curves.png', dpi=300)
plt.close()
print("   ✅ Saved: 6_learning_curves.png")

# 6.7 ROC Curves (Best Run)
print("\n📊 7/14 Generating ROC Curves (Best Run)...")
y_test_bin = label_binarize(best_y_test, classes=range(num_classes))

plt.figure(figsize=(12, 10))
for i in range(num_classes):
    fpr, tpr, _ = roc_curve(y_test_bin[:, i], best_y_pred_proba[:, i])
    roc_auc = auc(fpr, tpr)
    plt.plot(fpr, tpr, linewidth=2, label=f'{attack_names[i]} (AUC = {roc_auc:.3f})')

plt.plot([0, 1], [0, 1], 'k--', linewidth=2, label='Random Classifier')
plt.xlabel('False Positive Rate', fontsize=12)
plt.ylabel('True Positive Rate', fontsize=12)
plt.title(f'ROC Curves - Best Run #{best_run_idx + 1}', fontsize=16, fontweight='bold')
plt.legend(loc='lower right', fontsize=9)
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('7_roc_curves.png', dpi=300)
plt.close()
print("   ✅ Saved: 7_roc_curves.png")

# 6.8 Precision-Recall Curves (Best Run)
print("\n📉 8/14 Generating Precision-Recall Curves (Best Run)...")
plt.figure(figsize=(12, 10))
for i in range(num_classes):
    precision, recall, _ = precision_recall_curve(y_test_bin[:, i], best_y_pred_proba[:, i])
    ap = average_precision_score(y_test_bin[:, i], best_y_pred_proba[:, i])
    plt.plot(recall, precision, linewidth=2, label=f'{attack_names[i]} (AP = {ap:.3f})')

plt.xlabel('Recall', fontsize=12)
plt.ylabel('Precision', fontsize=12)
plt.title(f'Precision-Recall Curves - Best Run #{best_run_idx + 1}', fontsize=16, fontweight='bold')
plt.legend(loc='best', fontsize=9)
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('8_precision_recall_curves.png', dpi=300)
plt.close()
print("   ✅ Saved: 8_precision_recall_curves.png")

# 6.9 Class Distribution Comparison
print("\n📊 9/14 Generating Class Distribution...")
fig, axes = plt.subplots(1, 2, figsize=(16, 6))

df['label'].value_counts().plot(kind='bar', ax=axes[0], color='skyblue', edgecolor='black')
axes[0].set_title('Original Class Distribution', fontsize=14, fontweight='bold')
axes[0].set_ylabel('Count', fontsize=12)
axes[0].set_xlabel('Attack Type', fontsize=12)
axes[0].tick_params(axis='x', rotation=45)
axes[0].grid(True, alpha=0.3, axis='y')

pd.Series([attack_names[i] for i in best_y_pred]).value_counts().plot(
    kind='bar', ax=axes[1], color='lightcoral', edgecolor='black'
)
axes[1].set_title(f'Predicted Class Distribution - Best Run #{best_run_idx + 1}', fontsize=14, fontweight='bold')
axes[1].set_ylabel('Count', fontsize=12)
axes[1].set_xlabel('Attack Type', fontsize=12)
axes[1].tick_params(axis='x', rotation=45)
axes[1].grid(True, alpha=0.3, axis='y')

plt.tight_layout()
plt.savefig('9_class_distribution.png', dpi=300)
plt.close()
print("   ✅ Saved: 9_class_distribution.png")

# 6.10 Average Per-Class Metrics
print("\n📈 10/14 Generating Average Per-Class Metrics...")
fig, ax = plt.subplots(figsize=(14, 8))
x = np.arange(len(attack_names))
width = 0.25

bars1 = ax.bar(x - width, avg_precision, width, label='Precision', color='#2ecc71', edgecolor='black')
bars2 = ax.bar(x, avg_recall, width, label='Recall', color='#3498db', edgecolor='black')
bars3 = ax.bar(x + width, avg_f1, width, label='F1-Score', color='#e74c3c', edgecolor='black')

ax.set_xlabel('Attack Type', fontsize=12)
ax.set_ylabel('Score', fontsize=12)
ax.set_title('Per-Class Performance Metrics (Avg of 10 Runs)', fontsize=16, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(attack_names, rotation=45, ha='right')
ax.legend(fontsize=11)
ax.grid(True, alpha=0.3, axis='y')
ax.set_ylim([0, 1.1])
plt.tight_layout()
plt.savefig('10_per_class_metrics.png', dpi=300)
plt.close()
print("   ✅ Saved: 10_per_class_metrics.png")

# 6.11 Prediction Confidence Distribution (Best Run)
print("\n📊 11/14 Generating Confidence Distribution (Best Run)...")
plt.figure(figsize=(12, 6))
plt.hist(best_confidence, bins=50, color='purple', alpha=0.7, edgecolor='black')
plt.xlabel('Prediction Confidence', fontsize=12)
plt.ylabel('Frequency', fontsize=12)
plt.title(f'Prediction Confidence Distribution - Best Run #{best_run_idx + 1}', fontsize=16, fontweight='bold')
plt.axvline(best_confidence.mean(), color='red', linestyle='--', linewidth=2,
            label=f'Mean: {best_confidence.mean():.3f}')
plt.axvline(np.median(best_confidence), color='green', linestyle='--', linewidth=2,
            label=f'Median: {np.median(best_confidence):.3f}')
plt.legend(fontsize=11)
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('11_confidence_distribution.png', dpi=300)
plt.close()
print("   ✅ Saved: 11_confidence_distribution.png")

# 6.12 Error Analysis (Best Run)
print("\n🔍 12/14 Generating Error Analysis (Best Run)...")
misclassified = best_y_test != best_y_pred
if misclassified.sum() > 0:
    error_types = pd.DataFrame({
        'True': [attack_names[i] for i in best_y_test[misclassified]],
        'Predicted': [attack_names[i] for i in best_y_pred[misclassified]]
    })
    
    error_counts = error_types.groupby(['True', 'Predicted']).size().reset_index(name='Count')
    error_counts = error_counts.sort_values('Count', ascending=False).head(10)
    
    plt.figure(figsize=(12, 8))
    error_labels = error_counts['True'] + ' → ' + error_counts['Predicted']
    sns.barplot(data=error_counts, x='Count', y=error_labels, palette='Reds_r')
    plt.title(f'Top 10 Misclassification Patterns - Best Run #{best_run_idx + 1}', fontsize=16, fontweight='bold')
    plt.xlabel('Number of Misclassifications', fontsize=12)
    plt.ylabel('True → Predicted', fontsize=12)
    plt.tight_layout()
    plt.savefig('12_error_analysis.png', dpi=300)
    plt.close()
    print("   ✅ Saved: 12_error_analysis.png")
else:
    print("   ⚠️ No misclassifications found!")

# 6.13 Cross-Validation Scores (Best Run)
print("\n✅ 13/14 Plotting Cross-Validation Scores (Best Run)...")
plt.figure(figsize=(10, 6))
bars = plt.bar(range(1, len(best_cv_scores) + 1), best_cv_scores, color='teal', alpha=0.7, edgecolor='black')
plt.axhline(best_cv_scores.mean(), color='red', linestyle='--', linewidth=2,
            label=f'Mean: {best_cv_scores.mean():.4f}')
for i, (bar, score) in enumerate(zip(bars, best_cv_scores)):
    plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.005,
             f'{score:.4f}', ha='center', va='bottom', fontsize=10)
plt.xlabel('Fold Number', fontsize=12)
plt.ylabel('Accuracy Score', fontsize=12)
plt.title(f'Cross-Validation Scores (5-Fold) - Best Run #{best_run_idx + 1}', fontsize=16, fontweight='bold')
plt.xticks(range(1, len(best_cv_scores) + 1))
plt.ylim([min(best_cv_scores) - 0.02, 1.0])
plt.legend(fontsize=11)
plt.grid(True, alpha=0.3, axis='y')
plt.tight_layout()
plt.savefig('13_cv_scores.png', dpi=300)
plt.close()
print("   ✅ Saved: 13_cv_scores.png")

# 6.14 Metrics Variability Across Runs
print("\n📊 14/14 Generating Metrics Variability...")
fig, axes = plt.subplots(2, 2, figsize=(16, 12))

# Accuracy distribution
axes[0, 0].hist(all_accuracies, bins=15, color='steelblue', alpha=0.7, edgecolor='black')
axes[0, 0].axvline(mean_accuracy, color='red', linestyle='--', linewidth=2, label=f'Mean: {mean_accuracy:.4f}')
axes[0, 0].set_xlabel('Accuracy', fontsize=11)
axes[0, 0].set_ylabel('Frequency', fontsize=11)
axes[0, 0].set_title('Accuracy Distribution Across 10 Runs', fontsize=12, fontweight='bold')
axes[0, 0].legend(fontsize=10)
axes[0, 0].grid(True, alpha=0.3)

# Training time distribution
axes[0, 1].hist(all_train_times, bins=15, color='orange', alpha=0.7, edgecolor='black')
axes[0, 1].axvline(mean_train_time, color='red', linestyle='--', linewidth=2, label=f'Mean: {mean_train_time:.2f}s')
axes[0, 1].set_xlabel('Training Time (seconds)', fontsize=11)
axes[0, 1].set_ylabel('Frequency', fontsize=11)
axes[0, 1].set_title('Training Time Distribution', fontsize=12, fontweight='bold')
axes[0, 1].legend(fontsize=10)
axes[0, 1].grid(True, alpha=0.3)

# CV scores distribution
axes[1, 0].hist(all_cv_scores, bins=15, color='green', alpha=0.7, edgecolor='black')
axes[1, 0].axvline(mean_cv_score, color='red', linestyle='--', linewidth=2, label=f'Mean: {mean_cv_score:.4f}')
axes[1, 0].set_xlabel('CV Accuracy', fontsize=11)
axes[1, 0].set_ylabel('Frequency', fontsize=11)
axes[1, 0].set_title('Cross-Validation Score Distribution', fontsize=12, fontweight='bold')
axes[1, 0].legend(fontsize=10)
axes[1, 0].grid(True, alpha=0.3)

# Misclassifications distribution
axes[1, 1].hist(all_misclassifications, bins=15, color='red', alpha=0.7, edgecolor='black')
axes[1, 1].axvline(mean_misclassifications, color='darkred', linestyle='--', linewidth=2, 
                   label=f'Mean: {mean_misclassifications:.1f}')
axes[1, 1].set_xlabel('Number of Misclassifications', fontsize=11)
axes[1, 1].set_ylabel('Frequency', fontsize=11)
axes[1, 1].set_title('Misclassifications Distribution', fontsize=12, fontweight='bold')
axes[1, 1].legend(fontsize=10)
axes[1, 1].grid(True, alpha=0.3)

plt.suptitle('Metrics Variability Across 10 Runs', fontsize=16, fontweight='bold', y=1.00)
plt.tight_layout()
plt.savefig('14_metrics_variability.png', dpi=300)
plt.close()
print("   ✅ Saved: 14_metrics_variability.png")

print("\n" + "=" * 70)
print("✅ ALL VISUALIZATIONS COMPLETED!")
print("=" * 70)

# ═══════════════════════════════════════════════════════
# 7. SAVE MODEL (Best Run)
# ═══════════════════════════════════════════════════════
print("\n💾 SAVING BEST MODEL")

best_model.get_booster().save_model("xgboost_model.json")
joblib.dump(best_model, "xgb_model.pkl")
joblib.dump(label_encoder, "label_encoder.pkl")
joblib.dump(best_X_train.columns.tolist(), "feature_names.pkl")

print("✅ Saved: xgboost_model.json")
print("✅ Saved: xgb_model.pkl")
print("✅ Saved: label_encoder.pkl")
print("✅ Saved: feature_names.pkl")

# Save aggregated results
results_summary = pd.DataFrame({
    'Run': range(1, NUM_RUNS + 1),
    'Accuracy': all_accuracies,
    'Training_Time': all_train_times,
    'CV_Score': all_cv_scores,
    'Avg_Confidence': all_confidences,
    'Misclassifications': all_misclassifications
})
results_summary.to_csv('runs_summary.csv', index=False)
print("✅ Saved: runs_summary.csv")

# Save average confusion matrix
avg_cm_df = pd.DataFrame(avg_confusion_matrix, 
                          index=attack_names, 
                          columns=attack_names)
avg_cm_df.to_csv('avg_confusion_matrix.csv')
print("✅ Saved: avg_confusion_matrix.csv")

# ═══════════════════════════════════════════════════════
# 8. SUMMARY
# ═══════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("📋 MODEL SUMMARY (10 RUNS)")
print("=" * 70)
print(f"""
Model: XGBoost Classifier
Classes: {num_classes}
Number of Runs: {NUM_RUNS}
Features: {X.shape[1]}

AVERAGE METRICS (over {NUM_RUNS} runs):
  Accuracy: {mean_accuracy:.4f} ± {std_accuracy:.4f} ({mean_accuracy*100:.2f}%)
  Training Time: {mean_train_time:.2f} ± {std_train_time:.2f} seconds
  CV Accuracy: {mean_cv_score:.4f} ± {std_cv_score:.4f}
  Avg Confidence: {mean_confidence:.4f} ± {std_confidence:.4f}
  Misclassifications: {mean_misclassifications:.1f} ± {std_misclassifications:.1f}

BEST RUN: #{best_run_idx + 1}
  Training Samples: {len(best_X_train)}
  Testing Samples: {len(best_X_test)}
  Accuracy: {best_accuracy:.4f} ({best_accuracy*100:.2f}%)
  CV Accuracy: {best_cv_scores.mean():.4f} (+/- {best_cv_scores.std():.4f})
  Avg Confidence: {best_confidence.mean():.4f}
  Misclassifications: {(best_y_test != best_y_pred).sum()}
""")

print("\n📁 Generated Files:")
files = [
    "1_avg_confusion_matrix.png",
    "2_confusion_matrix_best.png",
    "3_feature_importance.png",
    "4_all_features_contribution.png",
    "5_accuracy_across_runs.png",
    "6_learning_curves.png",
    "7_roc_curves.png",
    "8_precision_recall_curves.png",
    "9_class_distribution.png",
    "10_per_class_metrics.png",
    "11_confidence_distribution.png",
    "12_error_analysis.png",
    "13_cv_scores.png",
    "14_metrics_variability.png",
    "all_features_contribution.csv",
    "runs_summary.csv",
    "avg_confusion_matrix.csv",
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