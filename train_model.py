# train_model.py (Final Version - Updated for 41 Features)
import pandas as pd
import numpy as np
import pickle
import json
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
    precision_recall_fscore_support,
)
import os
import sys
import time
import traceback

# --- Configuration ---
PICKLE_DIR = "pickle"
EXPECTED_FEATURE_COUNT = 41  # Includes Certificate Analysis + VT Check
DEFAULT_DATASET_PATH = "dataset.csv"
TARGET_COLUMN = "class"
# --- End Configuration ---

os.makedirs(PICKLE_DIR, exist_ok=True)


def create_synthetic_data(n_samples=20000, n_features=EXPECTED_FEATURE_COUNT):
    """Creates a synthetic dataset matching the expected feature count."""
    print(
        f"Creating synthetic dataset with {n_samples} samples and {n_features} features..."
    )
    np.random.seed(42)
    features = np.random.randint(-1, 2, size=(n_samples, n_features))
    labels = np.ones(n_samples)
    # Update indices if necessary, ensure they are < n_features (41)
    ip_idx, https_idx, age_idx, dns_idx = 0, 7, 8, 24
    short_idx, symbol_idx, brand_idx, gsb_idx, cert_idx, vt_idx = (
        2,
        3,
        32,
        33,
        34,
        40,
    )  # Added VT index

    unsafe_prob = 0.75
    for i in range(n_samples):
        is_unsafe = False
        # Add rules based on feature importance...
        if features[i, ip_idx] == -1 and np.random.rand() < 0.8:
            is_unsafe = True
        if not is_unsafe and features[i, https_idx] == -1 and np.random.rand() < 0.85:
            is_unsafe = True
        if (
            brand_idx < n_features
            and not is_unsafe
            and features[i, brand_idx] == -1
            and np.random.rand() < 0.9
        ):
            is_unsafe = True
        # Check VT index
        if (
            vt_idx < n_features
            and not is_unsafe
            and features[i, vt_idx] == -1
            and np.random.rand() < 0.99
        ):
            is_unsafe = True  # VT hit almost certainly unsafe
        if (
            gsb_idx < n_features
            and not is_unsafe
            and features[i, gsb_idx] == -1
            and np.random.rand() < 0.98
        ):
            is_unsafe = True

        if not is_unsafe and np.random.rand() < 0.07:
            is_unsafe = True  # Lower random chance
        if is_unsafe:
            labels[i] = -1
    # Generate correct number of feature names
    feature_names = [f"feature_{j}" for j in range(n_features)]
    data = pd.DataFrame(features, columns=feature_names)
    data[TARGET_COLUMN] = labels
    print(
        f"Synthetic dataset created. Label distribution:\n{data[TARGET_COLUMN].value_counts(normalize=True)}"
    )
    return data, feature_names


def train_model(dataset_path=DEFAULT_DATASET_PATH):
    """Loads data, trains a tuned RandomForest model, evaluates, and saves it."""
    print("--- Starting Model Training ---")
    start_time = time.time()
    try:
        print(f"Attempting to load dataset from: {dataset_path}")
        if os.path.exists(dataset_path):
            try:
                data = pd.read_csv(dataset_path, low_memory=False, on_bad_lines="warn")
            except:
                data = pd.read_csv(
                    dataset_path, low_memory=False, error_bad_lines=False
                )  # Fallback load
            print(f"Dataset loaded. Initial Shape: {data.shape}")
            if data.shape[0] < 200:
                raise ValueError("Dataset samples < 200.")
            # Update column check for 41 features + 1 label
            min_cols = EXPECTED_FEATURE_COUNT + 1
            if data.shape[1] < min_cols:
                raise ValueError(
                    f"Dataset columns ({data.shape[1]}) < expected ({min_cols})."
                )

            # --- Label Handling ---
            label_col_found = False
            target_col_actual = None
            possible_labels = [
                TARGET_COLUMN,
                "Result",
                "Class",
                "CLASS_LABEL",
                "Label",
                "Phishing",
                "Type",
            ]
            for col in possible_labels:
                if col in data.columns:
                    target_col_actual = col
                    label_col_found = True
                    break
            if not label_col_found:
                raise ValueError(f"Target column ({possible_labels}) not found.")
            if target_col_actual != TARGET_COLUMN:
                data = data.rename(columns={target_col_actual: TARGET_COLUMN})
            print(
                f"Using '{target_col_actual}' as target. Initial labels:\n{data[TARGET_COLUMN].value_counts(dropna=False)}"
            )
            label_map = {
                1: 1,
                "1": 1,
                "good": 1,
                "legitimate": 1,
                "benign": 1,
                "safe": 1,
                -1: -1,
                "-1": -1,
                0: -1,
                "0": -1,
                "bad": -1,
                "phishing": -1,
                "malicious": -1,
                "unsafe": -1,
                "spam": -1,
                "malware": -1,
                "scam": -1,
                "defacement": -1,
            }
            data[TARGET_COLUMN] = (
                data[TARGET_COLUMN].astype(str).str.lower().map(label_map)
            )
            rows_before = len(data)
            data.dropna(subset=[TARGET_COLUMN], inplace=True)
            data[TARGET_COLUMN] = data[TARGET_COLUMN].astype(int)
            rows_after = len(data)
            if rows_after < rows_before:
                print(f"W: Dropped {rows_before - rows_after} unmappable label rows.")
            if not all(data[TARGET_COLUMN].isin([1, -1])):
                raise ValueError(
                    f"Labels couldn't map to 1/-1. Remaining: {data[TARGET_COLUMN].unique()}"
                )
            print(f"Final labels:\n{data[TARGET_COLUMN].value_counts(normalize=True)}")
            if rows_after < 100:
                raise ValueError("Too few valid samples.")

            # --- Feature Selection & Cleaning ---
            all_columns = data.columns.tolist()
            # Select correct number of feature columns
            feature_names = [col for col in all_columns if col != TARGET_COLUMN][
                :EXPECTED_FEATURE_COUNT
            ]
            if len(feature_names) != EXPECTED_FEATURE_COUNT:
                raise ValueError(
                    f"Expected {EXPECTED_FEATURE_COUNT} features, found {len(feature_names)}."
                )
            X = data[feature_names].copy()
            y = data[TARGET_COLUMN]
            for col in X.columns:
                X[col] = pd.to_numeric(X[col], errors="coerce")
            cols_nan = X.isnull().sum()
            if cols_nan.sum() > 0:
                print(f"W: Filling NaNs with 0:\n{cols_nan[cols_nan > 0]}")
                X.fillna(0, inplace=True)

        else:  # Dataset not found
            print(
                f"Dataset not found. Creating synthetic data with {EXPECTED_FEATURE_COUNT} features..."
            )
            data, feature_names = create_synthetic_data(
                n_features=EXPECTED_FEATURE_COUNT
            )
            X = data[feature_names]
            y = data[TARGET_COLUMN]

        features_path = os.path.join(PICKLE_DIR, "feature_names.json")
        print(f"Saving {len(feature_names)} feature names to: {features_path}")
        with open(features_path, "w") as f:
            json.dump(feature_names, f, indent=4)

        print("Splitting data (80/20 split, stratified)...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        print(f"Training set: {X_train.shape}, Testing set: {X_test.shape}")

        # --- Hyperparameter Tuning ---
        print("Setting up GridSearchCV...")
        param_grid = {
            "n_estimators": [200, 350],
            "max_depth": [30, 40, None],
            "min_samples_split": [3, 5],
            "min_samples_leaf": [2, 3],
            "max_features": ["sqrt", 0.6],
            "criterion": ["gini", "entropy"],
        }
        rf = RandomForestClassifier(
            random_state=42, n_jobs=-1, class_weight="balanced_subsample"
        )
        grid_search = GridSearchCV(
            estimator=rf,
            param_grid=param_grid,
            cv=3,
            n_jobs=-1,
            verbose=2,
            scoring="f1_weighted",
        )
        print("Starting GridSearchCV...")
        grid_start = time.time()
        grid_search.fit(X_train, y_train)
        grid_end = time.time()
        print(f"GridSearchCV finished in {(grid_end - grid_start) / 60:.2f} min.")
        print(f"Best params: {grid_search.best_params_}")
        print(f"Best CV F1: {grid_search.best_score_:.4f}")
        model = grid_search.best_estimator_

        # --- Final Evaluation ---
        print("\n--- Evaluating Final Model ---")
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)
        safe_idx = -1
        y_prob_safe = np.zeros(len(y_test))  # Default safe prob
        try:
            safe_idx = list(model.classes_).index(1)
            y_prob_safe = y_prob[:, safe_idx]
        except:
            print("W: Class '1' not found.")
            safe_idx = 0
            y_prob_safe = y_prob[:, 0]  # Fallback
        acc = accuracy_score(y_test, y_pred)
        p, r, f1, _ = precision_recall_fscore_support(
            y_test, y_pred, labels=[1, -1], average=None, zero_division=0
        )
        f1_s = f1[0]
        f1_u = f1[1]
        recall_u = r[1]
        fnr = 1.0 - recall_u if recall_u else "N/A"
        try:
            roc = roc_auc_score(y_test, y_prob_safe)
        except:
            roc = "N/A"
        print(f"Test Accuracy: {acc:.4f}")
        print(f"Test F1 (S): {f1_s:.4f}")
        print(f"Test F1 (U): {f1_u:.4f}")
        print(f"Test Recall (U/TPR): {recall_u:.4f}")
        print(f"Test FNR (Miss): {fnr if isinstance(fnr, str) else f'{fnr:.4f}'}")
        print(f"Test ROC AUC: {roc if isinstance(roc, str) else f'{roc:.4f}'}")
        print(
            "\nClassification Report:\n",
            classification_report(
                y_test,
                y_pred,
                labels=[1, -1],
                target_names=["Safe", "Unsafe"],
                zero_division=0,
            ),
        )
        print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred, labels=[1, -1]))
        # --- Save Model ---
        model_path = os.path.join(PICKLE_DIR, "Phishing_model.pkl")
        print(f"\nSaving model to: {model_path}")
        with open(model_path, "wb") as f:
            pickle.dump(model, f)
        total_t = time.time() - start_time
        print(f"--- Training Complete ({total_t:.2f}s) ---")
        return True
    except FileNotFoundError as e:
        print(f"\nError: Dataset file not found. {e}", file=sys.stderr)
        return False
    except ValueError as e:
        print(f"\nError: Data validation/processing failed. {e}", file=sys.stderr)
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"\nAn unexpected error during training: {e}", file=sys.stderr)
        traceback.print_exc()
        return False


if __name__ == "__main__":
    dataset_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DATASET_PATH
    success = train_model(dataset_path=dataset_file)
    sys.exit(0 if success else 1)
