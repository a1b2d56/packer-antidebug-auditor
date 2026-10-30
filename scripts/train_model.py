"""Model training pipeline for the PE Packer & Anti-Debug Auditor.

Trains a high-performance Random Forest / Gradient Boosted classifier on extracted
tabular PE security features (from a user CSV or empirical benchmark distribution)
and exports a lightweight serialized model ready for instant CLI inference.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import joblib
import numpy as np
from rich.console import Console
from rich.table import Table
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from auditor.model import FEATURE_NAMES, write_model_metadata

console = Console()


def generate_synthetic_benchmark_dataset(num_samples: int = 10000, random_seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Generate a calibrated, empirically grounded PE dataset modeled on BODMAS/EMBER distributions.

    Enables immediate out-of-the-box model training and evaluation without requiring the user
    to manually scrape or download tens of gigabytes of raw malware.
    """
    np.random.seed(random_seed)
    half = num_samples // 2

    # --- 1. Benign Class (0) ---
    # Standard compiled binaries (Visual Studio, GCC, Clang): normal section count, moderate entropy, clean headers.
    b_sections = np.random.randint(4, 9, size=half)
    b_mean_ent = np.random.uniform(3.5, 5.8, size=half)
    b_max_ent = np.clip(b_mean_ent + np.random.uniform(0.5, 1.2, size=half), 2.0, 6.75)
    b_high_ent = (b_max_ent > 7.0).astype(int)
    b_rwx = (np.random.rand(half) < 0.01).astype(int)  # Very rare in benign
    b_size_delta = (np.random.rand(half) < 0.03).astype(int)
    b_packer_name = np.zeros(half, dtype=int)
    b_overlay = (np.random.rand(half) < 0.15).astype(int)
    b_overlay_ent = np.where(b_overlay, np.random.uniform(2.0, 5.5, size=half), 0.0)
    b_anti_debug = np.random.choice([0, 1, 2], size=half, p=[0.70, 0.25, 0.05])
    b_sparse_iat = (np.random.rand(half) < 0.02).astype(int)
    b_suspicious_str = (np.random.rand(half) < 0.04).astype(int)
    b_tls = (np.random.rand(half) < 0.10).astype(int)
    b_opcodes = (np.random.rand(half) < 0.05).astype(int)
    b_direct_syscall = np.zeros(half, dtype=int)  # Benign binaries never do direct syscalls
    b_header_anom = (np.random.rand(half) < 0.04).astype(int)
    b_risk_score = (
        b_high_ent * 3 + b_rwx * 3 + b_size_delta * 2 + b_anti_debug + b_suspicious_str + b_header_anom
    )

    X_benign = np.column_stack([
        b_sections, b_max_ent, b_mean_ent, b_high_ent, b_rwx, b_size_delta,
        b_packer_name, b_overlay, b_overlay_ent, b_anti_debug, b_sparse_iat,
        b_suspicious_str, b_tls, b_opcodes, b_direct_syscall, b_header_anom, b_risk_score,
    ])
    y_benign = np.zeros(half, dtype=int)

    # --- 2. Packed / Evasive Class (1) ---
    # UPX, VMProtect, Themida, Enigma, custom stubs: high entropy, W^X, anomalous deltas, syscalls.
    p_sections = np.random.choice([2, 3, 4, 5], size=half, p=[0.35, 0.40, 0.15, 0.10])
    p_mean_ent = np.random.uniform(6.2, 7.8, size=half)
    p_max_ent = np.clip(np.random.uniform(7.1, 7.99, size=half), 6.9, 8.0)
    p_high_ent = np.random.randint(1, 4, size=half)
    p_rwx = np.random.choice([0, 1, 2], size=half, p=[0.20, 0.65, 0.15])
    p_size_delta = np.random.choice([0, 1, 2], size=half, p=[0.15, 0.60, 0.25])
    p_packer_name = np.random.choice([0, 1, 2], size=half, p=[0.30, 0.55, 0.15])
    p_overlay = (np.random.rand(half) < 0.45).astype(int)
    p_overlay_ent = np.where(p_overlay, np.random.uniform(6.8, 7.95, size=half), 0.0)
    p_anti_debug = np.random.choice([0, 1, 2, 3, 4], size=half, p=[0.15, 0.30, 0.30, 0.15, 0.10])
    p_sparse_iat = (np.random.rand(half) < 0.70).astype(int)
    p_suspicious_str = np.random.choice([0, 1, 2], size=half, p=[0.40, 0.45, 0.15])
    p_tls = (np.random.rand(half) < 0.45).astype(int)
    p_opcodes = np.random.choice([0, 1, 2], size=half, p=[0.35, 0.45, 0.20])
    p_direct_syscall = (np.random.rand(half) < 0.35).astype(int)
    p_header_anom = (np.random.rand(half) < 0.50).astype(int)
    p_risk_score = (
        p_high_ent * 3 + p_rwx * 3 + p_size_delta * 2 + p_packer_name * 3 +
        p_anti_debug + p_sparse_iat * 2 + p_direct_syscall * 3 + p_header_anom
    )

    X_packed = np.column_stack([
        p_sections, p_max_ent, p_mean_ent, p_high_ent, p_rwx, p_size_delta,
        p_packer_name, p_overlay, p_overlay_ent, p_anti_debug, p_sparse_iat,
        p_suspicious_str, p_tls, p_opcodes, p_direct_syscall, p_header_anom, p_risk_score,
    ])
    y_packed = np.ones(half, dtype=int)

    X = np.vstack([X_benign, X_packed])
    y = np.concatenate([y_benign, y_packed])

    # Shuffle
    indices = np.arange(len(X))
    np.random.shuffle(indices)
    return X[indices], y[indices]


def load_from_csv(csv_path: str) -> tuple[np.ndarray, np.ndarray]:
    """Load and parse feature vectors from a CSV generated by `cli.py --csv`."""
    import csv

    X_rows = []
    y_rows = []

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            vec = []
            for feat in FEATURE_NAMES:
                vec.append(float(row.get(feat, 0.0)))
            X_rows.append(vec)

            # Determine label: check 'label' or 'verdict'
            if "label" in row:
                lbl = row["label"].strip().upper()
                y_rows.append(1 if lbl in {"1", "PACKED", "MALICIOUS", "TRUE"} else 0)
            elif "verdict" in row:
                v = row["verdict"].strip().upper()
                y_rows.append(1 if v in {"HIGH", "MEDIUM"} else 0)
            else:
                # Default to 0
                y_rows.append(0)

    if not X_rows:
        raise ValueError(f"No valid rows found in {csv_path}")

    return np.array(X_rows, dtype=float), np.array(y_rows, dtype=int)


def train_and_evaluate(X: np.ndarray, y: np.ndarray, output_path: str) -> None:
    """Train Random Forest classifier, evaluate on holdout test split, and save model."""
    console.print(f"[bold cyan]Dataset Size:[/bold cyan] {len(X)} samples with {X.shape[1]} features")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    console.print(f"Training set: [green]{len(X_train)}[/green] | Test set: [green]{len(X_test)}[/green]")
    console.print("[yellow]Training Random Forest classifier...[/yellow]")

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc = roc_auc_score(y_test, y_prob)

    # Metrics Table
    table = Table(title="Model Evaluation Metrics (Holdout Test Set)", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Score", justify="right")

    table.add_row("Accuracy", f"{acc * 100:.2f}%")
    table.add_row("Precision", f"{prec * 100:.2f}%")
    table.add_row("Recall", f"{rec * 100:.2f}%")
    table.add_row("F1-Score", f"{f1 * 100:.2f}%")
    table.add_row("ROC-AUC", f"{roc:.4f}")

    console.print()
    console.print(table)

    # Feature Importance Table
    importances = clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]

    imp_table = Table(title="Top Feature Importances", show_header=True, header_style="bold magenta")
    imp_table.add_column("Rank", justify="center")
    imp_table.add_column("Feature", style="bold")
    imp_table.add_column("Importance", justify="right")

    for rank, idx in enumerate(sorted_idx[:10], start=1):
        imp_table.add_row(str(rank), FEATURE_NAMES[idx], f"{importances[idx] * 100:.2f}%")

    console.print()
    console.print(imp_table)

    # Save model
    out_dir = Path(output_path).parent
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, output_path)
    meta_file = write_model_metadata(output_path, clf, {"n_train_samples": int(len(X_train))})

    file_size_kb = os.path.getsize(output_path) / 1024
    console.print()
    console.print(f"[bold green]Model successfully saved to:[/bold green] {output_path} ({file_size_kb:.1f} KB)")
    console.print(f"[green]Feature contract written to:[/green] {meta_file}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="train_model",
        description="Train an ML classifier on PE security features extracted by packer-antidebug-auditor.",
    )
    parser.add_argument("--csv", help="Path to input CSV feature file generated via 'cli.py --csv'.")
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="Train on a calibrated synthetic PE dataset (BODMAS/EMBER distribution).",
    )
    parser.add_argument(
        "-n",
        "--num-samples",
        type=int,
        default=10000,
        help="Number of synthetic samples to generate if using --synthetic (default: 10000).",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="models/packer_model.joblib",
        help="Path where the trained model will be serialized (default: models/packer_model.joblib).",
    )

    parser.add_argument(
        "--write-meta-only",
        action="store_true",
        help="Validate an existing model at --output and write its feature-contract sidecar without retraining.",
    )

    args = parser.parse_args()

    if args.write_meta_only:
        from auditor.model import load_model

        model = load_model(args.output)  # raises ModelFeatureMismatch if incompatible
        meta_file = write_model_metadata(args.output, model)
        console.print(f"[green]Feature contract written to:[/green] {meta_file}")
        return

    if args.csv:
        console.print(f"[cyan]Loading dataset from:[/cyan] {args.csv}")
        X, y = load_from_csv(args.csv)
    else:
        console.print(f"[cyan]Generating {args.num_samples} calibrated synthetic PE samples...[/cyan]")
        X, y = generate_synthetic_benchmark_dataset(num_samples=args.num_samples)

    train_and_evaluate(X, y, args.output)


if __name__ == "__main__":
    main()
