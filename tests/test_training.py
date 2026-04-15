import json
import tempfile
import unittest
from pathlib import Path

from phishing_detector.training import (
    build_report,
    build_plot_manifest,
    build_markdown_summary,
    default_report_path,
    default_plot_dir,
    default_summary_path,
    extract_training_matrix,
    load_dataset,
    load_training_input,
    normalize_label,
    save_markdown_summary,
    save_report,
)


class TrainingHelpersTests(unittest.TestCase):
    def test_normalize_label(self):
        self.assertEqual(normalize_label("phishing"), 1)
        self.assertEqual(normalize_label("legitimate"), 0)
        self.assertEqual(normalize_label("bad"), 1)
        self.assertEqual(normalize_label("good"), 0)
        self.assertEqual(normalize_label("-1"), 1)

    def test_load_dataset_requires_columns(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "data.csv"
            file_path.write_text("url,label\nhttps://example.com,legitimate\n", encoding="utf-8")
            frame = load_dataset([file_path])
            self.assertEqual(len(frame), 1)

    def test_load_dataset_accepts_common_kaggle_columns(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "kaggle_style.csv"
            file_path.write_text(
                "URL,Result\nhttps://safe.example,good\nhttps://phish.example,bad\n",
                encoding="utf-8",
            )
            frame = load_dataset([file_path])
            self.assertEqual(list(frame.columns), ["url", "label"])
            self.assertEqual(frame["label"].tolist(), [0, 1])

    def test_load_dataset_accepts_domain_and_class_columns(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "alt_schema.csv"
            file_path.write_text(
                "Domain,Class\nexample.org,0\nmalicious.example,-1\n",
                encoding="utf-8",
            )
            frame = load_dataset([file_path])
            self.assertEqual(frame["url"].tolist(), ["example.org", "malicious.example"])
            self.assertEqual(frame["label"].tolist(), [0, 1])

    def test_load_training_input_detects_engineered_features(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "engineered.csv"
            file_path.write_text(
                "having_IP_Address,URL_Length,Result\n1,54,1\n0,12,0\n",
                encoding="utf-8",
            )
            frame, mode = load_training_input([file_path])
            self.assertEqual(mode, "engineered_features")
            self.assertEqual(frame.columns.tolist(), ["having_IP_Address", "URL_Length", "label"])

    def test_extract_training_matrix_uses_engineered_columns_directly(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "engineered.csv"
            file_path.write_text(
                "having_IP_Address,URL_Length,Result\n1,54,1\n0,12,0\n",
                encoding="utf-8",
            )
            frame, mode = load_training_input([file_path])
            x, y = extract_training_matrix(frame, dataset_mode=mode)
            self.assertEqual(x.columns.tolist(), ["having_IP_Address", "URL_Length"])
            self.assertEqual(y.tolist(), [1, 0])

    def test_default_report_path_follows_artifact_name(self):
        artifact_path = Path("data/model_artifact.pkl")
        self.assertEqual(default_report_path(artifact_path), Path("data/model_artifact_report.json"))

    def test_default_summary_path_follows_artifact_name(self):
        artifact_path = Path("data/model_artifact.pkl")
        self.assertEqual(default_summary_path(artifact_path), Path("data/model_artifact_summary.md"))

    def test_default_plot_dir_follows_artifact_name(self):
        artifact_path = Path("data/model_artifact.pkl")
        self.assertEqual(default_plot_dir(artifact_path), Path("data/model_artifact_plots"))

    def test_save_report_writes_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.json"
            report = {
                "model_name": "logistic_regression",
                "dataset_mode": "raw_url",
                "metrics": {"logistic_regression": {"accuracy": 1.0}},
            }
            save_report(report, report_path)
            written = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(written["model_name"], "logistic_regression")

    def test_save_markdown_summary_writes_text(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            summary_path = Path(temp_dir) / "summary.md"
            save_markdown_summary("# Training Summary", summary_path)
            self.assertEqual(summary_path.read_text(encoding="utf-8"), "# Training Summary")

    def test_build_report_contains_training_metadata(self):
        artifact = {
            "dataset_mode": "raw_url",
            "model_name": "random_forest",
            "threshold": 0.5,
            "training_rows": 100,
            "test_rows": 25,
            "feature_count": 32,
            "feature_order": ["url_length", "hostname_length"],
            "metrics": {"random_forest": {"accuracy": 0.98}},
            "evaluation_curves": {
                "random_forest": {
                    "confusion_matrix": {"tn": 10, "fp": 1, "fn": 2, "tp": 12},
                    "roc_curve": {"fpr": [0.0, 0.2, 1.0], "tpr": [0.0, 0.8, 1.0], "thresholds": [2.0, 1.0, 0.0]},
                }
            },
        }
        report = build_report(artifact, [Path("data/sample.csv")], Path("data/model.pkl"))
        self.assertEqual(report["model_name"], "random_forest")
        self.assertEqual(report["training_rows"], 100)
        self.assertEqual(Path(report["data_paths"][0]), Path("data/sample.csv"))
        self.assertIn("evaluation_curves", report)

    def test_build_markdown_summary_contains_table(self):
        report = {
            "dataset_mode": "raw_url",
            "model_name": "random_forest",
            "threshold": 0.5,
            "training_rows": 100,
            "test_rows": 25,
            "feature_count": 32,
            "feature_order": ["url_length", "hostname_length"],
            "data_paths": ["data/sample.csv"],
            "metrics": {
                "random_forest": {
                    "accuracy": 0.98,
                    "precision": 0.97,
                    "recall": 0.99,
                    "f1": 0.98,
                    "roc_auc": 0.995,
                }
            },
        }
        summary = build_markdown_summary(report)
        self.assertIn("# Training Summary", summary)
        self.assertIn("| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |", summary)
        self.assertIn("| random_forest | 0.9800 | 0.9700 | 0.9900 | 0.9800 | 0.9950 |", summary)

    def test_build_plot_manifest_contains_png_paths(self):
        report = {
            "metrics": {"logistic_regression": {}, "random_forest": {}},
        }
        manifest = build_plot_manifest(report, Path("data/model_artifact_plots"))
        self.assertEqual(
            Path(manifest["logistic_regression"]["confusion_matrix"]),
            Path("data/model_artifact_plots/logistic_regression_confusion_matrix.png"),
        )
        self.assertEqual(
            Path(manifest["random_forest"]["roc_curve"]),
            Path("data/model_artifact_plots/random_forest_roc_curve.png"),
        )


if __name__ == "__main__":
    unittest.main()
