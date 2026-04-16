from __future__ import annotations

from pathlib import Path

from flask import Flask, Response, abort, render_template, request, send_file

from .activity import load_recent_activity, record_batch_run, record_single_analysis
from .analysis_reporting import build_analysis_json, build_analysis_markdown
from .batch_analysis import analyze_batch_csv, batch_result_to_csv, build_batch_summary
from .inference import analyze_url
from .reporting import build_dashboard_view, build_training_report_view, load_training_report, resolve_data_asset
from .settings_view import build_settings_view


def create_app() -> Flask:
    template_dir = Path(__file__).resolve().parent.parent / "templates"
    app = Flask(__name__, template_folder=str(template_dir))

    @app.get("/")
    def index():
        return render_template("index.html", result=None, error=None, url_value="", dashboard=build_dashboard_view())

    @app.post("/analyze")
    def analyze():
        url_value = request.form.get("url", "")
        try:
            result = analyze_url(url_value)
            record_single_analysis(result)
            return render_template("index.html", result=result, error=None, url_value=url_value, dashboard=build_dashboard_view())
        except FileNotFoundError as exc:
            return render_template("index.html", result=None, error=str(exc), url_value=url_value, dashboard=build_dashboard_view()), 500
        except ValueError as exc:
            return render_template("index.html", result=None, error=str(exc), url_value=url_value, dashboard=build_dashboard_view()), 400
        except Exception as exc:
            return render_template(
                "index.html",
                result=None,
                error=f"Analysis failed: {exc}",
                url_value=url_value,
                dashboard=build_dashboard_view(),
            ), 500

    @app.get("/batch-analysis")
    def batch_analysis_page():
        return render_template("batch_analysis.html", summary=None, error=None, recent_activity=load_recent_activity())

    @app.post("/batch-analysis")
    def batch_analysis_run():
        uploaded = request.files.get("file")
        if uploaded is None or not uploaded.filename:
            return render_template("batch_analysis.html", summary=None, error="Choose a CSV file to analyze."), 400
        try:
            batch_result = analyze_batch_csv(uploaded.read(), filename=uploaded.filename)
            summary = build_batch_summary(batch_result)
            record_batch_run(uploaded.filename, summary)
            return render_template("batch_analysis.html", summary=summary, error=None, recent_activity=load_recent_activity())
        except ValueError as exc:
            return render_template("batch_analysis.html", summary=None, error=str(exc), recent_activity=load_recent_activity()), 400
        except FileNotFoundError as exc:
            return render_template("batch_analysis.html", summary=None, error=str(exc), recent_activity=load_recent_activity()), 500
        except Exception as exc:
            return render_template("batch_analysis.html", summary=None, error=f"Batch analysis failed: {exc}", recent_activity=load_recent_activity()), 500

    @app.post("/batch-analysis-export")
    def batch_analysis_export():
        uploaded = request.files.get("file")
        if uploaded is None or not uploaded.filename:
            return Response("Choose a CSV file to analyze.", status=400, mimetype="text/plain")
        try:
            batch_result = analyze_batch_csv(uploaded.read(), filename=uploaded.filename)
            csv_body = batch_result_to_csv(batch_result)
            return Response(
                csv_body,
                mimetype="text/csv",
                headers={"Content-Disposition": 'attachment; filename="batch_analysis_results.csv"'},
            )
        except ValueError as exc:
            return Response(str(exc), status=400, mimetype="text/plain")
        except FileNotFoundError as exc:
            return Response(str(exc), status=500, mimetype="text/plain")
        except Exception as exc:
            return Response(f"Batch analysis failed: {exc}", status=500, mimetype="text/plain")

    @app.get("/analysis-detail")
    def analysis_detail():
        url_value = request.args.get("url", "")
        try:
            result = analyze_url(url_value)
            return render_template("analysis_detail.html", result=result, error=None)
        except ValueError as exc:
            return render_template("analysis_detail.html", result=None, error=str(exc)), 400
        except FileNotFoundError as exc:
            return render_template("analysis_detail.html", result=None, error=str(exc)), 500
        except Exception as exc:
            return render_template("analysis_detail.html", result=None, error=f"Analysis failed: {exc}"), 500

    @app.get("/analysis-export.json")
    def analysis_export_json():
        url_value = request.args.get("url", "")
        try:
            result = analyze_url(url_value)
            body = build_analysis_json(result)
            return Response(
                body,
                mimetype="application/json",
                headers={
                    "Content-Disposition": 'attachment; filename="analysis_report.json"',
                },
            )
        except ValueError as exc:
            return Response(str(exc), status=400, mimetype="text/plain")
        except FileNotFoundError as exc:
            return Response(str(exc), status=500, mimetype="text/plain")
        except Exception as exc:
            return Response(f"Analysis failed: {exc}", status=500, mimetype="text/plain")

    @app.get("/analysis-export.md")
    def analysis_export_markdown():
        url_value = request.args.get("url", "")
        try:
            result = analyze_url(url_value)
            body = build_analysis_markdown(result)
            return Response(
                body,
                mimetype="text/markdown",
                headers={
                    "Content-Disposition": 'attachment; filename="analysis_report.md"',
                },
            )
        except ValueError as exc:
            return Response(str(exc), status=400, mimetype="text/plain")
        except FileNotFoundError as exc:
            return Response(str(exc), status=500, mimetype="text/plain")
        except Exception as exc:
            return Response(f"Analysis failed: {exc}", status=500, mimetype="text/plain")

    @app.post("/api/analyze")
    def api_analyze():
        payload = request.get_json(silent=True) or {}
        url_value = payload.get("url", "")
        try:
            result = analyze_url(url_value)
            record_single_analysis(result)
            body = build_analysis_json(result)
            return Response(body, mimetype="application/json")
        except ValueError as exc:
            return Response(str(exc), status=400, mimetype="text/plain")
        except FileNotFoundError as exc:
            return Response(str(exc), status=500, mimetype="text/plain")
        except Exception as exc:
            return Response(f"Analysis failed: {exc}", status=500, mimetype="text/plain")

    @app.get("/training-report")
    def training_report():
        try:
            report = load_training_report()
            view = build_training_report_view(report)
            return render_template("training_report.html", report=view, error=None)
        except FileNotFoundError as exc:
            return render_template("training_report.html", report=None, error=str(exc)), 404
        except Exception as exc:
            return render_template("training_report.html", report=None, error=f"Could not load training report: {exc}"), 500

    @app.get("/training-assets/<path:asset_path>")
    def training_asset(asset_path: str):
        try:
            asset = resolve_data_asset(asset_path)
        except FileNotFoundError:
            abort(404)
        except ValueError:
            abort(404)
        return send_file(asset)

    @app.get("/settings")
    def settings_page():
        return render_template("settings.html", settings=build_settings_view())

    return app
