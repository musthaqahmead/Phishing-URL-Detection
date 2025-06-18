# app.py (Full Corrected Code - Version for 41 Features including VT)

from flask import Flask, render_template, request
from requests.exceptions import Timeout, RequestException
import pickle
import json
import os
import numpy as np
import pandas as pd  # Make sure pandas is imported
from feature import FeatureExtraction  # Assuming feature.py is in the same directory
import subprocess
from datetime import datetime, timezone  # Corrected Import
import sys
import traceback
import requests  # Ensure requests is imported
import certifi  # Import the certifi library
from bs4 import BeautifulSoup  # Import BeautifulSoup for HTML parsing
import base64  # For VirusTotal URL ID
from urllib.parse import urlparse
from urllib3.exceptions import (
    LocationParseError,
)  # Added for URL parsing error handling


# --- Flask App Initialization ---
app = Flask(__name__)

# --- Constants ---
PICKLE_DIR = "pickle"
MODEL_PATH = os.path.join(PICKLE_DIR, "Phishing_model.pkl")
FEATURES_PATH = os.path.join(PICKLE_DIR, "feature_names.json")
EXPECTED_FEATURE_COUNT_NUMERICAL = 41  # Updated for VT check feature
DANGER_THRESHOLD = 45  # Score below which we force classification as DANGEROUS
GSB_API_KEY = (
    "AIzaSyDZL7mqndoajUZ9wjBnu4TEgqgJEAcYkKg"  # ***** PASTE YOUR KEY HERE *****
)
VT_API_KEY = "e2f8e4692d0272cd2e207c9365b352e49708691ddd58f5bfb86efe7423ec1251"  # ***** PASTE YOUR VT KEY HERE *****
# --- End Constants ---

# --- FEATURE_EXPLANATIONS Dictionary (Must cover indices 0-40) ---
FEATURE_EXPLANATIONS = {
    0: {
        "name": "Using IP Address",
        "safe": "Domain name used (not IP address).",
        "unsafe": "IP address used directly in URL.",
        "severity": "HIGH",
    },
    1: {
        "name": "URL Length",
        "safe": "URL length is standard.",
        "unsafe": "URL is unusually long.",
        "severity": "MEDIUM",
    },
    2: {
        "name": "Shortening Service",
        "safe": "URL destination is directly visible.",
        "unsafe": "Uses a shortening service (masks destination).",
        "severity": "HIGH",
    },
    3: {
        "name": "@ Symbol",
        "safe": "No '@' symbol present in URL.",
        "unsafe": "'@' symbol found, can obscure domain.",
        "severity": "HIGH",
    },
    4: {
        "name": "Double Slash Redirecting",
        "safe": "URL path structure normal.",
        "unsafe": "'//' found after protocol path.",
        "severity": "MEDIUM",
    },
    5: {
        "name": "Prefix/Suffix (Hyphen)",
        "safe": "No hyphen '-' in domain.",
        "unsafe": "Hyphen '-' found in domain.",
        "severity": "LOW",
    },
    6: {
        "name": "Subdomains",
        "safe": "Normal number of subdomains (0-2 dots typical).",
        "unsafe": "Excessive subdomains (>3 dots).",
        "severity": "MEDIUM",
    },
    7: {
        "name": "HTTPS Protocol",
        "safe": "Uses secure HTTPS.",
        "unsafe": "Does not use HTTPS (insecure connection).",
        "severity": "HIGH",
    },
    8: {
        "name": "Domain Age (>6 Months)",
        "safe": "Domain registered > 6 months ago.",
        "unsafe": "Domain registered recently (<6 months).",
        "severity": "HIGH",
    },
    9: {
        "name": "Favicon Source",
        "safe": "Favicon is loaded from the same domain.",
        "unsafe": "Favicon loaded from a different domain or missing.",
        "severity": "LOW",
    },
    10: {
        "name": "Non-Standard Port",
        "safe": "Uses standard web ports (e.g., 80, 443).",
        "unsafe": "Uses non-standard ports.",
        "severity": "MEDIUM",
    },
    11: {
        "name": "HTTPS in Domain Name",
        "safe": "No 'http(s)' misleadingly in domain.",
        "unsafe": "'http(s)' found in domain name itself.",
        "severity": "MEDIUM",
    },
    12: {
        "name": "External Objects Ratio",
        "safe": "Low % (<22%) of external images/scripts.",
        "unsafe": "High % (>61%) of external images/scripts.",
        "severity": "LOW",
    },
    13: {
        "name": "External Links Ratio",
        "safe": "Low % (<31%) of external links.",
        "unsafe": "High % (>67%) of external links.",
        "severity": "LOW",
    },
    14: {
        "name": "Links in Meta/Script/Link",
        "safe": "Low % (<30%) external links in tags.",
        "unsafe": "High % (>75%) external links in tags.",
        "severity": "LOW",
    },
    15: {
        "name": "Form Handler (SFH)",
        "safe": "Forms submit data internally.",
        "unsafe": "Forms submit data externally/blank/mailto.",
        "severity": "MEDIUM",
    },
    16: {
        "name": "Mailto in Source",
        "safe": "No 'mailto:' links found.",
        "unsafe": "'mailto:' link found.",
        "severity": "LOW",
    },
    17: {
        "name": "Abnormal URL (WHOIS)",
        "safe": "URL domain matches WHOIS.",
        "unsafe": "URL domain mismatch with WHOIS.",
        "severity": "MEDIUM",
    },
    18: {
        "name": "Website Forwarding",
        "safe": "Limited redirects (<=1).",
        "unsafe": "Excessive redirects (>=4).",
        "severity": "LOW",
    },
    19: {
        "name": "Status Bar Customization",
        "safe": "No status bar hiding detected.",
        "unsafe": "Status bar manipulation detected.",
        "severity": "LOW",
    },
    20: {
        "name": "Right Click Disabled",
        "safe": "Right-click enabled.",
        "unsafe": "Right-click disabled.",
        "severity": "LOW",
    },
    21: {
        "name": "Popup Window Usage",
        "safe": "No popups/alerts detected.",
        "unsafe": "Use of popups/alerts detected.",
        "severity": "LOW",
    },
    22: {
        "name": "Iframe Usage",
        "safe": "No hidden/suspicious iframes.",
        "unsafe": "Hidden iframes detected.",
        "severity": "MEDIUM",
    },
    23: {
        "name": "Age of Domain (Alias)",
        "safe": "Domain registered > 6 months ago.",
        "unsafe": "Domain registered < 6 months ago.",
        "severity": "HIGH",
    },
    24: {
        "name": "DNS Record",
        "safe": "DNS record exists.",
        "unsafe": "No DNS record found.",
        "severity": "HIGH",
    },
    25: {
        "name": "Website Traffic",
        "safe": "N/A (Placeholder)",
        "unsafe": "N/A (Placeholder)",
        "severity": "LOW",
    },
    26: {
        "name": "PageRank",
        "safe": "N/A (Placeholder)",
        "unsafe": "N/A (Placeholder)",
        "severity": "LOW",
    },
    27: {
        "name": "Google Index (Basic)",
        "safe": "Likely indexable (Has DNS, not IP).",
        "unsafe": "Not indexable (No DNS or uses IP).",
        "severity": "LOW",
    },
    28: {
        "name": "Links Pointing to Page",
        "safe": "N/A (Placeholder)",
        "unsafe": "N/A (Placeholder)",
        "severity": "LOW",
    },
    29: {
        "name": "Stats Report (Blacklists)",
        "safe": "Not found in local blacklist.",
        "unsafe": "Found in local blacklist.",
        "severity": "HIGH",
    },
    30: {
        "name": "Suspicious Keywords",
        "safe": "No/few suspicious keywords in URL.",
        "unsafe": "Multiple suspicious keywords found in URL.",
        "severity": "MEDIUM",
    },
    31: {
        "name": "Special Characters Ratio",
        "safe": "Low ratio of unusual special chars.",
        "unsafe": "High ratio of unusual special chars in URL.",
        "severity": "LOW",
    },
    32: {
        "name": "Brand Impersonation (Basic)",
        "safe": "No obvious brand names found in misleading URL parts.",
        "unsafe": "Known brand name found in subdomain or path, suggesting impersonation.",
        "severity": "HIGH",
    },
    33: {
        "name": "Google Safe Browsing",
        "safe": "URL not flagged by GSB.",
        "unsafe": "URL flagged by GSB.",
        "severity": "HIGH",
    },
    34: {
        "name": "Certificate Analysis",
        "safe": "Certificate appears trustworthy.",
        "unsafe": "Certificate has suspicious traits.",
        "severity": "MEDIUM",
    },
    35: {
        "name": "Path Depth",
        "safe": "URL path depth is shallow/normal.",
        "unsafe": "URL path depth is excessive.",
        "severity": "LOW",
    },
    36: {
        "name": "Suspicious Filename/Extension",
        "safe": "Filename/extension appear normal.",
        "unsafe": "Path includes suspicious filename/extension.",
        "severity": "MEDIUM",
    },
    37: {
        "name": "Query String Length",
        "safe": "Query string is short/empty.",
        "unsafe": "Query string is excessively long.",
        "severity": "LOW",
    },
    38: {
        "name": "Hex Encoding Ratio",
        "safe": "Little/no hex encoding.",
        "unsafe": "High ratio hex encoding.",
        "severity": "LOW",
    },
    39: {
        "name": "Form Analysis (Password)",
        "safe": "Forms look standard.",
        "unsafe": "Suspicious password form setup.",
        "severity": "MEDIUM",
    },
    40: {
        "name": "VirusTotal Check",
        "safe": "Not flagged by VirusTotal.",
        "unsafe": "Flagged as malicious/suspicious by VirusTotal engines.",
        "severity": "HIGH",
    },
}


# --- Helper Functions ---
def ensure_model_exists():
    """Ensures model and feature files exist, trains if needed."""
    os.makedirs(PICKLE_DIR, exist_ok=True)
    if not os.path.exists(MODEL_PATH) or not os.path.exists(FEATURES_PATH):
        print(f"Model or feature names not found. Attempting to train...")
        try:
            train_script_path = "train_model.py"
            if not os.path.exists(train_script_path):
                raise FileNotFoundError(f"{train_script_path} not found.")
            python_executable = sys.executable
            print(f"Running training script: {python_executable} {train_script_path}")
            result = subprocess.run(
                [python_executable, train_script_path],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
            print(
                "--- Training Script Output START ---\n",
                result.stdout,
                "\n--- Training Script Output END ---",
            )
            if result.stderr:
                print(
                    "--- Training Script Error Output START ---\n",
                    result.stderr,
                    "\n--- Training Script Error Output END ---",
                    file=sys.stderr,
                )
            if not os.path.exists(MODEL_PATH) or not os.path.exists(FEATURES_PATH):
                raise Exception(
                    "Training script ran but failed to create required files."
                )
            print("Model training completed via subprocess.")
        except FileNotFoundError as fnf_error:
            print(f"Error: {fnf_error}", file=sys.stderr)
            raise Exception("Training script missing.") from fnf_error
        except subprocess.CalledProcessError as proc_error:
            print(
                f"Error running training script (Exit Code: {proc_error.returncode}): {proc_error}\n--- Training Output ---\n{proc_error.stdout}\n{proc_error.stderr}\n--- End Output ---",
                file=sys.stderr,
            )
            raise Exception("Failed to train model.") from proc_error
        except Exception as e:
            print(f"Error during model check/training: {e}", file=sys.stderr)
            raise Exception(f"Failed to ensure model exists: {e}") from e
    else:
        print("Model and feature names found.")


def analyze_features(features_with_domain, url_type="Initial"):
    """Analyze features and categorize them."""
    print(f"--- Analyzing features for {url_type} URL ---")
    analysis = {
        "safe": [],
        "unsafe": [],
        "neutral": [],
        "severity_counts": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
    }
    numeric_features = features_with_domain[:-1]
    if len(numeric_features) != EXPECTED_FEATURE_COUNT_NUMERICAL:
        print(
            f"ERROR: analyze_features ({url_type}) expected {EXPECTED_FEATURE_COUNT_NUMERICAL}, got {len(numeric_features)}",
            file=sys.stderr,
        )
        return analysis
    for i, value in enumerate(numeric_features):
        if i in FEATURE_EXPLANATIONS:
            expl = FEATURE_EXPLANATIONS[i]
            name = expl.get("name", f"F{i}")
            severity = expl.get("severity", "LOW")
            if value == 1:
                analysis["safe"].append(
                    {"name": name, "explanation": expl.get("safe", "OK")}
                )
            elif value == -1:
                analysis["severity_counts"][severity] += 1
                analysis["unsafe"].append(
                    {
                        "name": name,
                        "explanation": expl.get("unsafe", "Risk"),
                        "severity": severity,
                    }
                )
            else:
                analysis["neutral"].append(
                    {"name": name, "explanation": f"{name}: Neutral/NA"}
                )
        else:
            name = f"F_{i}"
            print(f"W: No explanation {name}")
            analysis["neutral"].append({"name": name, "explanation": "Neutral/NA"})
    return analysis


def calculate_weighted_safety_score(
    url, features, domain_info, model_prediction, model_probability
):
    base_score = 66.53  # Start with a neutral score
    print(f"Starting Score Calc (Initial) - Base: {base_score:.2f}")

    # Initialize pen variable with a default value
    pen = 0.0

    try:
        # Safely extract TLD from URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        url_tld = domain.split(".")[-1].lower() if domain else ""

        # Check TLD
        suspicious_tlds = ["xyz", "top", "club", "online", "site", "info", "biz"]
        if url_tld in suspicious_tlds:
            pen = -1.5
            print(f"  Penalty: Suspicious TLD '{url_tld}' -> {pen:.2f}")
            base_score += pen

        # Add domain reputation boost if available
        if domain_info and "domain" in domain_info:
            domain = domain_info["domain"]
            if domain in [
                "google.com",
                "youtube.com",
                "facebook.com",
                "amazon.com",
                "microsoft.com",
            ]:
                boost = 11.65
                print(f"  * Legit Boost '{domain}': +{boost}")
                base_score += boost

        # Adjust based on model prediction and probability
        if model_prediction == 1:  # Safe prediction
            base_score += model_probability * 10  # Boost score based on confidence
        else:  # Unsafe prediction
            base_score -= (
                1 - model_probability
            ) * 15  # Reduce score based on confidence

        # Ensure score stays within 0-100 range
        adjusted_score = base_score
        final_score = round(max(0, min(100, adjusted_score)), 2)

        return final_score

    except Exception as e:
        print(f"Error in calculate_weighted_safety_score: {str(e)}")
        # Return a default score if there's an error
        return 50.0  # Neutral score


def generate_detailed_recommendations(
    safety_score, feature_analysis, initial_url=None, final_url=None
):
    """Generate recommendations, potentially noting redirects."""
    recommendations = []
    unsafe_count = len(feature_analysis.get("unsafe", []))
    if initial_url and final_url and initial_url != final_url:
        recommendations.append(f"Note: Initial URL redirected to -> {final_url}")
    if safety_score >= 85:
        recommendations.append(
            f"\n✅ LOW RISK ({safety_score}% safe): Final URL appears generally safe."
        )
    elif safety_score >= 60:
        recommendations.append(
            f"\n🤔 CAUTION ADVISED ({safety_score}% safe): Minor risks detected. Verify source."
        )
    elif safety_score >= DANGER_THRESHOLD:
        recommendations.append(
            f"\n⚠️ MEDIUM RISK ({safety_score}% safe): Suspicious factors detected. EXTREME caution required."
        )
    else:
        recommendations.append(
            f"\n🚨 HIGH RISK ({safety_score}% safe): Strong risk indicators. **DO NOT PROCEED.**"
        )
    if unsafe_count > 0:
        recommendations.append(f"\nKey Risk Factors ({unsafe_count} found):")
        sorted_unsafe = feature_analysis.get("unsafe", [])  # Assumes pre-sorted
        for feature in sorted_unsafe[:7]:
            recommendations.append(
                f"  - **{feature.get('name', '?')} ({feature.get('severity', '?')}):** {feature.get('explanation', '?')}"
            )
        if unsafe_count > 7:
            recommendations.append("  - ... and others.")
    if feature_analysis.get("safe"):
        recommendations.append("\nPositive Indicators:")
        for feature in feature_analysis["safe"][:4]:
            recommendations.append(
                f"  - {feature.get('name', '?')}: {feature.get('explanation', '?')}"
            )
    recommendations.append("\nGeneral Security Tips:")
    if safety_score < 60:
        recommendations.extend(
            [
                "  - NEVER enter passwords/financial details unless 100% certain.",
                "  - Be wary of urgent requests, unexpected warnings, offers too good to be true.",
                "  - Check URL bar carefully for misspellings/odd chars.",
                "  - If unsure, contact company via known, trusted method (not from link!).",
            ]
        )
    else:
        recommendations.extend(
            [
                "  - Always double-check addresses.",
                "  - Keep software up-to-date.",
                "  - Use strong passwords & MFA/2FA.",
            ]
        )
    if safety_score < DANGER_THRESHOLD + 10:
        recommendations.append("  - Consider reporting suspicious URLs.")
    return "\n".join(recommendations)


def handle_analysis_error(error_type):
    """Return appropriate error message based on type of error"""
    if isinstance(error_type, requests.exceptions.ConnectionError):
        return {
            "message": "Unable to connect. Please check your internet connection.",
            "type": "connection",
        }
    elif isinstance(error_type, requests.exceptions.Timeout):
        return {
            "message": "Request timed out. Please try again later.",
            "type": "timeout",
        }
    elif isinstance(error_type, requests.exceptions.RequestException):
        return {
            "message": "Something went wrong with the analysis. Please try again later.",
            "type": "request",
        }
    else:
        return {
            "message": "An unexpected error occurred. Please try again later.",
            "type": "unknown",
        }


# --- End Helper Functions ---


# --- Main Flask Route ---
@app.route("/", methods=["GET", "POST"])
def index():
    print(">>> INDEX ROUTE HIT <<<")
    context = {
        "url": None,
        "final_url": None,
        "safety_score": None,
        "prediction": None,
        "recommendations": None,
        "feature_analysis": None,
        "is_unsafe": None,
        "analysis_timestamp": None,
        "error": None,
        "warning": None,
        "current_year": datetime.now().year,
    }
    model = None
    expected_feature_names_list = None

    try:
        ensure_model_exists()
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        with open(FEATURES_PATH, "r") as f:
            expected_feature_names_list = json.load(f)
        if len(expected_feature_names_list) != EXPECTED_FEATURE_COUNT_NUMERICAL:
            raise ValueError(
                f"FATAL: Feature name list len mismatch ({len(expected_feature_names_list)} vs {EXPECTED_FEATURE_COUNT_NUMERICAL})"
            )

        if request.method == "POST":
            print("--- POST REQUEST RECEIVED ---")
            # Reset all analysis-related context variables
            context["final_url"] = None
            context["safety_score"] = None
            context["prediction"] = None
            context["recommendations"] = None
            context["feature_analysis"] = None
            context["is_unsafe"] = None
            context["analysis_timestamp"] = None
            context["error"] = None
            context["warning"] = None

            # Get URL from form, handling both initial submission and try again
            url_input = request.form.get("url", "").strip()
            if not url_input:
                context["error"] = "Please enter a URL."
                return render_template("index.html", **context)

            # Store the URL in context for display
            context["url"] = url_input

            # --- Wrap core processing ---
            try:
                print("--- ENTERING CORE PROCESSING TRY BLOCK ---", flush=True)
                initial_url = (
                    url_input
                    if url_input.startswith(("http://", "https://"))
                    else "https://" + url_input
                )
                print(f"Analyzing Initial URL: {initial_url}", flush=True)
                sys.stdout.flush()
                final_url = initial_url
                response = None
                initial_request_error = None
                headers = {"User-Agent": "Mozilla/5.0", "Accept": "text/html"}
                try:
                    verify_opt = certifi.where() if "certifi" in sys.modules else False
                    response = requests.get(
                        initial_url,
                        headers=headers,
                        timeout=15,
                        verify=verify_opt,
                        allow_redirects=True,
                    )
                    final_url = response.url
                    if response.status_code == 403:  # Specifically Forbidden
                        initial_request_error = f"Access Forbidden (403) to {final_url}. Site blocked the request."
                        print(f"W: {initial_request_error}.")
                        context["warning"] = (
                            initial_request_error + " Limited analysis performed."
                        )
                    elif response.status_code == 404:  # Specifically Not Found
                        initial_request_error = f"URL Not Found (404): {final_url}."
                        print(f"W: {initial_request_error}.")
                        context["warning"] = (
                            initial_request_error + " Limited analysis performed."
                        )
                    elif 400 <= response.status_code < 500:  # Other Client Errors
                        initial_request_error = f"Client Error ({response.status_code}) accessing {final_url}."
                        print(f"W: {initial_request_error}. Proceeding.")
                        context["warning"] = (
                            initial_request_error + " Limited analysis performed."
                        )
                    elif response.status_code >= 500:  # Server Errors
                        response.raise_for_status()
                    context["final_url"] = final_url
                    if initial_url != final_url:
                        print(
                            f"Redirect: Initial [{initial_url}] -> Final [{final_url}]",
                            flush=True,
                        )
                        sys.stdout.flush()
                except Timeout:
                    initial_request_error = f"Timeout connecting to {initial_url}."
                    print(f"W: {initial_request_error}.")
                except LocationParseError as parse_err:
                    initial_request_error = (
                        f"Invalid hostname structure in {initial_url}: {parse_err}."
                    )
                    print(f"E: {initial_request_error}")
                    context["error"] = initial_request_error + " Cannot analyze."
                    return render_template("index.html", **context)
                except RequestException as req_err:
                    initial_request_error = f"Could not reach {initial_url}: {req_err}."
                    print(f"W: {initial_request_error}.", flush=True)
                    sys.stdout.flush()
                if initial_request_error and not context["error"]:
                    context["warning"] = (
                        initial_request_error + " Proceeding with limited analysis."
                    )

                # --- Initialize results ---
                results = {}
                score_initial, pred_initial_val = (
                    100.0,
                    1,
                )  # Default safe unless analysis runs
                feat_initial_with_domain = None

                # --- Step 2a: Analyze INITIAL URL ---
                print(
                    f"\n--- Analyzing FEATURES for INITIAL URL: {initial_url} ---",
                    flush=True,
                )
                sys.stdout.flush()
                gsb_key = (
                    GSB_API_KEY
                    if GSB_API_KEY
                    and GSB_API_KEY != "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"
                    else None
                )  # Replace placeholder check if needed
                vt_key = (
                    VT_API_KEY
                    if VT_API_KEY and VT_API_KEY != "YOUR_VIRUSTOTAL_PUBLIC_API_KEY"
                    else None
                )  # Replace placeholder check if needed
                if not gsb_key:
                    print("W: GSB key not set.")
                if not vt_key:
                    print("W: VT key not set.")

                fe_initial = FeatureExtraction(initial_url)
                features_vector_initial = fe_initial.getFeaturesList(
                    api_key=gsb_key, vt_api_key=vt_key
                )
                if len(features_vector_initial) != EXPECTED_FEATURE_COUNT_NUMERICAL + 1:
                    raise ValueError(f"Initial URL feature extraction length mismatch")
                num_feat_initial = [
                    int(f) if isinstance(f, (int, float)) and f in [-1, 0, 1] else 0
                    for f in features_vector_initial[:-1]
                ]
                if len(num_feat_initial) != EXPECTED_FEATURE_COUNT_NUMERICAL:
                    raise ValueError("Initial numeric feature count mismatch.")

                feat_initial_df = pd.DataFrame(
                    [num_feat_initial], columns=expected_feature_names_list
                )
                feat_initial_with_domain = num_feat_initial + [
                    fe_initial.domain if fe_initial.domain else ""
                ]

                pred_initial_res = model.predict(feat_initial_df)
                pred_initial_val = (
                    int(pred_initial_res[0]) if pred_initial_res[0] in [1, -1] else -1
                )
                prob_safe_initial = 0.5
                try:
                    probs_init = model.predict_proba(feat_initial_df)[0]
                    safe_idx = list(model.classes_).index(1)
                    prob_safe_initial = max(0, min(1, probs_init[safe_idx]))
                except:
                    pass
                score_initial = calculate_weighted_safety_score(
                    initial_url,
                    feat_initial_with_domain,
                    None,
                    pred_initial_val,
                    prob_safe_initial,
                )
                results["initial"] = {
                    "score": score_initial,
                    "pred": pred_initial_val,
                    "features": feat_initial_with_domain,
                }
                print(
                    f"--- Initial URL Analysis Complete: Score={score_initial}, Pred={pred_initial_val} ---",
                    flush=True,
                )
                sys.stdout.flush()
                # --- Step 2b: Analyze FINAL URL ---
                # >>> REMOVE/COMMENT OUT FINAL URL ANALYSIS <<<
                # score_final = score_initial
                # pred_final_value = pred_initial_val
                # features_final_with_domain = feat_initial_with_domain
                # analysis_to_use = "initial"

                # --- NEW Step 4: Determine Final Outcome based on ML and API checks ---
                print(f"\n--- Determining Final Outcome ---")
                print(f"ML Prediction (Initial URL): {pred_initial_val}")

                # Default to ML results initially
                final_pred_to_use = pred_initial_val
                final_score_to_use = results["initial"][
                    "score"
                ]  # Use initial score as base
                features_to_analyze = results["initial"][
                    "features"
                ]  # Use initial features
                analysis_source = "ML Model"  # Track the source of the decision

                if final_pred_to_use == 1:
                    # ML predicted SAFE, now check API results stored in features
                    print("ML is Safe. Checking API results from feature vector...")
                    # Indices based on your getFeaturesList order:
                    gsb_feature_index = 33
                    vt_feature_index = 40

                    gsb_result = features_vector_initial[gsb_feature_index]
                    vt_result = features_vector_initial[vt_feature_index]

                    print(f"  GSB Feature Result: {gsb_result}")
                    print(f"  VT Feature Result: {vt_result}")

                    if gsb_result == -1 or vt_result == -1:
                        print("API Check Override: GSB or VT flagged as DANGEROUS.")
                        final_pred_to_use = -1  # Override ML prediction
                        analysis_source = "API (GSB/VT)"
                        # Adjust score to reflect API danger, even if ML was safe
                        # Example: Assign a moderately low score
                        final_score_to_use = min(score_initial, 30.0)  # Cap score low
                        print(
                            f"  Overriding Prediction to -1. Final Score adjusted to: {final_score_to_use}"
                        )
                    else:
                        print(
                            "API Checks confirm Safe/Neutral. Sticking with ML Safe prediction."
                        )
                        # Keep final_pred_to_use = 1
                        # Keep final_score_to_use = results["initial"]["score"]
                        analysis_source = "ML Model & APIs"  # Both agree

                else:
                    # ML predicted DANGEROUS initially
                    print("ML is Dangerous. Using ML result directly.")
                    # Keep final_pred_to_use = -1
                    # Keep final_score_to_use = results["initial"]["score"]
                    analysis_source = "ML Model"

                # --- Set context based on the final decision ---
                context["safety_score"] = round(final_score_to_use, 2)
                context["prediction"] = final_pred_to_use
                context["is_unsafe"] = final_pred_to_use == -1
                context["feature_analysis"] = analyze_features(
                    features_to_analyze,
                    url_type="Initial",  # Analyze features from initial URL
                )
                # Add note about analysis source to recommendations? (Optional)
                context["recommendations"] = generate_detailed_recommendations(
                    context["safety_score"],
                    context["feature_analysis"],
                    initial_url=initial_url,
                    final_url=final_url,  # Still useful to show redirection
                )
                # Add the source of the final decision to the recommendations or context if desired
                context["recommendations"] += (
                    f"\n\n*Final assessment based on: {analysis_source}*"
                )
                context["analysis_timestamp"] = datetime.now(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )

                print(f"--- Final Decision ---")
                print(
                    f"  Prediction: {'DANGEROUS' if context['is_unsafe'] else 'SAFE'} ({context['prediction']})"
                )
                print(f"  Safety Score: {context['safety_score']}%")
                print(f"  Based On: {analysis_source}")
                # --- End NEW Step 4 ---

                # --- Step 5: Analyze Features & Generate Recommendations ---
                # This block is now *integrated* into the new Step 4 logic above.
                # Ensure sorting and recommendation generation uses the final decided context.
                if context["feature_analysis"] and context["feature_analysis"].get(
                    "unsafe"
                ):
                    try:
                        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
                        context["feature_analysis"]["unsafe"].sort(
                            key=lambda item: severity_order.get(
                                item.get("severity", "LOW"), 3
                            )
                        )
                    except Exception as sort_e:
                        print(f"W: Sort unsafe err: {sort_e}")

                # Recommendation generation is already handled within the new Step 4 block

            # --- Catch errors specifically within the POST processing ---
            except Exception as post_error:
                print("--- ERROR IN POST PROCESSING CATCH BLOCK ---", flush=True)
                sys.stdout.flush()
                print(
                    f"Error processing POST for {url_input}: {post_error}",
                    file=sys.stderr,
                )
                traceback.print_exc()
                context["error"] = f"Failed to analyze URL. Error: {post_error}"
                context["final_url"] = (
                    final_url if "final_url" in locals() else initial_url
                )
                context["safety_score"] = None
                context["prediction"] = None
                context["recommendations"] = "Analysis error."
                context["feature_analysis"] = None
                context["is_unsafe"] = None
                context["analysis_timestamp"] = None

        return render_template("index.html", **context)

    # --- Catch Fatal Errors ---
    except Exception as e:
        print(f"FATAL Error in Flask route setup: {str(e)}", file=sys.stderr)
        traceback.print_exc()
        context["error"] = f"Critical server error ({type(e).__name__})."
        for key in list(context.keys()):
            if key not in ["error", "current_year"]:
                context[key] = None
        return render_template("index.html", **context)


# --- Main Entry Point ---
if __name__ == "__main__":
    # from waitress import serve
    # print("Starting server via Waitress on http://0.0.0.0:5000")
    # serve(app, host='0.0.0.0', port=5000)
    print("Starting server via Flask dev server on http://0.0.0.0:5000")
    app.run(
        debug=True, host="0.0.0.0", port=5000, use_reloader=True
    )  # Run on port 5000 and this is final one
