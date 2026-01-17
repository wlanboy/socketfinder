#!/usr/bin/env python3
import os
import pandas as pd
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

RESULT_DIR = "results"
TEMPLATE_DIR = "templates"
TEMPLATE_FILE = "report.html.j2"

# ------------------------------------------------------------
# Erweiterte Ampellogik
# ------------------------------------------------------------
def classify(row):
    if row.get("error") and str(row["error"]).strip() != "":
        return "red"
    if not row.get("tls_version"):
        return "red"
    if str(row.get("hostname_mismatch")).lower() == "true":
        return "red"

    tls = str(row.get("tls_version", ""))
    if tls not in ["TLSv1.2", "TLSv1.3"]:
        return "red"

    try:
        seclevel = int(row.get("seclevel", 0))
    except:
        seclevel = 0

    if seclevel == 0:
        return "red"
    if seclevel == 1:
        return "yellow"

    if row.get("cipher") in ["UNKNOWN", "", None]:
        return "yellow"
    if not row.get("san"):
        return "yellow"

    return "green"


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
def main():
    result_path = Path(RESULT_DIR)
    hosts = {}

    for file in result_path.glob("*_tls.csv"):
        host = file.name.replace("_tls.csv", "")
        tls_file = file
        err_file = result_path / f"{host}_errors.csv"

        df_tls = pd.read_csv(tls_file)
        df_err = pd.read_csv(err_file) if err_file.exists() else pd.DataFrame()

        if not df_err.empty:
            for col in df_tls.columns:
                if col not in df_err.columns:
                    df_err[col] = ""

        df = pd.concat([df_tls, df_err], ignore_index=True)

        df["ampel"] = df.apply(classify, axis=1)
        df["ampel_sort"] = df["ampel"].map({"red": 0, "yellow": 1, "green": 2})
        df = df.sort_values("ampel_sort")

        hosts[host] = df

    overview = [(host, df["ampel"].min()) for host, df in hosts.items()]

    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template(TEMPLATE_FILE)

    html = template.render(overview=overview, details=hosts)

    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html)

    print("Report erzeugt: report.html")


if __name__ == "__main__":
    main()
