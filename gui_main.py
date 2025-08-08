# gui_main.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import threading
from datetime import datetime
import json
import asyncio
import httpx
import textwrap

# Import custom modules from the framework
from analyzers.static_analyzer import StaticAnalyzer
from analyzers.vt_analyzer import VTAnalyzer
from utils.config import get_config_value
from utils.exporter import export_all_formats

def analyze_file(file_path: str, vt_analyzer: VTAnalyzer) -> dict:
    """
    Orchestrates the analysis of a single file using both static and VT analyzers.
    """
    static_analyzer = StaticAnalyzer(file_path)
    static_report = static_analyzer.run_analysis()

    file_hash = static_report.get('hashes', {}).get('sha256')
    if file_hash:
        vt_report = vt_analyzer.query_hash(file_hash)
        static_report.update(vt_report)
    else:
        static_report['virustotal_report'] = {'error': 'Hash could not be computed for VT query.'}

    return static_report

def analyze_url(url: str, vt_analyzer: VTAnalyzer) -> dict:
    """
    Orchestrates the analysis of a single URL.
    """
    vt_report = vt_analyzer.query_url(url)
    final_report = {
        'static_analysis_score': 0, 
        'static_analysis_summary': ['N/A for URLs'],
        'score_breakdown': {}
    }
    final_report.update(vt_report)
    return final_report

async def get_ai_summary(report: dict, api_key: str) -> str:
    """
    Generates an AI-powered summary of the analysis report using the Gemini API.
    """
    if not api_key:
        return "Gemini API key not configured. Skipping AI summary."
    try:
        prompt_data = {
            "static_findings": report.get("static_analysis_summary"),
            "yara_matches": report.get("yara_analysis", {}).get("matches"),
            "virustotal_positives": report.get("virustotal_report", {}).get("positives")
        }

        prompt = (
            "You are a senior SOC analyst. Based on the following data, provide a concise threat summary and map potential adversary behavior to the MITRE ATT&CK framework. "
            "Focus on actionable intelligence.\n\n"
            "1. **Threat Summary:** (Provide a brief, clear summary of the threat.)\n"
            "2. **MITRE ATT&CK Mapping:** (List relevant Tactic and Technique IDs, e.g., T1059.001 - Command and Scripting Interpreter: PowerShell)\n\n"
            f"Analysis Data:\n{json.dumps(prompt_data, indent=2)}"
        )

        payload = {"contents": [{"role": "user", "parts": [{"text": prompt}]}]}
        api_url = get_config_value("GEMINI_ENDPOINT") + f"?key={api_key}"

        async with httpx.AsyncClient() as client:
            response = await client.post(api_url, json=payload, timeout=60)
            response.raise_for_status()
            result = response.json()

        if result.get('candidates'):
            return result['candidates'][0]['content']['parts'][0]['text']
        else:
            return "AI summary could not be generated. The response was empty."
    except httpx.HTTPStatusError as e:
        return f"AI summary generation failed with HTTP error: {e.response.status_code} - {e.response.text}"
    except Exception as e:
        return f"AI summary generation failed with an unexpected error: {e}"

def format_report_for_gui(report: dict, indicator: str) -> str:
    """
    Formats the analysis report into a human-readable string for the GUI.
    """
    report_lines = []
    report_lines.append("="*25 + " ANALYSIS REPORT " + "="*25)
    report_lines.append(f"Indicator:\t{indicator}")
    report_lines.append(f"Report Time:\t{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("-"*67)

    if 'file_info' in report:
        file_info = report['file_info']
        report_lines.append("\n[+] FILE INFORMATION")
        report_lines.append(f"  File Name:\t{file_info.get('file_name', 'N/A')}")
        report_lines.append(f"  Extension:\t{file_info.get('file_extension', 'N/A')}")
        report_lines.append(f"  True Type:\t{file_info.get('true_file_type', 'N/A')}")
        report_lines.append(f"  Entropy:\t{file_info.get('entropy', 0.0):.4f}")

    report_lines.append("\n[+] STATIC ANALYSIS")
    static_score = report.get('static_analysis_score', 0)
    report_lines.append(f"  Static Score:\t\t{static_score}")
    summary = report.get('static_analysis_summary', ["N/A"])
    report_lines.append("  Static Findings:")
    for item in summary:
        report_lines.append(f"    - {item}")

    if 'ip_enrichment' in report and report['ip_enrichment']:
        report_lines.append("\n[+] GEO-IP ENRICHMENT")
        for item in report['ip_enrichment']:
            report_lines.append(f"  - {item['ip']} ({item['isp']}) - {item['country']}, {item['city']}")

    vt_report = report.get('virustotal_report', {})
    vt_positives = vt_report.get('positives', 0) if vt_report and 'error' not in vt_report else 0
    threat_score = static_score + (vt_positives * 2)

    verdict = "CLEAN"
    if threat_score > 20:
        verdict = "MALICIOUS"
    elif threat_score > 5:
        verdict = "SUSPICIOUS"

    report_lines.append("\n[+] FINAL VERDICT")
    report_lines.append(f"  Overall Threat Score:\t{threat_score}")
    report_lines.append(f"  Recommendation:\t{verdict}")

    if 'ai_summary' in report:
        summary_part, attack_part = report['ai_summary'], ""
        if "**MITRE ATT&CK Mapping:**" in summary_part:
            parts = summary_part.split("**MITRE ATT&CK Mapping:**")
            summary_part = parts[0].replace("**Threat Summary:**", "").strip()
            attack_part = parts[1].strip()

        report_lines.append("\n[+] AI-POWERED SUMMARY")
        for line in textwrap.wrap(summary_part, width=65):
            report_lines.append(f"  {line}")

        if attack_part:
            report_lines.append("\n[+] MITRE ATT&CK MAPPING")
            for line in attack_part.split('\n'):
                report_lines.append(f"  {line}")

    report_lines.append("\n" + "="*67 + "\n\n")
    return "\n".join(report_lines)

class ScoreVisualizationWindow(tk.Toplevel):
    """
    A pop-up window to display the threat score breakdown as a bar chart.
    """
    def __init__(self, parent, score_data):
        super().__init__(parent)
        self.title("Threat Score Visualization")
        self.geometry("600x400")
        self.configure(bg="#1c1c1c")

        canvas = tk.Canvas(self, bg="#1c1c1c", highlightthickness=0)
        canvas.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.draw_chart(canvas, score_data)

    def draw_chart(self, canvas, score_data):
        chart_data = {k: v for k, v in score_data.items() if v > 0}
        if not chart_data:
            canvas.create_text(300, 200, text="No significant threats detected.", fill="#00ff41", font=("Courier New", 14))
            return

        max_score = max(chart_data.values())
        chart_width, chart_height = 560, 360
        bar_width = chart_width / (len(chart_data) * 2)

        x_padding, y_padding = 50, 50

        for i, (name, score) in enumerate(chart_data.items()):
            x0 = x_padding + i * (bar_width * 2)
            y0 = chart_height - (score / max_score) * (chart_height - y_padding)
            x1 = x0 + bar_width
            y1 = chart_height

            canvas.create_rectangle(x0, y0, x1, y1, fill="#00ff41", outline="#00ff41")
            canvas.create_text(x0 + bar_width/2, y0 - 10, text=str(score), fill="white", font=("Courier New", 10))
            canvas.create_text(x0 + bar_width/2, y1 + 15, text=name, fill="white", font=("Courier New", 10), angle=25)

class AnalysisApp(tk.Tk):
    """
    The main application class for the GUI.
    """
    def __init__(self, vt_analyzer, gemini_api_key):
        super().__init__()
        self.vt_analyzer = vt_analyzer
        self.gemini_api_key = gemini_api_key
        self.title("SOC Tier 1 Analysis Framework")
        self.geometry("800x700")

        self.last_score_data = None
        self._setup_style()
        self._create_widgets()

    def _setup_style(self):
        bg_color, fg_color = "#1c1c1c", "#00ff41"
        self.configure(bg=bg_color)
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('.', background=bg_color, foreground=fg_color, font=('Courier New', 10))
        style.configure('TFrame', background=bg_color)
        style.configure('TButton', background="#2a2a2a", foreground=fg_color, borderwidth=1)
        style.map('TButton', background=[('active', '#3c3c3c')])
        style.configure('TEntry', fieldbackground="#333333", foreground=fg_color, insertcolor=fg_color)
        style.configure('TLabelFrame', background=bg_color, foreground=fg_color)
        style.configure('TLabelFrame.Label', background=bg_color, foreground=fg_color)

    def _create_widgets(self):
        main_frame = ttk.Frame(self, padding="10", style='TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True)

        input_frame = ttk.LabelFrame(main_frame, text="Indicator Input", padding="10")
        input_frame.pack(fill=tk.X, pady=5)

        file_button = ttk.Button(input_frame, text="Analyze Files...", command=self.start_file_analysis)
        file_button.pack(side=tk.LEFT, padx=5)

        self.url_entry = ttk.Entry(input_frame, width=60, style='TEntry')
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        url_button = ttk.Button(input_frame, text="Analyze URL", command=self.start_url_analysis)
        url_button.pack(side=tk.LEFT, padx=5)

        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=5)

        self.viz_button = ttk.Button(action_frame, text="Visualize Last Score", command=self.show_visualization, state="disabled")
        self.viz_button.pack(side=tk.LEFT, padx=10)

        results_frame = ttk.LabelFrame(main_frame, text="Analysis Report", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.results_text = tk.Text(results_frame, wrap=tk.WORD, font=("Courier New", 10), bg="#1c1c1c", fg="#00ff41", insertbackground="#00ff41", borderwidth=0, highlightthickness=0)
        self.results_text.pack(fill=tk.BOTH, expand=True)

        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def show_visualization(self):
        if self.last_score_data:
            ScoreVisualizationWindow(self, self.last_score_data)

    def run_multi_file_analysis(self, file_paths):
        total_files = len(file_paths)
        for i, file_path in enumerate(file_paths):
            try:
                self.status_var.set(f"Analyzing file {i+1}/{total_files}...")
                report = analyze_file(file_path, self.vt_analyzer)

                loop = asyncio.new_event_loop()
                ai_summary_text = loop.run_until_complete(get_ai_summary(report, self.gemini_api_key))
                loop.close()
                report['ai_summary'] = ai_summary_text

                vt_positives = report.get('virustotal_report', {}).get('positives', 0)
                self.last_score_data = report.get('score_breakdown', {})
                self.last_score_data['VirusTotal Detections'] = vt_positives * 2
                self.viz_button.config(state="normal")

                formatted_report = format_report_for_gui(report, os.path.basename(file_path))
                self.results_text.insert(tk.END, formatted_report)
                self.results_text.see(tk.END)
                export_all_formats(report, os.path.basename(file_path))
            except Exception as e:
                self.results_text.insert(tk.END, f"--- ERROR analyzing {os.path.basename(file_path)} ---\n{e}\n\n")
        self.status_var.set(f"Analysis complete for {total_files} files. Ready.")

    def start_file_analysis(self):
        # Set the initialdir to the shared folder inside the container.
        file_paths = filedialog.askopenfilenames(
            initialdir="/scannable_files",
            title="Select files for analysis"
        )
        if not file_paths: return
        self.results_text.delete(1.0, tk.END)
        self.viz_button.config(state="disabled")
        threading.Thread(target=self.run_multi_file_analysis, args=(file_paths,), daemon=True).start()

    def start_url_analysis(self):
        self.viz_button.config(state="disabled")
        self.last_score_data = None
        url = self.url_entry.get()
        if not url.startswith("http"):
            messagebox.showerror("Invalid URL", "Please enter a valid URL (e.g., http://example.com)")
            return
        self.results_text.delete(1.0, tk.END)
        threading.Thread(target=self.run_analysis_and_update_gui, args=(url, 'url'), daemon=True).start()

    def run_analysis_and_update_gui(self, indicator, indicator_type):
        try:
            self.status_var.set(f"Analyzing {indicator_type}...")
            if indicator_type == 'url':
                report = analyze_url(indicator, self.vt_analyzer)
            else:
                return

            loop = asyncio.new_event_loop()
            ai_summary_text = loop.run_until_complete(get_ai_summary(report, self.gemini_api_key))
            loop.close()
            report['ai_summary'] = ai_summary_text

            formatted_report = format_report_for_gui(report, indicator)
            self.results_text.insert(tk.END, formatted_report)
            export_all_formats(report, indicator)
            self.status_var.set("Analysis complete. Reports saved.")
        except Exception as e:
            self.status_var.set(f"Error: {e}")
            messagebox.showerror("Analysis Error", str(e))

if __name__ == "__main__":
    try:
        vt_api_key = get_config_value('VIRUSTOTAL_API_KEY')
        gemini_api_key = get_config_value('GEMINI_API_KEY')
        vt_analyzer_instance = VTAnalyzer(api_key=vt_api_key)
        app = AnalysisApp(vt_analyzer_instance, gemini_api_key)
        app.mainloop()
    except Exception as e:
        messagebox.showerror("Fatal Error", f"Could not start application: {e}")


