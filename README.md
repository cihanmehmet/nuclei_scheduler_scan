# nuclei_scheduler_scan
Nuclei Scheduler Scan

This script allows you to scan Nuclei daily between specific hours. The results are recorded in the log file.
```bash 
    python3 nuclei_scheduler.py "nuclei -duc -ni -l httpx.txt -c 200 -es info,low -o nuclei-result.txt"
    python3 nuclei_scheduler.py "nuclei -l targets.txt -t templates/ -o output.txt"
    python3 nuclei_scheduler.py "nuclei -duc -ni -l httpx.txt -c 100 -es info,low -etags wordpress,wp-plugin -o nuclei-result.txt"
```
