# Nuclei Scheduler

A Python-based scheduler for managing [Nuclei](https://github.com/projectdiscovery/nuclei) scans. This script allows you to run long-running security scans within specific time windows, automatically pausing and resuming them as needed. It's perfect for managing resource-intensive scans on systems where you need to limit activity to off-peak hours.

## Features

- **Time-Based Scheduling**: Automatically starts and stops Nuclei scans based on configurable time windows for weekdays and weekends.
- **Kill & Resume**: Gracefully stops the Nuclei process using `SIGINT` (Ctrl+C) when the allowed time window ends, ensuring Nuclei can save its state.
- **Automatic Resume**: Automatically finds and uses the last `.cfg` resume file to continue the scan from where it left off.
- **State Management**: Tracks the progress of each unique scan command. Once a scan is complete, it won't be started again.
- **Dynamic Output Files**: When a scan is resumed, it appends a timestamp (`-HH-DD-MM`) to the output filename to prevent overwriting results from previous sessions.
- **Persistent Logging**: All scheduler actions and Nuclei output are appended to a `nuclei_scheduler.log` file for easy debugging and history tracking.
- **Graceful Shutdown**: Handles `KeyboardInterrupt` (Ctrl+C) to stop the running scan and save the resume state before exiting.
- **Old Resume File Cleanup**: Automatically deletes archived resume files older than a specified number of days (default is 7).

## Requirements

- Python 3.x
- [Nuclei](https://github.com/projectdiscovery/nuclei) installed and accessible in your system's `PATH`.

## Installation

1.  Save the script as `nuclei_scheduler.py`.
2.  Make it executable (optional): `chmod +x nuclei_scheduler.py`.
3.  No external Python libraries are required.

## Usage

To run the scheduler, execute the script from your terminal and pass the entire Nuclei command you want to run as a single argument, enclosed in quotes.

### Basic Syntax

```bash
python3 nuclei_scheduler.py "your_nuclei_command_here"
```

### Examples

**Example 1: Basic scan**
```bash
python3 nuclei_scheduler.py "nuclei -l targets.txt -t templates/ -o output.txt"
```

**Example 2: A more complex command**
```bash
python3 nuclei_scheduler.py "nuclei -duc -ni -l httpx.txt -c 100 -es info,low -etags wordpress,wp-plugin -o nuclei-result.txt"
```

The script will then take over, running this command only during the hours defined in the configuration.

## How It Works

1. **Scheduling**: Monitors time windows and starts/stops scans automatically
2. **Resume**: Captures resume files when stopped, continues from last position
3. **State**: Maintains scan status in `~/.nuclei_scheduler_state.json`
4. **Logging**: Outputs to console and `nuclei_scheduler.log`

## Example Output

```
🚀 NUCLEI SCHEDULER STARTED
📅 Date: 2024-01-15 14:30:00
⏰ SCHEDULING:
  ✅ Weekday: 01:00:00 - 07:00:00
  ❌ Weekend: Disabled

🔴 Waiting | Starting in: 10 hours, 30 minutes
🟢 Running (PID: 54321) | Stopping in: 5 hours, 15 minutes
🎉 SCAN COMPLETED - NO NEW SCAN WILL START!
```

### Resetting Scan State

If you want to force the script to start a scan from the beginning (ignoring its "completed" status), run it with the `--reset` flag. This will delete the state file.

```bash
python3 nuclei_scheduler.py --reset
```

## Configuration

All scheduling settings are located at the top of the `nuclei_scheduler.py` script. You can modify them directly.

```python
# --- SCHEDULING SETTINGS ---
WEEKDAY_SCAN_ENABLED = True
WEEKEND_SCAN_ENABLED = False

# Run from 1 AM to 7 AM on weekdays
WEEKDAY_SCAN_WINDOW = {
    'start': datetime.time(1, 0),
    'end': datetime.time(7, 0)
}

# For weekend scans, runs from Saturday at 00:10 until Sunday at 23:50
SATURDAY_SCAN_WINDOW = {
    'start': datetime.time(0, 10)
}
SUNDAY_SCAN_WINDOW = {
    'end': datetime.time(23, 50)
}
```

- `WEEKDAY_SCAN_ENABLED`: Set to `True` or `False` to enable/disable scanning on weekdays (Mon-Fri).
- `WEEKEND_SCAN_ENABLED`: Set to `True` or `False` to enable/disable scanning on weekends (Sat-Sun).
- `WEEKDAY_SCAN_WINDOW`: Defines the start and end times for scans. Handles overnight windows correctly (e.g., start at 22:00, end at 06:00).
- `SATURDAY_SCAN_WINDOW` / `SUNDAY_SCAN_WINDOW`: Defines the start and end times for a continuous weekend scanning window.

## Configuration

Edit script variables:

```python
# Weekday scanning (Monday-Friday) 01:00-07:00
WEEKDAY_SCAN_ENABLED = True
WEEKDAY_SCAN_WINDOW = {
    'start': datetime.time(1, 0),
    'end': datetime.time(7, 0)
}

# Weekend scanning (disabled by default)
WEEKEND_SCAN_ENABLED = False
```

## How It Works

1.  **Command ID**: The script generates a unique SHA1 hash for each Nuclei command. This ID is used to track the state of that specific scan.
2.  **State File**: A state file named `.nuclei_scheduler_state.json` is created in your home directory (`~`). This file stores the path to the latest resume file (`.cfg`) and the completion status for each command ID.
3.  **Main Loop**: The script enters an infinite loop, checking the current time every 30 seconds.
4.  **Execution Window**:
    - If the current time is **inside** the allowed scanning window and the process isn't running, it starts Nuclei. If a resume file exists for the command, it appends the `-resume` flag to the command.
    - If the current time is **outside** the window and the process is running, it sends a `SIGINT` signal to Nuclei. This allows Nuclei to shut down gracefully and write a final resume file. The script captures the path to this file and saves it in the state file for the next run.
5.  **Logging**: All output from the scheduler and the Nuclei process is redirected to `nuclei_scheduler.log` and printed to the console.

## License

This project is licensed under the MIT License.
