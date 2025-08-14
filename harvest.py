import keyring
import subprocess
import tempfile
import os
import sys
import time
import logging
from logging.handlers import RotatingFileHandler
import tkinter as tk
from tkinter import scrolledtext
import threading
import queue
import re
import json
import traceback

# --- Configuration File Path ---
CONFIG_FILE_PATH = "chia_monitor_config.json"

# --- Default Configuration (used if config file is not found or invalid) ---
DEFAULT_CONFIG = {
    "chia_path": r"c:\Chia\resources\app.asar.unpacked\daemon\chia.exe", # Path to Chia CLI/daemon executable
    "chia_gui_path": r"c:\Chia\chia.exe", # Path to Chia GUI executable
    "keyring_service_name": "chia_wallet_password",
    "keyring_username": "chia_farmer",
    "network_share_service_name": "chia_network_shares",
    "log_file_path": r"D:\harvest_script_log.log",
    "max_log_bytes": 1 * 1024 * 1024,
    "backup_count": 5,
    "summary_check_interval_seconds": 300,
    "network_drive_retry_attempts": 5, # Total attempts for the *full cycle* of checks
    "network_drive_retry_delay_seconds": 10,
    "plot_filename_pattern_str": r"plot-k32-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-.{64}\.plot",
    "plot_directories": [
        r"D:\\",
        r"E:\\",
        r"M:\\NAS-SYS02\ChiaFarmNFS01\\",
        r"N:\\NAS-SYS01\ChiaFarmNFS02\\"
    ],
    "expected_plots": 0
}

# --- Global Config and Compiled Pattern ---
config = {}
PLOT_FILENAME_PATTERN = None 

MAPPED_UNC_PATTERN = re.compile(r"^(?P<drive_letter>[A-Za-z]):(?P<unc_path>\\\\.+)$")

# --- Global GUI and Threading Variables ---
root = None
status_var = None
summary_text_widget = None
rolling_log_widget = None
log_queue = queue.Queue()
stop_event = threading.Event()

farm_status_label = None
last_check_timestamp_var = None
plot_count_var = None
expected_plots_entry = None
plot_match_indicator_label = None
plot_paths_text_widget = None

# --- Logging Setup ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# --- Custom Log Handler for GUI Text Widget ---
class TextWidgetHandler(logging.Handler):
    def __init__(self, msg_queue):
        super().__init__()
        self.msg_queue = msg_queue

    def emit(self, record):
        msg = self.format(record)
        try:
            self.msg_queue.put_nowait(msg)
        except queue.Full:
            pass

# --- Configuration Load/Save Functions ---
def load_config():
    global config, PLOT_FILENAME_PATTERN
    
    config = DEFAULT_CONFIG.copy()

    try:
        with open(CONFIG_FILE_PATH, 'r') as f:
            loaded_config = json.load(f)
        config.update(loaded_config)
        logger.info(f"Loaded configuration from {CONFIG_FILE_PATH}.")
        
        # Ensure numeric types are correctly cast
        config["max_log_bytes"] = int(config.get("max_log_bytes", DEFAULT_CONFIG["max_log_bytes"]))
        config["backup_count"] = int(config.get("backup_count", DEFAULT_CONFIG["backup_count"]))
        config["summary_check_interval_seconds"] = int(config.get("summary_check_interval_seconds", DEFAULT_CONFIG["summary_check_interval_seconds"]))
        config["network_drive_retry_attempts"] = int(config.get("network_drive_retry_attempts", DEFAULT_CONFIG["network_drive_retry_attempts"]))
        config["network_drive_retry_delay_seconds"] = int(config.get("network_drive_retry_delay_seconds", DEFAULT_CONFIG["network_drive_retry_delay_seconds"]))
        
        if not isinstance(config.get("plot_directories"), list):
            config["plot_directories"] = DEFAULT_CONFIG["plot_directories"]
            logger.warning(f"Invalid 'plot_directories' format in config. Using default.")
        
        try:
            config["expected_plots"] = int(config.get("expected_plots", DEFAULT_CONFIG["expected_plots"]))
        except ValueError:
            config["expected_plots"] = DEFAULT_CONFIG["expected_plots"]
            logger.warning(f"Invalid 'expected_plots' format in config. Using default ({DEFAULT_CONFIG['expected_plots']}).")

    except FileNotFoundError:
        logger.warning(f"Configuration file {CONFIG_FILE_PATH} not found. Using default settings.")
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON from {CONFIG_FILE_PATH}. File might be corrupted. Using default settings.")
    except Exception as e:
        logger.error(f"An unexpected error occurred while loading config: {e}. Using default settings.")

    PLOT_FILENAME_PATTERN = re.compile(config.get("plot_filename_pattern_str", DEFAULT_CONFIG["plot_filename_pattern_str"]))


def _reconfigure_logging():
    # Remove existing handlers to prevent duplicate logs if called multiple times
    for handler in logger.handlers[:]: 
        logger.removeHandler(handler)

    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # File handler
    file_handler = RotatingFileHandler(
        config["log_file_path"],
        maxBytes=config["max_log_bytes"],
        backupCount=config["backup_count"]
    )
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.INFO)
    logger.addHandler(file_handler)

    # GUI handler (only if GUI is active)
    if root:
        gui_handler = TextWidgetHandler(log_queue)
        gui_handler.setFormatter(log_formatter)
        gui_handler.setLevel(logging.INFO)
        logger.addHandler(gui_handler)
    else:
        # Fallback to stream handler if GUI not yet set up
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(log_formatter)
        stream_handler.setLevel(logging.INFO)
        logger.addHandler(stream_handler)


def save_config_on_exit():
    # Update plot_directories from GUI widget before saving
    config["plot_directories"] = [
        p.strip() for p in plot_paths_text_widget.get("1.0", tk.END).splitlines()
        if p.strip()
    ]

    # Update expected_plots from GUI widget before saving
    try:
        config["expected_plots"] = int(expected_plots_entry.get())
    except ValueError:
        config["expected_plots"] = 0
        logger.warning(f"Invalid expected plots input '{expected_plots_entry.get()}'. Saving 0 for expected plots.")

    try:
        with open(CONFIG_FILE_PATH, 'w') as f:
            json.dump(config, f, indent=4)
        logger.info(f"Configuration saved to {CONFIG_FILE_PATH}.")
    except Exception as e:
        logger.error(f"Error saving configuration to {CONFIG_FILE_PATH}: {e}")


# --- GUI Update Functions (called safely from main thread) ---
def _update_status_gui(message):
    if status_var:
        status_var.set(message)

def _update_summary_gui(message):
    if summary_text_widget:
        summary_text_widget.config(state=tk.NORMAL)
        summary_text_widget.delete(1.0, tk.END)
        summary_text_widget.insert(tk.END, message)
        summary_text_widget.config(state=tk.DISABLED)
        summary_text_widget.see(tk.END)

def _update_rolling_log_gui():
    while not log_queue.empty():
        try:
            message = log_queue.get_nowait()
            if rolling_log_widget:
                rolling_log_widget.config(state=tk.NORMAL)
                rolling_log_widget.insert(tk.END, message + "\n")
                rolling_log_widget.config(state=tk.DISABLED)
                rolling_log_widget.see(tk.END)
        except queue.Empty:
            break
    if root:
        root.after(100, _update_rolling_log_gui)

def _update_farm_status_indicator(is_farming):
    if farm_status_label:
        if is_farming:
            farm_status_label.config(text="Farming: ACTIVE", bg="green", fg="white")
        else:
            farm_status_label.config(text="Farming: INACTIVE", bg="red", fg="white")
    if last_check_timestamp_var:
        last_check_timestamp_var.set(f"Last Check: {time.strftime('%Y-%m-%d %H:%M:%S')}")

def _update_plot_count_gui(actual_count):
    if plot_count_var:
        plot_count_var.set(f"Plots Found: {actual_count}")

    if plot_match_indicator_label:
        expected_count = config["expected_plots"]
        try:
            if actual_count == expected_count:
                plot_match_indicator_label.config(text=f"Match: {actual_count}/{expected_count} (OK)", bg="green", fg="white")
            else:
                plot_match_indicator_label.config(text=f"Match: {actual_count}/{expected_count} (MISMATCH)", bg="red", fg="white")
        except ValueError:
            plot_match_indicator_label.config(text=f"Match: {actual_count}/INVALID (Config Error)", bg="orange", fg="black")


# --- Helper Functions (used by background thread) ---

def log_and_update_gui(message, is_error=False, is_summary=False):
    if is_error:
        logger.error(message)
    elif is_summary:
        logger.info(message)
        if root:
            root.after(0, lambda: _update_summary_gui(message))
    else:
        logger.info(message)

    if status_var and not is_summary:
        root.after(0, lambda: _update_status_gui(message.split('\n')[0]))

def get_passphrase_from_keyring():
    try:
        log_and_update_gui(f"Attempting to retrieve passphrase for service '{config['keyring_service_name']}', user '{config['keyring_username']}'...")
        password = keyring.get_password(config["keyring_service_name"], config["keyring_username"])
        if password:
            log_and_update_gui("Passphrase retrieved successfully from keyring.")
            return password
        else:
            log_and_update_gui(f"Failed to retrieve passphrase. Keyring returned None for service '{config['keyring_service_name']}', user '{config['keyring_username']}'.", is_error=True)
            return None
    except Exception as e:
        log_and_update_gui(f"CRITICAL_ERROR: An unexpected error occurred during keyring retrieval: {e}", is_error=True)
        return None

def run_chia_command(args, capture_output=False, detached_for_long_running_process=False):
    """Runs a Chia CLI command."""
    command = [config["chia_path"]] + args
    
    log_and_update_gui(f"Executing Chia command: {' '.join(command)}")

    try:
        if detached_for_long_running_process:
            # For long-running processes like `start farmer`, detach and stream output
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
            stdout_lines = []
            stderr_lines = []

            def read_pipe(pipe, output_list, is_error_pipe=False):
                for line in iter(pipe.readline, ''):
                    output_list.append(line)
                    log_and_update_gui(f"Chia {'stderr' if is_error_pipe else 'stdout'}: {line.strip()}", is_error=is_error_pipe)
                pipe.close()

            stdout_thread = threading.Thread(target=read_pipe, args=(process.stdout, stdout_lines, False))
            stderr_thread = threading.Thread(target=read_pipe, args=(process.stderr, stderr_lines, True))
            stdout_thread.start()
            stderr_thread.start()

            stdout_thread.join()
            stderr_thread.join()
            
            process.wait() # Wait for the process to truly finish (after pipes are closed)
            
            logger.info(f"Command exited with code: {process.returncode}")
            return "".join(stdout_lines), "".join(stderr_lines), process.returncode
        elif capture_output:
            # For commands where output is needed immediately (e.g., farm summary)
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            log_and_update_gui(f"Command exited with code: {result.returncode}")
            if result.stdout:
                log_and_update_gui(f"Command stdout:\n{result.stdout.strip()}")
            if result.stderr:
                log_and_update_gui(f"Command stderr:\n{result.stderr.strip()}", is_error=True)
            return result.stdout, result.stderr, result.returncode
        else:
            # For simple commands where output isn't needed or is streamed directly to console
            result = subprocess.run(command, check=False)
            log_and_update_gui(f"Command exited with code: {result.returncode}")
            return None, None, result.returncode

    except FileNotFoundError:
        log_and_update_gui(f"Error: Chia executable not found at '{config['chia_path']}'. Verify the path.", is_error=True)
        return None, None, 1
    except Exception as e:
        log_and_update_gui(f"An unexpected error occurred while running Chia command: {e}", is_error=True)
        return None, None, 1

def run_chia_command_gui(args):
    """Runs a Chia GUI command as a detached background process."""
    gui_path = config.get("chia_gui_path", r"c:\chia\chia.exe") # Use the dedicated GUI path
    command = [gui_path] + args
    
    log_and_update_gui(f"Executing Chia GUI command: {' '.join(command)}")

    try:
        subprocess.Popen(command, creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
        log_and_update_gui(f"Chia GUI command issued successfully for '{gui_path}'.")
    except FileNotFoundError:
        log_and_update_gui(f"Error: Chia GUI executable not found at '{gui_path}'. Verify the path.", is_error=True)
    except Exception as e:
        log_and_update_gui(f"An unexpected error occurred while running Chia GUI command: {e}", is_error=True)


def force_net_use_connection(unc_path, drive_letter=None, username=None, password=None):
    """
    Attempts to map a network drive or establish a connection to a UNC path using 'net use'.
    Does NOT attempt to delete existing mappings.
    """
    command = ["net", "use"]
    effective_path_for_check = unc_path

    if drive_letter:
        command.append(f"{drive_letter.upper()}:")
        command.append(unc_path)
        effective_path_for_check = f"{drive_letter.upper()}:\\"
        log_message = f"Attempting to map drive {drive_letter.upper()}: to '{unc_path}' using 'net use'..."
    else:
        command.append(unc_path)
        log_message = f"Attempting to force network connection for '{unc_path}' using 'net use'..."

    if username:
        command.append("/user:" + username)
        if password:
            command.append(password)
        log_message += " (with provided credentials)"
    else:
        log_message += " (without explicit credentials - relying on current user context)"

    log_and_update_gui(log_message)
    log_and_update_gui(f"Executing `{' '.join(command)}`") # Log exact command

    try:
        log_and_update_gui("Note: Running 'net use' with `shell=True`. If issues persist, verify network credentials and/or try running the script as Administrator.", is_error=False)
        result = subprocess.run(command, capture_output=True, text=True, check=False, shell=True)
        
        log_and_update_gui(f"Command Output (net use map/connect):\n{result.stdout.strip()}\n{result.stderr.strip()}") # Log exact output

        if result.returncode == 0:
            log_and_update_gui(f"'net use' command successful for '{unc_path}' (or '{drive_letter.upper()}:').")
            return True, effective_path_for_check
        else:
            error_message = f"'net use' command failed for '{unc_path}' (or '{drive_letter.upper()}:' if specified). Return code: {result.returncode}."
            if "System error 67" in result.stderr or "The network name cannot be found" in result.stderr:
                error_message += "\nNOTE: 'System error 67: The network name cannot be found' often indicates the server or share name is unresolvable or truly offline, or that authentication failed for the specified network path."
                error_message += "\nSUGGESTION: Verify the UNC path is correct and accessible. If it is, ensure you've stored the correct network share username/password in keyring, or try running this script as an Administrator."
            elif "System error 85" in result.stderr or "The local device name is already in use" in result.stderr:
                error_message += f"\nNOTE: Drive letter {drive_letter.upper()}: is already in use by another resource. Ensure it's free or delete existing mapping manually (not attempted by this script)."
            elif "System error 1219" in result.stderr or "Multiple connections to a server or shared resource by the same user" in result.stderr:
                 error_message += "\nNOTE: Multiple connections error. Try disconnecting existing connections or use a different drive letter or explicitly providing different credentials for each connection if necessary."
            elif "System error 1312" in result.stderr or "A specified logon session does not exist" in result.stderr:
                error_message += "\nNOTE: This typically means the username or password provided is incorrect, or the account lacks permission."
            
            log_and_update_gui(error_message, is_error=True)
            return False, effective_path_for_check
    except FileNotFoundError:
        log_and_update_gui("Error: 'net' command not found. Ensure it's in your system PATH.", is_error=True)
        return False, effective_path_for_check
    except Exception as e:
        log_and_update_gui(f"An error occurred while running 'net use' for '{unc_path}' (or '{drive_letter.upper()}:' if specified): {e}", is_error=True)
        return False, effective_path_for_check

def get_network_share_credentials():
    try:
        username = keyring.get_password(config["network_share_service_name"], "username")
        password = keyring.get_password(config["network_share_service_name"], "password")
        if username and password:
            log_and_update_gui(f"Network share credentials retrieved successfully from keyring service '{config['network_share_service_name']}'.")
            return username, password
        else:
            log_and_update_gui(f"Network share credentials not found or incomplete in keyring for service '{config['network_share_service_name']}'. Proceeding without explicit credentials for network drives. If network access fails, store credentials.", is_error=True)
            return None, None
    except Exception as e:
        log_and_update_gui(f"Error retrieving network share credentials from keyring: {e}. Proceeding without explicit credentials for network drives.", is_error=True)
        return None, None

def check_directory_accessibility(path, check_type_description="path"):
    """
    Checks if a directory is accessible and logs the attempt.
    """
    log_and_update_gui(f"Attempting directory check ('dir {path}' equivalent) for {check_type_description}...")
    if os.path.isdir(path):
        log_and_update_gui(f"Check Succeeded: '{path}' ({check_type_description}) is accessible.")
        return True
    else:
        log_and_update_gui(f"Check Failed: '{path}' ({check_type_description}) is NOT accessible.", is_error=True)
        return False

def count_plots(directories):
    total_plots = 0
    log_and_update_gui("Starting plot file scan...")
    
    net_user, net_pass = get_network_share_credentials()

    for directory_string in directories:
        parsed_dir = {}
        match = MAPPED_UNC_PATTERN.match(directory_string)

        if match:
            parsed_dir['map_letter'] = match.group('drive_letter').upper()
            parsed_dir['unc_path'] = match.group('unc_path')
            parsed_dir['use_path_for_scan'] = f"{parsed_dir['map_letter']}:\\"
            parsed_dir['is_network'] = True
            parsed_dir['is_explicit_map_requested'] = True
        elif directory_string.startswith("\\\\"):
            parsed_dir['unc_path'] = directory_string
            parsed_dir['use_path_for_scan'] = directory_string
            parsed_dir['is_network'] = True
            parsed_dir['is_explicit_map_requested'] = False
        else:
            parsed_dir['path'] = directory_string
            parsed_dir['use_path_for_scan'] = directory_string
            parsed_dir['is_network'] = False
            parsed_dir['is_explicit_map_requested'] = False

        dir_accessible = False
        final_scan_path = "" # The path that will actually be scanned

        if parsed_dir['is_network']:
            log_and_update_gui(f"Checking network path: '{directory_string}'.")

            for attempt_num in range(1, config["network_drive_retry_attempts"] + 1):
                log_and_update_gui(f"NETWORK ACCESS ATTEMPT {attempt_num}/{config['network_drive_retry_attempts']} for '{directory_string}'...")
                
                current_attempt_accessible = False

                if parsed_dir['is_explicit_map_requested']:
                    map_letter = parsed_dir['map_letter']
                    unc_path_for_map = parsed_dir['unc_path']
                    mapped_drive_path = f"{map_letter}:\\"

                    # 1. net use <letter> <path>
                    log_and_update_gui(f"Strategy 1 (Explicit Map - `net use {map_letter}: {unc_path_for_map}`):")
                    map_success, actual_path_from_net_use = force_net_use_connection(
                        unc_path_for_map, 
                        map_letter, 
                        username=net_user, 
                        password=net_pass
                    )
                    
                    if map_success:
                        # Check accessibility via the newly mapped drive or if already mapped
                        if check_directory_accessibility(actual_path_from_net_use, f"mapped drive {map_letter}:"):
                            current_attempt_accessible = True
                            final_scan_path = actual_path_from_net_use
                    
                    if not current_attempt_accessible:
                        # Fallback 1: dir <path> (direct UNC check)
                        log_and_update_gui(f"Strategy 2 (Direct UNC Path - `dir {unc_path_for_map}`):")
                        if check_directory_accessibility(unc_path_for_map, "direct UNC"):
                            current_attempt_accessible = True
                            final_scan_path = unc_path_for_map

                    if not current_attempt_accessible:
                        # Fallback 2: dir <letter> (even if net use M: \path failed, M: might exist from before)
                        log_and_update_gui(f"Strategy 3 (Direct Mapped Drive Letter - `dir {mapped_drive_path}`):")
                        if check_directory_accessibility(mapped_drive_path, f"existing mapped drive {map_letter}:"):
                            current_attempt_accessible = True
                            final_scan_path = mapped_drive_path

                else: # Not an explicit map request, just a direct UNC path like \\SERVER\SHARE
                    unc_path = directory_string

                    # 1. dir <path> (direct UNC check)
                    log_and_update_gui(f"Strategy 1 (Direct UNC Path - `dir {unc_path}`):")
                    if check_directory_accessibility(unc_path, "direct UNC"):
                        current_attempt_accessible = True
                        final_scan_path = unc_path
                    
                    if not current_attempt_accessible:
                        # Fallback: net use <path> (no letter) - for a nudge
                        log_and_update_gui(f"Strategy 2 (Generic Net Use - `net use {unc_path}` for a nudge):")
                        net_use_succeeded, _ = force_net_use_connection(unc_path, username=net_user, password=net_pass) 
                        if net_use_succeeded:
                            log_and_update_gui(f"Giving network path '{unc_path}' a moment after 'net use' (succeeded). Retrying accessibility check...")
                            time.sleep(config["network_drive_retry_delay_seconds"]) # Give it a moment after successful net use
                            if check_directory_accessibility(unc_path, "direct UNC after net use nudge"):
                                current_attempt_accessible = True
                                final_scan_path = unc_path
                            else:
                                log_and_update_gui(f"Network path '{unc_path}' still not accessible after 'net use' and wait. Moving to next main attempt.", is_error=True)
                        else:
                            log_and_update_gui(f"'net use' command failed for '{unc_path}'. Moving to next main attempt.", is_error=True)

                if current_attempt_accessible:
                    dir_accessible = True
                    log_and_update_gui(f"Network path '{directory_string}' is now accessible via '{final_scan_path}'.")
                    break # Exit the retry loop for this directory
                else:
                    if attempt_num < config['network_drive_retry_attempts']:
                        log_and_update_gui(f"All strategies in attempt {attempt_num} failed for '{directory_string}'. Retrying full cycle in {config['network_drive_retry_delay_seconds']} seconds...")
                        time.sleep(config["network_drive_retry_delay_seconds"])
                    else:
                        log_and_update_gui(f"All {config['network_drive_retry_attempts']} attempts failed for '{directory_string}'. Skipping this path.", is_error=True)
            
            if not dir_accessible:
                continue # Move to the next directory in plot_directories

        else: # Local drive
            final_scan_path = directory_string
            if not check_directory_accessibility(final_scan_path, "local path"):
                log_and_update_gui(f"Warning: Plot directory not found or not accessible: '{final_scan_path}'. Skipping.", is_error=True)
                continue
            dir_accessible = True

        if dir_accessible:
            try:
                for root_dir, _, files in os.walk(final_scan_path):
                    for file in files:
                        if PLOT_FILENAME_PATTERN.match(file):
                            total_plots += 1
                log_and_update_gui(f"Scanned directory '{directory_string}' (using '{final_scan_path}'). Current total: {total_plots} plots.")
            except Exception as e:
                log_and_update_gui(f"Error scanning directory '{final_scan_path}': {e}", is_error=True)
                
    log_and_update_gui(f"Plot scan complete. Total plots found: {total_plots}.")
    root.after(0, lambda: _update_plot_count_gui(total_plots))
    return total_plots


# --- Background Worker Thread ---
def chia_worker_thread():
    passphrase_file_path = None
    try:
        log_and_update_gui("Background worker thread started.")

        # Run plot count at startup
        count_plots(config["plot_directories"])

        passphrase = get_passphrase_from_keyring()
        if not passphrase:
            log_and_update_gui("Script cannot proceed without passphrase. Exiting worker thread.", is_error=True)
            root.after(0, on_closing) 
            return

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write(passphrase)
            passphrase_file_path = temp_file.name
        log_and_update_gui(f"Passphrase written to temporary file: '{passphrase_file_path}'.")

        log_and_update_gui("Starting Chia farmer using passphrase file...")
        run_chia_command(["--passphrase-file", passphrase_file_path, "start", "farmer"], detached_for_long_running_process=True)
        log_and_update_gui("Chia farmer start command issued. Waiting for services to become active.")

        if passphrase_file_path and os.path.exists(passphrase_file_path):
            try:
                os.remove(passphrase_file_path)
                log_and_update_gui(f"Removed temporary passphrase file: '{passphrase_file_path}' immediately after command call.")
                passphrase_file_path = None
            except Exception as e:
                log_and_update_gui(f"Error removing temporary passphrase file immediately: {e}", is_error=True)

        log_and_update_gui(f"Waiting 30 seconds for Chia services to initialize before first summary check.")
        time.sleep(30)

        farmer_summary_attempts = 0 # Counter for farm summary checks
        gui_launched_for_mismatch = False # Flag to ensure GUI is only launched once for mismatch

        while not stop_event.is_set():
            farmer_summary_attempts += 1 # Increment counter for each summary check attempt
            is_farming_active, summary_output = get_farm_summary() 
            current_plot_count = count_plots(config["plot_directories"])

            # Logic to launch Chia GUI if plot count doesn't match and farming is active
            if is_farming_active and current_plot_count != config["expected_plots"]:
                # Launch GUI only on the 3rd attempt and if not already launched
                if farmer_summary_attempts == 3 and not gui_launched_for_mismatch:
                    log_and_update_gui(f"Plot count mismatch detected ({current_plot_count} plots found, {config['expected_plots']} expected) while farming is active on attempt {farmer_summary_attempts}. Launching Chia GUI to potentially aid network reconnection.", is_error=True)
                    run_chia_command_gui(["start", "gui"]) # Call new function for GUI command
                    gui_launched_for_mismatch = True
                elif gui_launched_for_mismatch:
                    log_and_update_gui("Plot count mismatch persists, but Chia GUI was already launched for this issue. Not launching again.", is_error=False)
                else:
                    log_and_update_gui(f"Plot count mismatch detected, but it's only attempt {farmer_summary_attempts}. Waiting for the 3rd attempt before launching GUI.", is_error=False)
            else:
                # Reset the flag if the conditions are met (match found) or if farming is not active
                if gui_launched_for_mismatch and (is_farming_active and current_plot_count == config["expected_plots"]):
                    log_and_update_gui("Plot count now matches expected. Resetting GUI launch flag.", is_error=False)
                    gui_launched_for_mismatch = False
                elif gui_launched_for_mismatch and not is_farming_active:
                    log_and_update_gui("Farming is no longer active. Resetting GUI launch flag.", is_error=False)
                    gui_launched_for_mismatch = False
            
            if not stop_event.is_set():
                time.sleep(config["summary_check_interval_seconds"])
        
        log_and_update_gui("Worker thread received stop signal. Exiting.")

    except Exception as e:
        log_and_update_gui(f"An unhandled error occurred in worker thread: {e}", is_error=True)
    finally:
        # Final cleanup for passphrase file
        if passphrase_file_path and os.path.exists(passphrase_file_path):
            log_and_update_gui("Performing temporary file cleanup in worker thread (fallback).", is_summary=True)
            try:
                os.remove(passphrase_file_path)
                log_and_update_gui(f"Removed temporary passphrase file: '{passphrase_file_path}'.")
            except Exception as e:
                log_and_update_gui(f"Error removing temporary passphrase file (fallback): {e}", is_error=True)
        
        log_and_update_gui("Worker thread finished.", is_summary=True)


def get_farm_summary():
    """Fetches Chia farm summary and returns farming status and output."""
    try:
        log_and_update_gui("Fetching Chia farm summary...")
        stdout, stderr, exit_code = run_chia_command(["farm", "summary"], capture_output=True)

        is_farming = False
        summary_output = "No Chia farm summary available yet."

        if exit_code == 0:
            summary_output = stdout.strip()
            if "Farming status: Farming" in summary_output:
                is_farming = True
            log_and_update_gui("Chia farm summary retrieved successfully.", is_summary=True)
        else:
            summary_output = f"Failed to get Chia farm summary. Exit code: {exit_code}\nStderr:\n{stderr.strip()}"
            log_and_update_gui(summary_output, is_error=True, is_summary=True)
            is_farming = False # Ensure false if command fails
            
        root.after(0, lambda: _update_farm_status_indicator(is_farming))
        root.after(0, lambda: _update_summary_gui(summary_output))
        return is_farming, summary_output 
    except Exception as e:
        log_and_update_gui(f"Error retrieving farm summary: {e}", is_error=True, is_summary=True)
        root.after(0, lambda: _update_farm_status_indicator(False))
        root.after(0, lambda: _update_summary_gui(f"Error: Could not retrieve farm summary.\n{e}"))
        return False, f"Error: Could not retrieve farm summary.\n{e}"


# --- GUI Setup and Main Execution ---
def setup_gui():
    global root, status_var, summary_text_widget, rolling_log_widget, farm_status_label, last_check_timestamp_var, plot_count_var, expected_plots_entry, plot_match_indicator_label, plot_paths_text_widget
    
    load_config()

    root = tk.Tk()
    root.title("Chia Farm Status Monitor")
    root.geometry("800x800")

    _reconfigure_logging() 

    status_var = tk.StringVar()
    status_var.set("Initializing script...")
    status_label = tk.Label(root, textvariable=status_var, wraplength=780, justify="left", font=("Arial", 10), bd=1, relief=tk.SUNKEN, anchor=tk.W)
    status_label.pack(fill=tk.X, pady=(5, 0), padx=5)

    status_indicator_frame = tk.Frame(root, bd=2, relief=tk.GROOVE)
    status_indicator_frame.pack(pady=5, padx=10, fill=tk.X)

    farm_status_label = tk.Label(status_indicator_frame, text="Farming: UNKNOWN", font=("Arial", 12, "bold"), fg="white", bg="gray", padx=10, pady=5)
    farm_status_label.pack(side=tk.LEFT, padx=5, pady=5)

    last_check_timestamp_var = tk.StringVar()
    last_check_timestamp_var.set("Last Check: N/A")
    last_check_label = tk.Label(status_indicator_frame, textvariable=last_check_timestamp_var, font=("Arial", 10), padx=5, pady=5)
    last_check_label.pack(side=tk.RIGHT, padx=5, pady=5)

    plot_paths_frame = tk.LabelFrame(root, text=f"Plot Directories (one path per line, 'M:\\\\server\\share' for explicit mapping. Retries: {config['network_drive_retry_attempts']}x{config['network_drive_retry_delay_seconds']}s)", padx=5, pady=5)
    plot_paths_frame.pack(padx=10, pady=5, fill=tk.X)
    plot_paths_text_widget = scrolledtext.ScrolledText(plot_paths_frame, wrap=tk.WORD, height=5, font=("Courier New", 9))
    plot_paths_text_widget.pack(fill=tk.X, expand=True)
    plot_paths_text_widget.insert(tk.END, "\n".join(config["plot_directories"]))

    plot_count_frame = tk.Frame(root, bd=2, relief=tk.GROOVE)
    plot_count_frame.pack(pady=5, padx=10, fill=tk.X)

    tk.Label(plot_count_frame, text="Expected Plots:", font=("Arial", 10)).pack(side=tk.LEFT, padx=(5,0), pady=5)
    expected_plots_entry = tk.Entry(plot_count_frame, width=10, font=("Arial", 10))
    expected_plots_entry.pack(side=tk.LEFT, padx=5, pady=5)
    expected_plots_entry.insert(0, str(config["expected_plots"]))

    plot_count_var = tk.StringVar()
    plot_count_var.set("Plots Found: Scanning...")
    tk.Label(plot_count_frame, textvariable=plot_count_var, font=("Arial", 11), anchor=tk.W).pack(side=tk.LEFT, padx=5, pady=5, expand=True)

    plot_match_indicator_label = tk.Label(plot_count_frame, text="Match: UNKNOWN", font=("Arial", 10, "bold"), fg="white", bg="gray", padx=5, pady=2)
    plot_match_indicator_label.pack(side=tk.RIGHT, padx=5, pady=5)

    summary_frame = tk.LabelFrame(root, text="Farm Summary", padx=5, pady=5)
    summary_frame.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
    summary_text_widget = scrolledtext.ScrolledText(summary_frame, wrap=tk.WORD, width=90, height=10, font=("Courier New", 9))
    summary_text_widget.pack(fill=tk.BOTH, expand=True)
    summary_text_widget.insert(tk.END, "Waiting for Chia farm summary...\n")
    summary_text_widget.config(state=tk.DISABLED)

    log_frame = tk.LabelFrame(root, text="Script Log", padx=5, pady=5)
    log_frame.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
    rolling_log_widget = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=90, height=10, font=("Courier New", 8), bg="black", fg="white")
    rolling_log_widget.pack(fill=tk.BOTH, expand=True)
    rolling_log_widget.config(state=tk.DISABLED)

    quit_button = tk.Button(root, text="Quit Monitor & Stop Chia Farmer", command=on_closing)
    quit_button.pack(pady=10)

    worker_thread = threading.Thread(
        target=chia_worker_thread,
        daemon=True
    )
    worker_thread.start()

    root.after(100, _update_rolling_log_gui)

    root.protocol("WM_DELETE_WINDOW", on_closing)

    root.mainloop()

def on_closing():
    logger.info("GUI close/quit button pressed. Initiating graceful shutdown of Chia services and saving configuration.")
    stop_event.set()

    save_config_on_exit()

    shutdown_thread = threading.Thread(target=perform_cleanup_and_exit)
    shutdown_thread.start()

def perform_cleanup_and_exit():
    try:
        log_and_update_gui("Attempting to stop Chia farmer services...")
        stdout, stderr, exit_code = run_chia_command(["stop", "farmer"], capture_output=True)
        
        if exit_code == 0:
            log_and_update_gui(f"Chia farmer services stopped successfully.\nStdout:\n{stdout.strip()}\nStderr:\n{stderr.strip()}")
        else:
            log_and_update_gui(f"Failed to stop Chia farmer services. Exit code: {exit_code}\nStdout:\n{stdout.strip()}\nStderr:\n{stderr.strip()}", is_error=True)

        log_and_update_gui("Waiting 10 seconds after stopping Chia services before final exit.")
        time.sleep(10)

    except Exception as e:
        log_and_update_gui(f"An error occurred during shutdown process: {e}", is_error=True)
    finally:
        log_and_update_gui("Final cleanup complete. Exiting application.", is_summary=True)
        if root:
            root.after(0, root.destroy)
        logger.info("GUI destroyed. Script exiting completely.")
        time.sleep(0.1)
        sys.exit(0)

if __name__ == "__main__":
    try:
        setup_gui()
    except Exception as e:
        print(f"FATAL ERROR: Script terminated unexpectedly during startup.", file=sys.stderr)
        print(f"Exception Type: {type(e).__name__}", file=sys.stderr)
        print(f"Exception Message: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
