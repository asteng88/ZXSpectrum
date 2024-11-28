import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import os
import shutil
import pandas as pd
from pathlib import Path
from subprocess import Popen
import time
from concurrent.futures import ThreadPoolExecutor
import threading
import queue
from threading import Thread
import zipfile
import tempfile
import shutil

class FileMoverApp:
    def __init__(self, root):
        # Get the directory where the script is located
        self.program_dir = os.path.dirname(os.path.abspath(__file__))
        self.root = root
        self.root.title("File-o-tron")
        self.root.geometry("700x500")
        
        # Constants
        self.MAX_RETRIES = 3
        self.RETRY_DELAY = 1  # seconds
        self.CHUNK_SIZE = 1000  # files per chunk
        
        # Variables
        self.source_path = tk.StringVar()
        self.dest_path = tk.StringVar()
        self.copy_duplicates = tk.BooleanVar()
        self.copy_files = tk.BooleanVar()
        self.current_operation = tk.StringVar()
        self.current_operation.set("Ready")
        self.organize_by_type = tk.BooleanVar()
        self.filter_by_type = tk.BooleanVar()
        self.selected_file_type = tk.StringVar()
        self.file_types = ['All Files']
        self.unzip_first = tk.BooleanVar()
        self.temp_dirs = []  # Store temp directories for zip cleanup
        self.status_label = None
        self.stop_requested = False
        self.start_button = None  # Add this line
        self.inventory_button = None  # Add this line
        self.open_folder_button = None
        self.unzip_button = None
        
        # Add source path trace
        self.source_path.trace_add('write', self.update_button_states)
        
        # GUI Elements
        self.create_widgets()
        
        self._status_buffer = []
        self._max_status_lines = 100
        self.total_files = 0
        self.queue = queue.Queue()
        self.processing = False
        self._pending_files = 0
    
    def create_widgets(self):
        # Configure column weights
        self.root.grid_columnconfigure(1, weight=1)
        
        # Source folder - make entry expand and fill
        ttk.Label(self.root, text="Source Folder:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
        ttk.Entry(self.root, textvariable=self.source_path, width=70).grid(
            row=0, column=1, padx=5, pady=5, sticky='ew'
        )
        ttk.Button(self.root, text="Browse", command=self.browse_source).grid(
            row=0, column=2, padx=5, pady=5, sticky='w'
        )
        
        # Destination folder - make entry expand and fill
        ttk.Label(self.root, text="Destination Folder:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
        ttk.Entry(self.root, textvariable=self.dest_path, width=70).grid(
            row=1, column=1, padx=5, pady=5, sticky='ew'
        )
        ttk.Button(self.root, text="Browse", command=self.browse_dest).grid(
            row=1, column=2, padx=5, pady=5, sticky='w'
        )
        
        # Duplicate checkbox
        ttk.Checkbutton(self.root, text="Copy/Move Duplicate Files", variable=self.copy_duplicates).grid(row=3, column=1, pady=5)
        
        # Copy files checkbox
        ttk.Checkbutton(self.root, text="Copy Files (Move Files if unchecked)", variable=self.copy_files).grid(row=2, column=1, pady=5)
        
        # Organize by type checkbox
        ttk.Checkbutton(self.root, text="Organize into Folders by File Type", variable=self.organize_by_type).grid(row=4, column=1, pady=5)
        
        # Add unzip checkbox after organize by type
        ttk.Checkbutton(self.root, text="Unzip Archives Before Processing", 
                       variable=self.unzip_first).grid(row=4, column=1, pady=5)

        # File type filter frame
        filter_frame = ttk.Frame(self.root)
        filter_frame.grid(row=5, column=1, pady=5)
        
        ttk.Checkbutton(filter_frame, text="Filter by File Type", 
                       variable=self.filter_by_type).pack(side=tk.LEFT, padx=5)
        
        self.file_type_combo = ttk.Combobox(filter_frame, 
                                           textvariable=self.selected_file_type,
                                           state='readonly',
                                           width=20)
        self.file_type_combo['values'] = self.file_types
        self.file_type_combo.set('All Files')
        self.file_type_combo.pack(side=tk.LEFT, padx=5)

        # Button row
        button_frame = ttk.Frame(self.root)
        button_frame.grid(row=6, column=0, columnspan=3, pady=20)
        
        style = ttk.Style()
        style.configure('Green.TButton', background='green', foreground='green')
        style.configure('Red.TButton', background='red', foreground='red')
        style.configure('Highlight.TButton', background='yellow', foreground='black')
        
        self.start_button = ttk.Button(button_frame, text="START", command=self.move_files)
        self.start_button.configure(style='Green.TButton')
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="STOP", command=self.stop_process, style='Red.TButton')
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.stop_button['state'] = 'disabled'
        
        ttk.Button(button_frame, text="Clear Inputs", command=self.clear_inputs).pack(side=tk.LEFT, padx=5)
        
        self.unzip_button = ttk.Button(button_frame, text="Unzip Source", command=self.unzip_source)
        self.unzip_button.pack(side=tk.LEFT, padx=5)
        
        self.inventory_button = ttk.Button(button_frame, text="Create Inventory List", command=self.create_inventory)
        self.inventory_button.pack(side=tk.LEFT, padx=5)
        
        self.open_folder_button = ttk.Button(button_frame, text="Open Folder", command=self.view_destination)
        self.open_folder_button.pack(side=tk.LEFT, padx=5)
        
        # Update button states initially
        self.update_button_states()
        
        # Current operation label (modified)
        ttk.Label(self.root, text="Status:").grid(row=7, column=0, padx=5, pady=5, sticky='e')
        self.status_label = ttk.Label(self.root, textvariable=self.current_operation, width=50)
        self.status_label.grid(row=7, column=1, padx=5, pady=5, sticky='w')
        
        # Status box
        self.status_text = tk.Text(self.root, height=10, width=60)
        self.status_text.grid(row=8, column=0, columnspan=3, padx=5, pady=5)
        
        # Progress bar
        progress_frame = ttk.Frame(self.root)
        progress_frame.grid(row=9, column=0, columnspan=3)
        progress_frame.grid_columnconfigure(0, weight=1)
        progress_frame.grid_columnconfigure(2, weight=1)
        
        ttk.Label(progress_frame, text="Progress:").grid(row=0, column=0, sticky='e', padx=(0,5))
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            orient='horizontal',
            mode='determinate',
            length=350
        )
        self.progress_bar.grid(row=0, column=1, pady=5)
        
        # Add Quit button in bottom right
        ttk.Button(self.root, text="Quit", command=self.root.quit).grid(
            row=9, column=2, padx=5, pady=5, sticky='e'
        )
    
    def browse_source(self):
        """Simple folder browser for source"""
        folder = filedialog.askdirectory()
        if folder:
            self.root.config(cursor="wait")  # Change to wait cursor
            self.source_path.set(folder)
            self.status_text.delete(1.0, tk.END)
            self.current_operation.set("Scanning source folder...")
            self.update_status(f"Selected source folder: {folder}")
            self.update_status("Scanning for file types, please wait...")
            self.root.update_idletasks()  # Force cursor update
            # Use after to allow GUI to update before scanning
            self.root.after(100, lambda: self._scan_source(folder))

    def _scan_source(self, folder):
        """Helper method to scan source and reset cursor"""
        try:
            self.update_file_types(folder)
        finally:
            self.root.config(cursor="")  # Reset cursor to default
            self.root.update_idletasks()

    def browse_dest(self):
        """Simple folder browser for destination"""
        folder = filedialog.askdirectory()
        if folder:
            self.root.config(cursor="wait")
            self.dest_path.set(folder)
            self.update_button_states()
            self.root.update_idletasks()
            self.root.after(100, lambda: self.root.config(cursor=""))  # Reset cursor after brief delay
    
    def update_file_types(self, directory):
        """Scan directory for unique file extensions"""
        file_types = set(['All Files'])
        total_files = 0
        try:
            for root, _, files in os.walk(directory):
                self.current_operation.set(f"Scanning: {os.path.basename(root)}")
                self.update_status(f"Scanning folder: {root}")
                for file in files:
                    total_files += 1
                    ext = os.path.splitext(file)[1].lower()
                    if ext:
                        file_types.add(ext[1:])  # Remove the dot
                    if total_files % 1000 == 0:  # Update every 1000 files
                        self.update_status(f"Scanned {total_files} files...")
            
            self.file_types = sorted(list(file_types))
            self.file_type_combo['values'] = self.file_types
            self.selected_file_type.set('All Files')
            
            # Final status updates
            self.current_operation.set("Scan complete")
            self.update_status(f"Total files found: {total_files}")
            self.update_status(f"File types found: {', '.join(self.file_types[1:])}")
            
        except Exception as e:
            self.current_operation.set("Scan failed")
            self.update_status(f"Error scanning file types: {str(e)}")
    
    def update_status(self, message):
        """Immediately update status text"""
        self.status_text.insert(tk.END, f"{message}\n")
        self.status_text.see(tk.END)
        self.root.update_idletasks()
    
    def count_files(self, directory):
        """Fast file counting using scandir"""
        total = 0
        try:
            with os.scandir(directory) as it:
                for entry in it:
                    if entry.is_file():
                        total += 1
                    elif entry.is_dir():
                        total += self.count_files(entry.path)
        except PermissionError as e:
            self.update_status(f"Permission denied: {directory}")
        except Exception as e:
            self.update_status(f"Error scanning {directory}: {str(e)}")
        return total

    def safe_file_operation(self, operation, src, dst, retry_count=0):
        """Perform file operation with retry logic"""
        try:
            operation(src, dst)
            return True
        except (PermissionError, OSError) as e:
            if retry_count < self.MAX_RETRIES:
                self.update_status(f"Retrying {src} after error: {str(e)}")
                time.sleep(self.RETRY_DELAY)
                return self.safe_file_operation(operation, src, dst, retry_count + 1)
            else:
                self.update_status(f"Failed after {self.MAX_RETRIES} retries: {src}")
                return False

    def process_file(self, src_path, dst_path):
        """Process a single file with optimal copying strategy"""
        try:
            # Handle zip files if unzip option is enabled
            if self.unzip_first.get() and src_path.lower().endswith('.zip'):
                return self.process_zip_file(src_path, dst_path)

            # Check file type filter
            if self.filter_by_type.get() and self.selected_file_type.get() != 'All Files':
                file_ext = os.path.splitext(src_path)[1][1:].lower()
                if file_ext != self.selected_file_type.get().lower():
                    return None

            # Modify destination path when organizing by type
            if self.organize_by_type.get():
                file_ext = os.path.splitext(src_path)[1][1:].lower() or 'no_extension'
                filename = os.path.basename(src_path)
                dst_path = os.path.join(os.path.dirname(dst_path), file_ext, filename)
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)

            if os.path.exists(dst_path):
                if self.copy_duplicates.get():
                    base, ext = os.path.splitext(dst_path)
                    i = 1
                    while os.path.exists(f"{base}_{i}{ext}"):
                        i += 1
                    dst_path = f"{base}_{i}{ext}"
                else:
                    self.update_status(f"Skipping duplicate: {os.path.basename(src_path)}")
                    return None
            
            operation = shutil.copy2 if self.copy_files.get() else shutil.move
            if self.safe_file_operation(operation, src_path, dst_path):
                self.update_status(f"Successfully processed: {os.path.basename(src_path)}")
                return {
                    'Filename': os.path.basename(src_path),
                    'Source Path': src_path,
                    'Destination Path': dst_path
                }
        except Exception as e:
            self.update_status(f"Error processing {src_path}: {str(e)}")
        return None

    def process_zip_file(self, zip_path, dst_base):
        """Extract and process files from zip archive"""
        try:
            # Create temp directory for extraction
            temp_dir = tempfile.mkdtemp()
            self.temp_dirs.append(temp_dir)
            
            self.update_status(f"Extracting: {os.path.basename(zip_path)}")
            
            # Extract zip
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Process extracted files
            processed_files = []
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    src_file = os.path.join(root, file)
                    # Calculate relative path from temp dir
                    rel_path = os.path.relpath(src_file, temp_dir)
                    
                    if self.organize_by_type.get():
                        file_ext = os.path.splitext(file)[1][1:].lower() or 'no_extension'
                        dst_file = os.path.join(dst_base, file_ext, file)
                    else:
                        dst_file = os.path.join(dst_base, rel_path)
                    
                    # Create destination directory
                    os.makedirs(os.path.dirname(dst_file), exist_ok=True)
                    
                    # Copy file
                    if self.safe_file_operation(shutil.copy2, src_file, dst_file):
                        processed_files.append({
                            'Filename': file,
                            'Source Path': f"{zip_path}:/{rel_path}",
                            'Destination Path': dst_file
                        })
            
            return processed_files
            
        except Exception as e:
            self.update_status(f"Error processing zip {zip_path}: {str(e)}")
            return None
        finally:
            # Cleanup temp directory
            try:
                shutil.rmtree(temp_dir)
                self.temp_dirs.remove(temp_dir)
            except Exception:
                pass

    def count_files_threaded(self):
        """Count files in a separate thread"""
        self.counting_complete = False
        self.total_files = 0
        
        def count():
            self.total_files = self.count_files(self.source_path.get())
            self.counting_complete = True
            self.root.event_generate('<<CountingComplete>>')
        
        self.current_operation.set("Scanning files...")
        self.update_status("Scanning source directory...")
        
        counting_thread = threading.Thread(target=count)
        counting_thread.daemon = True
        counting_thread.start()

    def safe_update_progress(self, value, operation_text):
        """Thread-safe progress update"""
        def update():
            self.progress_bar['value'] = value
            self.current_operation.set(operation_text)
            # Force label to update its geometry
            self.status_label.update_idletasks()
        self.root.after(0, update)

    def process_queue(self):
        """Process messages from the queue"""
        while True:
            try:
                msg = self.queue.get_nowait()
                if msg['type'] == 'progress':
                    self.progress_bar['value'] = msg['value']
                    self.current_operation.set(msg['text'])
                elif msg['type'] == 'status':
                    self.update_status(msg['text'])
                elif msg['type'] == 'complete':
                    self.processing = False
                    self.current_operation.set(msg['text'])
                self.queue.task_done()
            except queue.Empty:
                break
        
        if self.processing:
            self.root.after(100, self.process_queue)

    def move_files(self):
        if self.processing:
            return
            
        source = self.source_path.get()
        dest = self.dest_path.get()
        
        if not source or not dest:
            messagebox.showerror("Error", "Please select both source and destination folders")
            return

        self.processing = True
        self.stop_requested = False
        self.stop_button['state'] = 'normal'
        self._status_buffer = []
        self.status_text.delete(1.0, tk.END)
        self.progress_bar['value'] = 0
        self.current_operation.set("Starting...")
        
        # Start processing files
        thread = Thread(target=self.process_files_thread, args=(source, dest))
        thread.daemon = True
        thread.start()
        
        # Start queue processing
        self.root.after(100, self.process_queue)

    def process_files_thread(self, source, dest):
        """Process files in separate thread"""
        try:
            # Count files first
            self.queue.put({'type': 'status', 'text': 'Starting file scan...'})
            self.update_status("Scanning source directory for files...")
            total_files = self.count_files(source)
            
            if total_files == 0:
                self.update_status('No files found to process')
                self.queue.put({'type': 'complete', 'text': 'No files to process'})
                return

            self.update_status(f"Found {total_files} files to process")
            moved_files = []
            processed_files = 0
            
            for root, dirs, files in os.walk(source):
                if self.stop_requested:
                    self.update_status("Operation stopped by user")
                    self.queue.put({'type': 'complete', 'text': 'Operation stopped'})
                    break
                    
                self.update_status(f"Scanning folder: {root}")
                chunk = []
                for file in files:
                    src_path = os.path.join(root, file)
                    file_ext = os.path.splitext(file)[1][1:].lower() or 'no_extension'
                    
                    # Check file type filter first
                    if self.filter_by_type.get() and self.selected_file_type.get() != 'All Files':
                        if file_ext.lower() != self.selected_file_type.get().lower():
                            continue
                    
                    # Create destination path - always in extension folder
                    dst_path = os.path.join(dest, file_ext, os.path.basename(file))
                    
                    # Create the extension folder if it doesn't exist
                    ext_folder = os.path.join(dest, file_ext)
                    os.makedirs(ext_folder, exist_ok=True)
                    
                    chunk.append((src_path, dst_path))
                    
                    if len(chunk) >= self.CHUNK_SIZE:
                        self.update_status(f"Processing batch of {self.CHUNK_SIZE} files...")
                        processed_files = self._process_chunk(chunk, moved_files, processed_files, total_files)
                        chunk = []

                # Process remaining files in chunk
                if chunk:
                    self.update_status(f"Processing remaining {len(chunk)} files...")
                    processed_files = self._process_chunk(chunk, moved_files, processed_files, total_files)

            # Flatten zip results into moved_files list
            processed_files = []
            for result in moved_files:
                if isinstance(result, list):  # Results from zip file
                    processed_files.extend(result)
                else:
                    processed_files.append(result)
            moved_files = processed_files

            # Create report
            if moved_files:
                self.update_status("Creating report file...")
                df = pd.DataFrame(moved_files)
                report_path = os.path.join(dest, 'moved_files_report.xlsx')
                df.to_excel(report_path, index=False)
                self.update_status(f"Report saved to: {report_path}")

            operation = "Copied" if self.copy_files.get() else "Moved"
            final_message = f"Complete! {operation} {len(moved_files)} files"
            self.update_status(final_message)
            self.queue.put({'type': 'complete', 'text': final_message})

        except Exception as e:
            error_message = f"Error: {str(e)}"
            self.update_status(error_message)
            self.queue.put({'type': 'status', 'text': error_message})
            self.queue.put({'type': 'complete', 'text': "Failed"})
        finally:
            self.processing = False
            self.stop_button['state'] = 'disabled'
            self.stop_requested = False

    def _process_chunk(self, chunk, moved_files, processed_files, total_files):
        """Helper method to process a chunk of files"""
        with ThreadPoolExecutor() as executor:
            futures = []
            for file_tuple in chunk:
                if self.stop_requested:
                    break
                futures.append(executor.submit(self.process_file, *file_tuple))
                
            for future in futures:
                if self.stop_requested:
                    break
                result = future.result()
                if result:
                    moved_files.append(result)
                processed_files += 1
                self.queue.put({
                    'type': 'progress',
                    'value': (processed_files / total_files) * 100,
                    'text': f'Processing ({processed_files}/{total_files})'
                })
        return processed_files

    def stop_process(self):
        """Handles stop button press"""
        if self.processing:
            self.stop_requested = True
            self.current_operation.set("Stopping... Please wait...")
            self.update_status("Stop requested - waiting for current operations to complete...")

    def view_destination(self):
        dest = self.dest_path.get()
        if not dest:
            messagebox.showerror("Error", "No destination folder selected")
            return
        if not os.path.exists(dest):
            messagebox.showerror("Error", "Destination folder does not exist")
            return
            
        try:
            if os.name == 'nt':  # Windows
                os.startfile(dest)  # More reliable than explorer for Windows
            elif os.name == 'posix':  # macOS and Linux
                Popen(['open', dest] if os.sys.platform == 'darwin' else ['xdg-open', dest])
            self.update_status(f"Opening folder: {dest}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open folder: {str(e)}")
    
    def create_inventory(self):
        dest = self.dest_path.get()
        if not dest:
            messagebox.showerror("Error", "No destination folder selected")
            return
        if not os.path.exists(dest):
            messagebox.showerror("Error", "Destination folder does not exist")
            return
        
        try:
            self.update_status("Creating inventory list...")
            inventory = []
            for root, dirs, files in os.walk(dest):
                for file in files:
                    inventory.append(os.path.relpath(os.path.join(root, file), dest))
            
            inventory_path = os.path.join(dest, 'inventory.txt')
            with open(inventory_path, 'w') as f:
                f.write('\n'.join(inventory))
            
            self.update_status(f"Inventory list saved to: {inventory_path}")
        except Exception as e:
            self.update_status(f"Error creating inventory list: {str(e)}")
    
    def clear_inputs(self):
        self.source_path.set('')
        self.dest_path.set('')
        self.copy_duplicates.set(False)
        self.copy_files.set(False)
        self.current_operation.set('Ready')
        self.status_text.delete(1.0, tk.END)
        self.progress_bar['value'] = 0
        self.queue = queue.Queue()
        self.processing = False
        self.total_files = 0
        self.counting_complete = False
        self._pending_files = 0
        self.filter_by_type.set(False)
        self.selected_file_type.set('All Files')
        self.file_types = ['All Files']
        self.file_type_combo['values'] = self.file_types
        self.organize_by_type.set(False)
        self.unzip_first.set(False)
        # Cleanup any temporary directories
        for temp_dir in self.temp_dirs[:]:
            try:
                shutil.rmtree(temp_dir)
                self.temp_dirs.remove(temp_dir)
            except Exception:
                pass
        self.update_button_states()

    def update_button_states(self, *args):
        """Update button states based on destination and source paths"""
        has_dest = bool(self.dest_path.get())
        has_source = bool(self.source_path.get())
        
        # Update button states
        self.start_button['state'] = 'normal' if has_dest else 'disabled'
        self.inventory_button['state'] = 'normal' if has_dest else 'disabled'
        self.open_folder_button['state'] = 'normal' if has_dest else 'disabled'
        self.unzip_button['state'] = 'normal' if has_source else 'disabled'
        
        # Change unzip button style based on destination state
        if not has_dest and has_source:
            self.unzip_button.configure(style='Highlight.TButton')
        else:
            self.unzip_button.configure(style='TButton')

    def unzip_source(self):
        """Unzip all files in source folder without moving them"""
        source = self.source_path.get()
        if not source:
            messagebox.showerror("Error", "Please select source folder")
            return
            
        try:
            self.processing = True
            self.stop_requested = False
            self.stop_button['state'] = 'normal'
            self.current_operation.set("Scanning for zip files...")
            self.status_text.delete(1.0, tk.END)  # Clear status box
            
            # Count zip files
            zip_files = []
            for root, _, files in os.walk(source):
                for file in files:
                    if file.lower().endswith('.zip'):
                        zip_files.append(os.path.join(root, file))
            
            if not zip_files:
                messagebox.showinfo("Info", "No zip files found in source folder")
                return
            
            total_zips = len(zip_files)
            self.update_status(f"Found {total_zips} zip files to extract")
            self.progress_bar['value'] = 0
                
            for index, zip_path in enumerate(zip_files, 1):
                if self.stop_requested:
                    break
                    
                try:
                    filename = os.path.basename(zip_path)
                    self.current_operation.set(f"Extracting {index}/{total_zips}: {filename}")
                    self.update_status(f"Processing: {zip_path}")
                    
                    extract_path = os.path.splitext(zip_path)[0]
                    os.makedirs(extract_path, exist_ok=True)
                    
                    # Count files in zip for progress
                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        file_list = zip_ref.namelist()
                        total_files = len(file_list)
                        self.update_status(f"Archive contains {total_files} files")
                        
                        # Extract with progress updates
                        for i, member in enumerate(file_list, 1):
                            if self.stop_requested:
                                break
                            zip_ref.extract(member, extract_path)
                            if i % 10 == 0 or i == total_files:  # Update every 10 files or on last file
                                self.update_status(f"Extracted {i}/{total_files} files from {filename}")
                    
                    self.update_status(f"Completed: {filename}")
                    # Update overall progress
                    self.progress_bar['value'] = (index / total_zips) * 100
                    
                except Exception as e:
                    self.update_status(f"Error extracting {filename}: {str(e)}")
            
            if not self.stop_requested:
                self.update_status("Scanning for new file types...")
                self.update_file_types(source)
                self.current_operation.set("Extraction complete")
            else:
                self.current_operation.set("Extraction stopped")
            
        except Exception as e:
            self.update_status(f"Error during unzip: {str(e)}")
        finally:
            self.processing = False
            self.stop_button['state'] = 'disabled'
            self.stop_requested = False

if __name__ == "__main__":
    root = tk.Tk()
    # Add icon to the window using absolute path
    try:
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "File-O-Tron.png")
        icon = tk.PhotoImage(file=icon_path)
        root.iconphoto(True, icon)
    except Exception as e:
        print(f"Could not load icon from {icon_path}: {e}")
    app = FileMoverApp(root)
    root.mainloop()