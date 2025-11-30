"""
File Monitor View - Monitor file system changes
"""
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable
import os
import logging

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Static, DataTable, Button, Input, Label
from textual.reactive import reactive
from textual import on, work
from textual.timer import Timer

from HIDS.sysmon.file_watch import FileWatcher
from HIDS.database.database import Database
# from HIDS.database.database import Database


class DirectoryListPanel(Vertical):
    """Left panel showing list of monitored directories"""
    
    selected_directory = reactive("")
    monitored_dirs = reactive([])
    
    def compose(self) -> ComposeResult:
        """Compose the directory list panel"""
        yield Label("[bold]Monitored Directories[/bold]", classes="panel-title")
        yield Static(id="directory-list")
        yield Label("\n[dim]Click a directory to view details[/dim]")

    def watch_monitored_dirs(self, new_dirs: list[str]) -> None:
        """Update the directory list display"""
        dir_list_widget = self.query_one("#directory-list", Static)
        if new_dirs:
            dir_list_widget.update("\n".join([f"[green]●[/green] {d}" for d in new_dirs]))
        else:
            dir_list_widget.update("No directories being monitored.")


class DirectoryControlPanel(Horizontal):
    """Control panel for adding/removing directories"""
    
    def compose(self) -> ComposeResult:
        """Compose the control panel"""
        yield Input(
            placeholder="Enter directory path to monitor...",
            id="directory-input",
            classes="control-input"
        )
        yield Button("Add Directory", variant="success", id="add-dir-btn")
        yield Button("Remove Selected", variant="error", id="remove-dir-btn")
        yield Button("Pause All", variant="warning", id="pause-btn")


class FileMonitorTable(DataTable):
    """DataTable showing monitored directories and their status"""
    
    COLUMN_KEYS = {
        "path": "Directory Path",
        "status": "Status",
        "last_check": "Last Check",
        "files_modified": "Files Modified",
        "files_added": "Files Added",
        "files_deleted": "Files Deleted",
        "actions": "Actions"
    }
    
    def on_mount(self) -> None:
        """Initialize the file monitor table"""
        # Add columns
        for key, label in self.COLUMN_KEYS.items():
            if key == "path":
                self.add_column(label, width=40, key=key)
            elif key == "status":
                self.add_column(label, width=15, key=key)
            elif key == "last_check":
                self.add_column(label, width=20, key=key)
            elif key == "actions":
                self.add_column(label, width=10, key=key)
            else:
                self.add_column(label, width=15, key=key)
        
        # Table configuration
        self.cursor_type = "row"
        self.zebra_stripes = True
        self.show_cursor = True
        
        # No sample data initially, will be added by FileWatcher
        self.clear()
    
    def add_monitored_directory(self, path: str) -> None:
        """Add a new directory to monitor"""
        row_key = f"dir_{hash(path)}"
        
        self.add_row(
            path,
            Text("✓ Active", style="green bold"),
            datetime.now().strftime("%H:%M:%S"),
            "0",
            "0",
            "0",
            "📊",
            key=row_key
        )
    
    def update_directory_status(
        self,
        row_key: str,
        status: str,
        modified: int = 0,
        added: int = 0,
        deleted: int = 0
    ) -> None:
        """Update the status of a monitored directory"""
        status_map = {
            "active": Text("✓ Active", style="green bold"),
            "modified": Text("⚠ Modified", style="yellow bold"),
            "error": Text("✗ Error", style="red bold"),
            "paused": Text("⏸ Paused", style="blue bold"),
        }
        
        try:
            self.update_cell(row_key, "status", status_map.get(status, status))
            self.update_cell(row_key, "last_check", datetime.now().strftime("%H:%M:%S"))
            self.update_cell(row_key, "files_modified", str(modified))
            self.update_cell(row_key, "files_added", str(added))
            self.update_cell(row_key, "files_deleted", str(deleted))
        except Exception as e:
            # Handle update errors gracefully
            pass


class FileDetailsPanel(Vertical):
    """Right panel showing details of selected directory"""
    
    selected_path = reactive("")
    
    def compose(self) -> ComposeResult:
        """Compose the details panel"""
        yield Label("[bold]Directory Details[/bold]", classes="panel-title")
        yield Static(
            "Select a directory from the table to view details...",
            id="details-content",
            classes="details-display"
        )
    
    def update_details(self, path: str, details: str) -> None:
        """Update the details display"""
        self.selected_path = path
        details_widget = self.query_one("#details-content", Static)
        details_widget.update(details)


class FileMonitorView(Vertical):
    """File Monitor view with split-pane layout"""

    file_watcher: FileWatcher = None
    db_path: str = None
    logger: logging.Logger = None
    event_counts: dict = {}  # Track cumulative counts per directory
    pending_updates: dict = {}  # Batch pending UI updates
    update_timer: Optional[Timer] = None
    
    def __init__(self, *args, **kwargs):
        """Initialize the FileMonitorView with database path."""
        super().__init__(*args, **kwargs)
        # Set database path relative to UI directory
        ui_dir = Path(__file__).parent.parent
        self.db_path = str(ui_dir / "HIDS.db")
        
        # Set up logging
        self.logger = logging.getLogger('FileMonitor')
        self.logger.setLevel(logging.INFO)
        
        # Create file handler if not already exists
        if not self.logger.handlers:
            log_dir = ui_dir / "app_log"
            log_dir.mkdir(exist_ok=True)
            log_file = log_dir / "file_monitor.log"
            
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.INFO)
            
            # Create formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def on_mount(self) -> None:
        """Called when the widget is mounted."""
        self.file_watcher = FileWatcher(callback=self.handle_file_event)
        # Clear sample data from DirectoryListPanel and FileMonitorTable
        self.query_one("#directory-list", Static).update("No directories being monitored.")
        self.query_one("#file-monitor-table", FileMonitorTable).clear()
        
        # Start batch update timer (process updates every 2 seconds)
        self.update_timer = self.set_interval(2.0, self._process_pending_updates)
        
        # Load saved directories from database
        self._load_saved_directories()
    
    def _load_saved_directories(self) -> None:
        """Load previously monitored directories from the database on startup."""
        try:
            # Change to the database directory to ensure proper connection
            original_dir = os.getcwd()
            db_dir = os.path.dirname(self.db_path)
            if db_dir:
                os.chdir(db_dir)
            
            with Database() as db:
                db.create_tables()  # Ensure tables exist
                saved_dirs = db.get_all_monitored_directories()
                
                if saved_dirs:
                    table = self.query_one("#file-monitor-table", FileMonitorTable)
                    dir_list_panel = self.query_one("#dir-list-panel", DirectoryListPanel)
                    
                    loaded_count = 0
                    for dir_data in saved_dirs:
                        # dir_data is (ID, directory_name, full_path, added_timestamp, status,
                        #              files_modified_count, files_added_count, files_deleted_count)
                        directory_path = dir_data[2]  # full_path
                        
                        # Extract event counts if available (for new schema)
                        modified_count = dir_data[5] if len(dir_data) > 5 else 0
                        added_count = dir_data[6] if len(dir_data) > 6 else 0
                        deleted_count = dir_data[7] if len(dir_data) > 7 else 0
                        
                        # Verify directory still exists before monitoring
                        if Path(directory_path).exists():
                            try:
                                # Start monitoring
                                self.file_watcher.start_monitoring(directory_path)
                                
                                # Initialize event counts for this directory
                                self.event_counts[directory_path] = {
                                    'modified': modified_count,
                                    'added': added_count,
                                    'deleted': deleted_count
                                }
                                
                                # Add to table
                                table.add_monitored_directory(directory_path)
                                
                                # Update the table with loaded counts
                                row_key = f"dir_{hash(directory_path)}"
                                if row_key in table.rows:
                                    table.update_directory_status(
                                        row_key,
                                        "active",
                                        modified=modified_count,
                                        added=added_count,
                                        deleted=deleted_count
                                    )
                                
                                loaded_count += 1
                                self.logger.info(
                                    f"Loaded directory: {directory_path} "
                                    f"(Modified: {modified_count}, Added: {added_count}, Deleted: {deleted_count})"
                                )
                            except Exception as e:
                                self.notify(f"Error loading directory {directory_path}: {e}", severity="warning")
                                self.logger.error(f"Error loading directory {directory_path}: {e}")
                        else:
                            # Directory no longer exists, remove from database
                            db.delete_monitored_directory(directory_path)
                            self.notify(f"Removed non-existent directory: {directory_path}", severity="warning")
                    
                    # Update directory list panel
                    dir_list_panel.monitored_dirs = self.file_watcher.list_monitored_directories()
                    
                    if loaded_count > 0:
                        self.notify(f"Loaded {loaded_count} monitored director{'y' if loaded_count == 1 else 'ies'} from database", severity="information")
                        
            # Restore original directory
            os.chdir(original_dir)
                    
        except Exception as e:
            self.notify(f"Error loading saved directories: {e}", severity="error")

    def handle_file_event(self, event_type: str, path: str, is_directory: bool) -> None:
        """Callback for file system events - batches updates to prevent layout thrashing."""
        # Log the event
        item_type = "directory" if is_directory else "file"
        self.logger.info(f"Event: {event_type} | Type: {item_type} | Path: {path}")
        
        # Find the row corresponding to the monitored directory
        monitored_dirs = self.file_watcher.list_monitored_directories()
        for dir_path in monitored_dirs:
            if path.startswith(dir_path):
                # Initialize counts for this directory if not present
                if dir_path not in self.event_counts:
                    self.event_counts[dir_path] = {
                        'modified': 0,
                        'added': 0,
                        'deleted': 0
                    }
                
                # Update in-memory counts
                if event_type == "modified":
                    self.event_counts[dir_path]['modified'] += 1
                elif event_type == "created":
                    self.event_counts[dir_path]['added'] += 1
                elif event_type == "deleted":
                    self.event_counts[dir_path]['deleted'] += 1
                
                # Mark this directory for pending update
                self.pending_updates[dir_path] = event_type
                
                # Update database asynchronously
                self._update_database_async(dir_path, event_type)
                break
    
    @work(exclusive=True, thread=True)
    async def _update_database_async(self, dir_path: str, event_type: str) -> None:
        """Update database counts asynchronously to avoid blocking UI."""
        try:
            original_dir = os.getcwd()
            db_dir = os.path.dirname(self.db_path)
            if db_dir:
                os.chdir(db_dir)
            
            with Database() as db:
                db.increment_directory_event_count(dir_path, event_type)
            
            os.chdir(original_dir)
            self.logger.info(f"Updated {event_type} count in database for: {dir_path}")
        except Exception as e:
            self.logger.error(f"Error updating database event count: {e}")
            try:
                os.chdir(original_dir)
            except:
                pass
    
    def _process_pending_updates(self) -> None:
        """Process batched updates to UI - called every 2 seconds."""
        if not self.pending_updates:
            return
        
        try:
            table = self.query_one("#file-monitor-table", FileMonitorTable)
            
            # Process all pending updates in one batch
            for dir_path, event_type in list(self.pending_updates.items()):
                row_key = f"dir_{hash(dir_path)}"
                
                if row_key in table.rows and dir_path in self.event_counts:
                    counts = self.event_counts[dir_path]
                    status = "modified" if event_type in ["modified", "deleted"] else "active"
                    
                    table.update_directory_status(
                        row_key, status,
                        modified=counts['modified'],
                        added=counts['added'],
                        deleted=counts['deleted']
                    )
            
            # Clear pending updates after processing
            self.pending_updates.clear()
            
        except Exception as e:
            self.logger.error(f"Error processing pending updates: {e}")


    def compose(self) -> ComposeResult:
        """Compose the file monitor view"""
        # Control panel at top
        yield DirectoryControlPanel(id="control-panel")
        
        # Main split-pane layout
        with Horizontal(id="file-monitor-content"):
            # Left panel - directory list (30%)
            yield DirectoryListPanel(classes="left-panel", id="dir-list-panel")
            
            # Right panel - details and table (70%)
            with Vertical(classes="right-panel"):
                yield Label(
                    "[bold]Monitored Directories Status[/bold]",
                    classes="section-title"
                )
                yield FileMonitorTable(id="file-monitor-table")
                
                # Bottom details panel
                yield FileDetailsPanel(id="details-panel")
    
    @on(Button.Pressed, "#add-dir-btn")
    def handle_add_directory(self) -> None:
        """Handle add directory button press"""
        dir_input = self.query_one("#directory-input", Input)
        path = dir_input.value.strip()
        
        if path and Path(path).exists():
            # Resolve to absolute path
            abs_path = str(Path(path).resolve())
            
            try:
                # Save to database first
                original_dir = os.getcwd()
                db_dir = os.path.dirname(self.db_path)
                if db_dir:
                    os.chdir(db_dir)
                
                with Database() as db:
                    db.create_tables()  # Ensure tables exist
                    db_success = db.add_monitored_directory(abs_path)
                
                os.chdir(original_dir)
                
                if not db_success:
                    self.notify(f"Directory already being monitored: {abs_path}", severity="warning")
                    dir_input.value = ""
                    return
                
                # Start file watcher monitoring
                self.file_watcher.start_monitoring(abs_path)
                
                # Initialize event counts for this directory
                self.event_counts[abs_path] = {
                    'modified': 0,
                    'added': 0,
                    'deleted': 0
                }
                
                # Add to table
                table = self.query_one("#file-monitor-table", FileMonitorTable)
                table.add_monitored_directory(abs_path)
                
                # Update directory list panel
                dir_list_panel = self.query_one("#dir-list-panel", DirectoryListPanel)
                dir_list_panel.monitored_dirs = self.file_watcher.list_monitored_directories()
                
                # Clear input
                dir_input.value = ""
                
                # Log and notify
                self.logger.info(f"Added directory for monitoring: {abs_path}")
                self.notify(f"Added and saved directory: {abs_path}", severity="information")
                
            except Exception as e:
                self.notify(f"Error adding directory to database: {e}", severity="error")
                # Restore original directory
                try:
                    os.chdir(original_dir)
                except:
                    pass
                
        elif path:
            self.notify(f"Invalid path: {path}", severity="error")
    
    @on(Button.Pressed, "#remove-dir-btn")
    def handle_remove_directory(self) -> None:
        """Handle remove directory button press"""
        table = self.query_one("#file-monitor-table", FileMonitorTable)
        
        if table.cursor_coordinate:
            row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
            path = str(table.get_row(row_key)[0]) # Get path from the table
            
            try:
                # Stop file watcher monitoring
                self.file_watcher.stop_monitoring(path)
                
                # Remove from database
                original_dir = os.getcwd()
                db_dir = os.path.dirname(self.db_path)
                if db_dir:
                    os.chdir(db_dir)
                
                with Database() as db:
                    db_success = db.delete_monitored_directory(path)
                
                os.chdir(original_dir)
                
                if not db_success:
                    self.notify(f"Warning: Directory removed from UI but database deletion failed", severity="warning")
                
                # Remove from table
                table.remove_row(row_key)
                
                # Remove from event counts
                if path in self.event_counts:
                    del self.event_counts[path]
                
                # Update directory list panel
                dir_list_panel = self.query_one("#dir-list-panel", DirectoryListPanel)
                dir_list_panel.monitored_dirs = self.file_watcher.list_monitored_directories()
                
                # Log and notify
                self.logger.info(f"Removed directory from monitoring: {path}")
                self.notify(f"Directory removed from monitoring and database: {path}", severity="information")
                
            except Exception as e:
                self.notify(f"Error removing directory: {e}", severity="error")
                # Restore original directory
                try:
                    os.chdir(original_dir)
                except:
                    pass
    
    @on(Button.Pressed, "#pause-btn")
    def handle_pause(self, event: Button.Pressed) -> None:
        """Handle pause/resume button press"""
        button = event.button
        if button.label == "Pause All":
            self.file_watcher.stop_all_monitoring()
            button.label = "Resume All"
            button.variant = "primary"
            self.notify("All monitoring paused", severity="warning")
            # Update table statuses to paused
            table = self.query_one("#file-monitor-table", FileMonitorTable)
            for row_key in table.rows:
                table.update_directory_status(row_key, "paused")
        else:
            # Re-start monitoring all previously monitored directories
            table = self.query_one("#file-monitor-table", FileMonitorTable)
            for row_key in table.rows:
                path = str(table.get_row(row_key)[0])
                self.file_watcher.start_monitoring(path)
                table.update_directory_status(row_key, "active")

            button.label = "Pause All"
            button.variant = "warning"
            self.notify("Monitoring resumed", severity="information")
    
    def on_unmount(self) -> None:
        """Clean up when widget is unmounted."""
        if self.update_timer:
            self.update_timer.stop()
            self.update_timer = None
    
    @on(DataTable.RowSelected, "#file-monitor-table")
    def handle_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection in the table"""
        row_data = event.data_table.get_row(event.row_key)
        path = str(row_data[0])
        
        # Update details panel
        details_panel = self.query_one("#details-panel", FileDetailsPanel)
        details = f"""
[bold]Directory:[/bold] {path}
[bold]Status:[/bold] {row_data[1]}
[bold]Last Check:[/bold] {row_data[2]}
[bold]Files Modified:[/bold] {row_data[3]}
[bold]Files Added:[/bold] {row_data[4]}
[bold]Files Deleted:[/bold] {row_data[5]}

[dim]Click 'Remove Selected' to stop monitoring this directory[/dim]
        """
        details_panel.update_details(path, details.strip())