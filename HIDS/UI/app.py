"""
HIDS Main Application - Burp Suite-inspired UI using Textual
"""
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, TabbedContent, TabPane

from HIDS.UI.views.file_monitor import FileMonitorView
from HIDS.UI.views.network_monitor import NetworkMonitorView
from HIDS.UI.views.process_monitor import ProcessMonitorView
from HIDS.UI.views.log_viewer import LogViewerView


class HIDSApp(App):
    """Host-based Intrusion Detection System - Terminal UI Application"""
    
    TITLE = "HIDS - Host Intrusion Detection System"
    CSS_PATH = "hids.tcss"
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("f", "switch_tab('file-monitor')", "File Monitor"),
        ("n", "switch_tab('network')", "Network"),
        ("p", "switch_tab('process-monitor')", "Process Monitor"),
        ("l", "switch_tab('log-viewer')", "Log Viewer"),
        ("k", "kill_selected_process", "Kill Process"),
        ("r", "refresh_processes", "Refresh"),
    ]
    
    def compose(self) -> ComposeResult:
        """Compose the main UI layout"""
        yield Header(show_clock=True)
        
        with TabbedContent(initial="file-monitor"):
            with TabPane("File Monitor", id="file-monitor"):
                yield FileMonitorView(id="file-monitor-view")
            
            with TabPane("Network Monitor", id="network"):
                yield NetworkMonitorView()
            
            with TabPane("Process Monitor", id="process-monitor"):
                yield ProcessMonitorView(id="process-monitor-view")
            
            with TabPane("Log Viewer", id="log-viewer"):
                yield LogViewerView(id="log-viewer-view")
        
        yield Footer()
    
    def action_switch_tab(self, tab_id: str) -> None:
        """Switch to a specific tab"""
        tabbed_content = self.query_one(TabbedContent)
        tabbed_content.active = tab_id
    
    def action_kill_selected_process(self) -> None:
        """Kill the currently selected process"""
        try:
            process_view = self.query_one("#process-monitor-view", ProcessMonitorView)
            process_view.handle_kill_process()
        except Exception:
            # Process monitor not active
            pass
    
    def action_refresh_processes(self) -> None:
        """Refresh the process list"""
        try:
            process_view = self.query_one("#process-monitor-view", ProcessMonitorView)
            process_view.handle_refresh()
        except Exception:
            # Process monitor not active
            pass


def run_app() -> None:
    """Entry point to run the HIDS application"""
    app = HIDSApp()
    app.run()


if __name__ == "__main__":
    run_app()