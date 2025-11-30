from HIDS.log_analysis import alert
import queue
from HIDS.database.database import Database
from uuid import uuid4

class AlertManager:
    def __init__(self, queue=alert.alert_queue):
        self.__alert_queue = queue
        self.number_of_alerts = self.__alert_queue.qsize()

    def add_alert(self, alert:alert.Alert):
        try:
            if not self.__alert_queue.full():
                self.__alert_queue.put(alert)
        except queue.Full:
            print("Queue is full")


    def view_current_alert(self):
        try:
            if not self._alert_queue.empty():
                alert_data = self.__alert_queue.get()
                try:
                    print(f"{alert_data.timestamp} \n alert_level:{alert_data.alertLevel} \n {alert_data.message} \n\n {alert_data.detected_by}")
                except AttributeError:
                    print("Error: Alert data has missing attributes")
            else:
                print("No Alerts currently")
        except queue.Empty:
            print("No Alerts currently")
            
    def empty_queue(self):
        while not self.__alert_queue.empty():
            # Loop until the queue is empty
            try:
                self.__alert_queue.get_nowait()
                # Try to get an alert from the queue without blocking.
            except queue.Empty:
                break

    def save_alert_in_db(self, alert: alert.Alert):
        with Database() as db:
            alert_data = {
                "ID": str(uuid4()),
                "severity": alert.alertLevel,
                "message": alert.message,
                "detected_by": alert.detected_by,
                "details": str(alert.__dict__)  # Store all alert attributes as a string
            }
            db.write("alerts", alert_data)

    def query_alerts_db(self):
        pass
        #TODO


