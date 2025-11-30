import sqlite3

class Database:
    
    def __init__(self):
        self.__conn = sqlite3.connect("HIDS.db")
        self.__cursor = self.__conn.cursor()

    def __enter__(self):
        """
        Lets you write:     with Database() as db:
        and receive a ready‑to‑use Database instance.
        """
        return self            # give the caller the live object

    def __exit__(self, exc_type, exc, tb):
        """
        Runs automatically when the with‑block ends.

        • No error (exc_type is None)  → commit the outstanding work  
        • Error happened               → roll back so the DB stays clean  
        • Always                       → close the connection to release the file handle
        """
        if exc_type is None:
            self.__conn.commit()   # final save
        else:
            self.__conn.rollback() # undo partial work

        self.__conn.close()
        return False    

    def close(self):
        #incase I decide to be a dumb shit and not use the context manager.
        self.__conn.commit()
        self.__conn.close() 


    def get_cursor(self):
        return self.__cursor if isinstance(self.__cursor, sqlite3.Cursor) else None
    

    def create_tables(self):
        self.__cursor.execute('''

        CREATE TABLE IF NOT EXISTS file_monitoring(
            ID TEXT PRIMARY KEY,
            file_name TEXT NOT NULL,
            hash TEXT NOT NULL,
            file_path TEXT NOT NULL                      
         )
        ''')

        self.__cursor.execute('''
        
        CREATE TABLE IF NOT EXISTS directory_monitoring(
            ID TEXT PRIMARY KEY,
            directory_name TEXT NOT NULL,
            full_path TEXT NOT NULL UNIQUE,
            added_timestamp TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            files_modified_count INTEGER DEFAULT 0,
            files_added_count INTEGER DEFAULT 0,
            files_deleted_count INTEGER DEFAULT 0
        )
        ''')

        self.__cursor.execute('''

        CREATE TABLE IF NOT EXISTS alerts(
            ID TEXT PRIMARY KEY,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            detected_by TEXT NOT NULL,
            details TEXT NOT NULL               
        )

        ''')
        self.__conn.commit()

        #Catch errors associated with these crud functions

    def write(self, table_name, data):
        """
        Writes data to the specified table.
        Args:
            table_name (str): The name of the table.
            data (dict): A dictionary where keys are column names and values are the values to be inserted.
        """
        columns = ', '.join(data.keys())
        placeholders = ', '.join(['?'] * len(data))
        sql = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"
        values = list(data.values())
        self.__cursor.execute(sql, values)
        self.__conn.commit()

    def update(self, table_name, data, where):
        """
        Updates data in the specified table.
        Args:
            table_name (str): The name of the table.
            data (dict): A dictionary where keys are column names and values are the new values.
            where (str): The WHERE clause for the update.
        """
        set_clause = ', '.join([f"{key} = ?" for key in data.keys()])
        sql = f"UPDATE {table_name} SET {set_clause} WHERE {where}"
        values = list(data.values())
        self.__cursor.execute(sql, values)
        self.__conn.commit()
    def read_all(self, table_name):
        """
        Reads all data from the specified table.
        Args:
            table_name (str): The name of the table.
        Returns:
            list: A list of tuples containing the rows.
        """
        # Note: table_name should be validated/sanitized as it cannot be parameterized
        # Only use with trusted, application-controlled table names
        sql = f"SELECT * FROM {table_name}"
        self.__cursor.execute(sql)
        return self.__cursor.fetchall()


    def delete(self, table_name, where):
        """
        Deletes data from the specified table.
        Args:
            table_name (str): The name of the table.
            where (str): The WHERE clause for the delete.
        """
        sql = f"DELETE FROM {table_name} WHERE {where}"
        self.__cursor.execute(sql)
        self.__conn.commit()

    # Monitored Directories specific methods
    def add_monitored_directory(self, directory_path: str) -> bool:
        """
        Add a directory to the monitored directories table.
        Args:
            directory_path (str): The full path of the directory to monitor
        Returns:
            bool: True if successful, False if directory already exists or error
        """
        try:
            from datetime import datetime
            import os
            import uuid
            
            dir_name = os.path.basename(directory_path) or directory_path
            data = {
                'ID': str(uuid.uuid4()),
                'directory_name': dir_name,
                'full_path': directory_path,
                'added_timestamp': datetime.now().isoformat(),
                'status': 'active'
            }
            self.write('directory_monitoring', data)
            return True
        except sqlite3.IntegrityError:
            # Directory already exists (UNIQUE constraint on full_path)
            return False
        except Exception as e:
            print(f"Error adding monitored directory: {e}")
            return False

    def get_all_monitored_directories(self) -> list:
        """
        Retrieve all monitored directories from the database.
        Returns:
            list: List of tuples containing (ID, directory_name, full_path, added_timestamp, status)
        """
        try:
            return self.read_all('directory_monitoring')
        except Exception as e:
            print(f"Error retrieving monitored directories: {e}")
            return []

    def delete_monitored_directory(self, directory_path: str) -> bool:
        """
        Delete a monitored directory from the database.
        Args:
            directory_path (str): The full path of the directory to remove
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.delete('directory_monitoring', f"full_path = '{directory_path}'")
            return True
        except Exception as e:
            print(f"Error deleting monitored directory: {e}")
            return False

    def update_directory_status(self, directory_path: str, status: str) -> bool:
        """
        Update the status of a monitored directory.
        Args:
            directory_path (str): The full path of the directory
            status (str): The new status (e.g., 'active', 'paused', 'error')
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.update('directory_monitoring', {'status': status}, f"full_path = '{directory_path}'")
            return True
        except Exception as e:
            print(f"Error updating directory status: {e}")
            return False

    def increment_directory_event_count(self, directory_path: str, event_type: str) -> bool:
        """
        Increment the event count for a specific event type.
        Args:
            directory_path (str): The full path of the directory
            event_type (str): The type of event ('modified', 'created', 'deleted')
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            column_map = {
                'modified': 'files_modified_count',
                'created': 'files_added_count',
                'deleted': 'files_deleted_count'
            }
            
            column = column_map.get(event_type)
            if not column:
                return False
            
            sql = f"""
            UPDATE directory_monitoring 
            SET {column} = {column} + 1 
            WHERE full_path = ?
            """
            self.__cursor.execute(sql, (directory_path,))
            self.__conn.commit()
            return True
        except Exception as e:
            print(f"Error incrementing event count: {e}")
            return False

    def get_directory_event_counts(self, directory_path: str) -> dict:
        """
        Get the event counts for a monitored directory.
        Args:
            directory_path (str): The full path of the directory
        Returns:
            dict: Dictionary with event counts or None if not found
        """
        try:
            sql = """
            SELECT files_modified_count, files_added_count, files_deleted_count 
            FROM directory_monitoring 
            WHERE full_path = ?
            """
            self.__cursor.execute(sql, (directory_path,))
            result = self.__cursor.fetchone()
            
            if result:
                return {
                    'modified': result[0],
                    'added': result[1],
                    'deleted': result[2]
                }
            return None
        except Exception as e:
            print(f"Error getting directory event counts: {e}")
            return None

