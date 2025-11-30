import pytest
import os
import uuid
from HIDS.database.database import Database
import sqlite3

@pytest.fixture
def db():
    database = Database()
    return database

class TestDatabase:
    def test_db_file_exists(self):
        file_found = False
        for root, _, files in os.walk("."):
            if "HIDS.db" in files:
                file_found = True
                break
        assert file_found

    def test_create_tables(self, db):
        db.create_tables()
        # Verify tables are created (implementation needed)
        conn = sqlite3.connect("HIDS.db")
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        table_names = [table[0] for table in tables]
        assert "file_monitoring" in table_names
        assert "directory_mon" in table_names
        assert "alerts" in table_names
       

    def test_write(self, db):
        id = str(uuid.uuid4())
        data = {"ID": id, "file_name": "test.txt", "hash": "123", "file_path": "/tmp"}
        db.write("file_monitoring", data)
        # Verify data is written (implementation needed)
        conn = sqlite3.connect("HIDS.db")
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM file_monitoring WHERE ID = '{id}'")
        result = cursor.fetchone()
        assert result is not None
        assert result[1] == "test.txt"
       
    def test_update(self, db):
        id = str(uuid.uuid4())
        data = {"ID": id, "file_name": "test.txt", "hash": "123", "file_path": "/tmp"}
        db.write("file_monitoring", data)
        data = {"hash": "456"}
        db.update("file_monitoring", data, f"ID = '{id}'")
        # Verify data is updated (implementation needed)
        conn = sqlite3.connect("HIDS.db")
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM file_monitoring WHERE ID = '{id}'")
        result = cursor.fetchone()
        assert result is not None
        assert result[2] == "456"
       

    def test_delete(self, db):
        id = str(uuid.uuid4())
        data = {"ID": id, "file_name": "test.txt", "hash": "123", "file_path": "/tmp"}
        db.write("file_monitoring", data)
        db.delete("file_monitoring", f"ID = '{id}'")
        # Verify data is deleted (implementation needed)
        conn = sqlite3.connect("HIDS.db")
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM file_monitoring WHERE ID = '{id}'")
        result = cursor.fetchone()
        assert result is None
    