import mysql.connector

# Insert your Aiven Database details here
config = {
    'user': 'avnadmin',
    'password': 'AVNS_zO9UOWRe4l57p8pfpKh',
    'host': 'mysql-2d4333a9-aogundijo531-a14f.a.aivencloud.com',
    'port': 26635,
    'database': 'defaultdb',
}

try:
    print("Connecting to Aiven Cloud...")
    conn = mysql.connector.connect(**config)
    cursor = conn.cursor()

    print("Building tbl_users...")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tbl_users (
        user_id INT AUTO_INCREMENT PRIMARY KEY,
        full_name VARCHAR(100),
        email VARCHAR(100) UNIQUE,
        password_hash VARCHAR(255)
    )
    """)

    print("Building tbl_scan_logs...")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tbl_scan_logs (
        log_id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        payload_type VARCHAR(10),
        payload_content TEXT,
        threat_probability VARCHAR(20),
        classification VARCHAR(20),
        scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES tbl_users(user_id)
    )
    """)
    
    conn.commit()
    print("✅ Cloud database built successfully!")

except Exception as e:
    print(f"❌ Error: {e}")
finally:
    if 'conn' in locals() and conn.is_connected():
        cursor.close()
        conn.close()