from flask_login import UserMixin
from db_model.mysql import conn_mysqldb

class User(UserMixin):
    
    def __init__(self,user_id,username,email,passwords):
        self.id = user_id
        self.username = username
        self.email = email
        self.passwords = passwords
    
    def get_id(self):
        return str(self.id)
    
    def get_passwords(self):
        return str(self.passwords)
    
    @staticmethod
    def get(user_id):
        mysql_db = conn_mysqldb()
        db_cursor = mysql_db.cursor()
        sql = "SELECT * FROM user_info WHERE user_id = '" +str(user_id) + "'"
        print(sql)
        db_cursor.execute(sql)
        user = db_cursor.fetchone()
        if not user:
            return None
        
        user = User(user_id=user[0],username=user[1], email=user[2], passwords=user[3])
        return user
    
    @staticmethod
    def find(username):
        mysql_db = conn_mysqldb()
        db_cursor = mysql_db.cursor()
        sql = "SELECT * FROM user_info WHERE USERNAME = '" +str(username) + "'"
        print(sql)
        db_cursor.execute(sql)
        user = db_cursor.fetchone()
        if not user:
            return None
        
        user = User(user_id=user[0],username=user[1], email=user[2], passwords=user[3])
        return user
    
    @staticmethod
    def create(username, email,passwords):
        user = User.find(username)
        if user == None:
            mysql_db = conn_mysqldb()
            db_cursor = mysql_db.cursor()
            sql = "INSERT INTO user_info (USERNAME, EMAIL, PASSWORDS) VALUES ('%s', '%s','%s')" %(str(username),str(email),str(passwords))
            db_cursor.execute(sql)
            mysql_db.commit()
            return User.find(username)
        else:
            return None
    
    @staticmethod
    def delete(user_id):
        mysql_db = conn_mysqldb()
        db_cursor = mysql_db.cursor()
        sql = "DELETE FROM user_info WHERE USER_ID = %d" %(user_id)
        deleted = db_cursor.execute(sql)
        mysql_db.commit()
        return deleted
    