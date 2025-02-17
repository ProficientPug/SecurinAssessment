import schedule
import time
import os

def run_db_update():
    os.system('please input the path of the databse.py file in the user computer')


schedule.every(1).hour.do(run_db_update)

while True:
    schedule.run_pending()
    time.sleep(1)
