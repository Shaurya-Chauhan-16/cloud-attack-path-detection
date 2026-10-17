import sqlite3
c = sqlite3.connect("data/local/events.db")
rows = c.execute("""select datetime(start,'unixepoch'), interface_id, flow_direction, action
from flow_events where dstport='8080' and srcaddr='10.20.1.10' and dstaddr='10.20.2.10'
order by start""").fetchall()
for r in rows: print(r)
