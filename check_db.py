import sqlite3
c = sqlite3.connect("data/local/events.db")
q = lambda s: c.execute(s).fetchall()

print("flow total:", q("select count(*) from flow_events"))
print("trail total:", q("select count(*) from trail_events"))
print("REJECT 8080:", q("select srcaddr,dstaddr,dstport,action,start from flow_events where dstport='8080' and action='REJECT' limit 3"))
print("ACCEPT 8080:", q("select srcaddr,dstaddr,dstport,action,start from flow_events where dstport='8080' and action='ACCEPT' limit 3"))
print("SG events:", q("select event_time,event_name,source_ip from trail_events where event_name in ('AuthorizeSecurityGroupIngress','RevokeSecurityGroupIngress') order by event_time"))
