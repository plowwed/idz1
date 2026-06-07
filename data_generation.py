"""модуль для генерации данных"""
import json
from faker import Faker
import random

fake = Faker()
random.seed(42)
ip_pool = [fake.ipv4() for _ in range(100)] #100 уникальных

baseline = []
for _ in range(1000):
    ip = random.choice(ip_pool)  # случайный ip из пула
    baseline.append(ip)

common_ips = random.sample(ip_pool, 30) #30 из пула
new_ips = [fake.ipv4() for _ in range(10)] #10 новых
anomaly_ips = [fake.ipv4() for _ in range(10)] #10 аномальных
current = []
for _ in range(150):
    current.append(random.choice(common_ips))
#новые устройства
for ip in new_ips:
    current.append(ip)
    if random.random() < 0.5:
        current.append(ip)

# аномальные устройства
for ip in anomaly_ips:
    for _ in range(random.randint(15, 25)):
        current.append(ip)

random.shuffle(current)

with open('baseline.json', 'w') as f:
    json.dump(baseline, f, indent=2)

with open('current.json', 'w') as f:
    json.dump(current, f, indent=2)
