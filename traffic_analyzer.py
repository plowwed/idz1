import json
import math
from collections import Counter

class TrafficAnalyzer:
    def __init__(self, baseline=None, current=None, sigma=3):
        self._baseline = baseline
        self._current = current
        self._sigma = sigma
        self.baseline_all = []
        self.current_all = []
        self._baseline_unique = set()
        self._current_unique = set()
        self._new_dev = set()
        self._missing_dev = set()
        self._suspicious_dev = {}
        self._mean = 0
        self._std = 0
        self._threshold = 0
        self._report = {}

    def read_data(self, filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for d in data:
                yield d

    def load_data(self):
        self.baseline_all = list(self.read_data(self._baseline))
        self.current_all = list(self.read_data(self._current))
        self._baseline_unique = set(self.baseline_all)
        self._current_unique = set(self.current_all)

    def to_dict(self):
        return{
            "settings": {
                "baseline": self._baseline,
                "current": self._current,
                "sigma": self._sigma,
            },
            "data":{
                "baseline_all": self.baseline_all,
                "current_all": self.current_all,
                "baseline_unique": list(self._baseline_unique),
                "current_unique": list(self._current_unique)
            },
            "results":{
                "new_devices": list(self._new_dev),
                "missing_devices": list(self._missing_dev),
                "suspicious_devices": self._suspicious_dev,
                "mean": self._mean,
                "std": self._std,
                "threshold": self._threshold
            }
        }

    @classmethod
    def from_dict(cls, data):
        obj = cls(
            baseline=data["settings"]["baseline"],
            current=data["settings"]["current"],
            sigma=data["settings"]["sigma"]
        )
        obj.baseline_all = data["data"]["baseline_all"]
        obj.current_all = data["data"]["current_all"]
        obj._baseline_unique = set(data["data"]["baseline_unique"])
        obj._current_unique = set(data["data"]["current_unique"])
        obj._new_dev = set(data["results"]["new_devices"])
        obj._missing_dev = set(data["results"]["missing_devices"])
        obj._suspicious_dev = data["results"]["suspicious_devices"]
        obj._mean = data["results"]["mean"]
        obj._std = data["results"]["std"]
        obj._threshold = data["results"]["threshold"]
        return obj

    def new_device(self):
        self._new_dev = self._current_unique - self._baseline_unique
        return self._new_dev

    def missing_device(self):
        self._missing_dev = self._baseline_unique - self._current_unique
        return self._missing_dev

    def count_connections(self, ip_list):
        return dict(Counter(ip_list))

    def anomalies(self):
        baseline_count = Counter(self.baseline_all)
        count_list = list(baseline_count.values())
        if len(count_list) == 0:
            raise ValueError('нет данных')
        self._mean = sum(count_list) / len(count_list)
        variance = sum((x - self._mean) ** 2 for x in count_list) / len(count_list)
        self._std = math.sqrt(variance)
        self._threshold = self._mean + self._sigma * self._std
        current_count = Counter(self.current_all)
        self._suspicious_dev = {}
        for ip in self._new_dev:
            conn = current_count[ip]
            if conn > self._threshold:
                self._suspicious_dev[ip] = {"connection": conn, "threshold": self._threshold}

        return self._suspicious_dev

    def save_state(self, filepath):
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)

    def load_state(self, filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        new_obj = self.from_dict(data)
        self.__dict__.update(new_obj.__dict__)

    def report(self, output_path="report.json"):
        report_data = {
            "settings": {
                "baseline_file": self._baseline,
                "current_file": self._current,
                "sigma_multiplier": self._sigma
            },
            "statistics": {
                "baseline_unique_ips": len(self._baseline_unique),
                "current_unique_ips": len(self._current_unique),
                "new_devices_count": len(self._new_dev),
                "missing_devices_count": len(self._missing_dev),
                "mean_connections": self._mean,
                "std_connections": self._std,
                "anomaly_threshold": self._threshold
            },
            "new_devices": list(self._new_dev),
            "missing_devices": list(self._missing_dev),
            "suspicious_devices": self._suspicious_dev
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        return report_data