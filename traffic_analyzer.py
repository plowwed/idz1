import json
import math
from collections import Counter
import logging

class TrafficAnalyzer:
    """анализатор сетевого трафика для обнаружения аномалий
       сравнивает два набора данных о сетевых соединениях:
       1) baseline - записи за неделю нормальной работы;
       2) current - записи за последний час
       находит новые устройства, пропавшие устройства и подозрительную активность
       на основе статистического анализа.
       Attributes:
           baseline_all (list) - все IP-адреса из baseline (с повторениями),
           current_all (list) - все IP-адреса из current (с повторениями).
       Examples:
           analyzer = TrafficAnalyzer("baseline.json", "current.json", sigma=3)
           analyzer.load_data()
           analyzer.new_device()
           analyzer.anomalies()
       """
    def __init__(self, baseline=None, current=None, sigma=3):
        """инициализирует анализ сетевого трафика
           Attributes:
               baseline (str) - путь к json файлу с baseline данными,
               current (str) - путь к json файлу с current данными,
               sigma (int/float) - множитель стандартного отклонения для определенного порога аномалии, по умолчанию равен 3.
           """
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        file_handler = logging.FileHandler('app.log', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        self.logger.handlers.clear()
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
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
        self.logger.info(f'анализатор создан ({baseline}, {current}, {sigma})')

    @property
    def sigma(self):
        """множитель стандартного отклонения для порога аномалии.
        Returns:
            int or float - текущий множитель сигмы.
        """
        return self._sigma

    @sigma.setter
    def sigma(self, value):
        """устанавливает множитель сигмы.
        Args:
            value (int or float) - новый множитель (должен быть > 0).
        Raises:
            ValueError: если значение меньше или равно нулю.
        """
        if value <= 0:
            raise ValueError("сигма должна быть положительным числом")
        self._sigma = value
        self.logger.debug(f"множитель сигмы изменён на {value}")

    def read_data(self, filepath):
        """читает ip-адреса из json файла.
        Args:
            filepath (str) - путь к json файлу со списком ip-адресов.
        Yields:
            str - ip-адрес из файла.
        """

        self.logger.debug(f'чтение файла ({filepath})')
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            self.logger.debug(f'файл открыт, записей {len(data)}')
            for d in data:
                yield d

    def load_data(self):
        """загружает данные из baseline и current файлов.
        загружает все ip-адреса в списки (с повторениями) и строит множества уникальных ip для дальнейшего анализа.
        """
        self.logger.info('началась загрузка данных')
        self.baseline_all = list(self.read_data(self._baseline))
        self.logger.info('все записи baseline загружены в список')
        self.current_all = list(self.read_data(self._current))
        self.logger.info('все записи current загружены в список')
        self._baseline_unique = set(self.baseline_all)
        self.logger.info('уникальные записи baseline загружены в множество')
        self._current_unique = set(self.current_all)
        self.logger.info('уникальные записи current загружены в множество')

    def to_dict(self):
        """сериализует состояние объекта в словарь.
        Returns:
            dict - полное состояние объекта, включая настройки, данные и результаты.
        """
        self.logger.debug('началась сериализация объекта в словарь')
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
        """создаёт объект из словаря.
        Args:
            data (dict) - словарь с данными объекта (из to_dict()).
        Returns:
            TrafficAnalyzer - восстановленный объект анализатора.
        """
        logging.info('создание объекта из словаря')
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
        logging.debug('объект восстановлен')
        return obj

    def new_device(self):
        """находит ip-адреса, которые появились только в current наборе.
        вычисляет разность множеств current_unique - baseline_unique.
        Returns:
            set - множество новых ip-адресов.
        """
        self.logger.info('начался поиск новых устройств')
        self._new_dev = self._current_unique - self._baseline_unique
        self.logger.info(f'найдено новых устройств {len(self._new_dev)}')
        self.logger.debug(f'новые ip {list(self._new_dev)}')
        return self._new_dev

    def missing_device(self):
        """находит ip-адреса, которые были в baseline, но отсутствуют в current. вычисляет разность множеств baseline_unique - current_unique.
        Returns:
            set - множество пропавших IP-адресов.
        """
        self.logger.info('начался поиск пропавших устройств')
        self._missing_dev = self._baseline_unique - self._current_unique
        self.logger.info(f'найдено пропавших устройств {len(self._missing_dev)}')
        self.logger.debug(f'пропавшие ip {list(self._missing_dev)}')
        return self._missing_dev

    def count_connections(self, ip_list):
        """подсчитывает количество соединений для каждого ip-адреса.
        использует collections.Counter для подсчёта.
        Args:
            ip_list (list) - список ip-адресов (с повторениями).
        Returns:
            dict - словарь {ip: количество_соединений}.
        Examples:
            analyzer.count_connections(["192.168.1.1", "192.168.1.1", "10.0.0.1"])
            {"192.168.1.1": 2, "10.0.0.1": 1}
        """
        self.logger.info(f'подсчет соединений для {len(ip_list)} записей')
        return dict(Counter(ip_list))

    def anomalies(self):
        """обнаруживает аномальные соединения методом трёх сигм.
        вычисляет среднее и стандартное отклонение по baseline, затем проверяет новые устройства из current на превышение порога μ + k*σ (где k — множитель сигмы).
        устройства с количеством соединений выше порога помечаются как подозрительные.
        Returns:
            dict - словарь подозрительных устройств
                {ip: {"connections": N, "threshold": T}}.
        Raises:
            ValueError - если нет данных для анализа.
        """
        self.logger.info('начался поиск аномалий')
        baseline_count = Counter(self.baseline_all)
        count_list = list(baseline_count.values())
        if len(count_list) == 0:
            self.logger.error('нет данных')
            raise ValueError('нет данных')
        self._mean = sum(count_list) / len(count_list)
        variance = sum((x - self._mean) ** 2 for x in count_list) / len(count_list)
        self._std = math.sqrt(variance)
        self._threshold = self._mean + self._sigma * self._std
        self.logger.debug(f'среднее {self._mean}')
        self.logger.debug(f'стандартное отклонение {self._std}')
        self.logger.debug(f'порог аномалии {self._threshold}')
        current_count = Counter(self.current_all)
        self._suspicious_dev = {}
        for ip in self._new_dev:
            conn = current_count[ip]
            self.logger.debug(f'проверка ip {ip} {conn} соединений')
            if conn > self._threshold:
                self._suspicious_dev[ip] = {"connection": conn, "threshold": self._threshold}
                self.logger.info(f'найдена аномалия {ip} ({conn} соединений)')
        self.logger.info(f'всего подозрительных устройств {len(self._suspicious_dev)}')
        return self._suspicious_dev

    def save_state(self, filepath):
        """сохраняет полное состояние объекта в json файл.
        Args:
            filepath (str) - путь для сохранения.
        """
        self.logger.info(f'сохранение состояния в {filepath}')
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
        self.logger.info('состояние сохранено')

    def load_state(self, filepath):
        """загружает состояние объекта из json файла.
        Args:
            filepath (str) - путь к файлу состояния.
        """
        self.logger.info(f'загрузка состояния из {filepath}')
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        new_obj = self.from_dict(data)
        self.__dict__.update(new_obj.__dict__)
        self.logger.info('состояние загружено')

    def report(self, output_path="report.json"):
        """генерирует аналитический отчёт в json формате.
            отчёт содержит:
                1) настройки анализа;
               2) статистику (количество уникальных ip, новых, пропавших);
               3) метрики (среднее, стандартное отклонение, порог);
               4) списки новых, пропавших и подозрительных устройств.
            Args:
                output_path (str) - путь для сохранения отчёта.
                по умолчанию "report.json".
            Returns:
                dict - словарь с данными отчёта.
        """
        self.logger.info(f'генерация отчета в {output_path}')
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
        self.logger.info(f'отчет загружен в {output_path}')
        return report_data