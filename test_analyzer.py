import json
import os
import pytest
import tempfile
from traffic_analyzer import TrafficAnalyzer


@pytest.fixture
def temp_files():
    """создание временных данных для тестирования"""
    temp_dir = tempfile.mkdtemp()

    baseline_data = [
        "192.168.1.1", "192.168.1.1", "192.168.1.1",
        "192.168.1.2", "192.168.1.2",
        "192.168.1.3",
        "10.0.0.1", "10.0.0.1",
        "10.0.0.2"
    ]

    current_data = [
        "192.168.1.1", "192.168.1.1",
        "192.168.1.2",
        "192.168.1.4", "192.168.1.4", "192.168.1.4", "192.168.1.4",
        "10.0.0.3"
    ]

    baseline_path = os.path.join(temp_dir, "baseline_test.json")
    current_path = os.path.join(temp_dir, "current_test.json")

    with open(baseline_path, 'w') as f:
        json.dump(baseline_data, f)
    with open(current_path, 'w') as f:
        json.dump(current_data, f)

    yield {
        "temp_dir": temp_dir,
        "baseline_path": baseline_path,
        "current_path": current_path
    }

    for file in os.listdir(temp_dir):
        os.remove(os.path.join(temp_dir, file))
    os.rmdir(temp_dir)


@pytest.fixture
def analyzer(temp_files):
    """создает анализатор с загруженными данными"""
    a = TrafficAnalyzer(temp_files["baseline_path"], temp_files["current_path"], sigma=2)
    a.load_data()
    return a

def test_load_data(analyzer):
    """загрузка данных"""
    assert len(analyzer.baseline_all) == 9
    assert len(analyzer.current_all) == 8

def test_new_device(analyzer):
    """поиск новых устройств"""
    new = analyzer.new_device()
    assert new == {"192.168.1.4", "10.0.0.3"}

def test_new_device_empty(temp_files):
    """нет новых устройств"""
    data = ["192.168.1.1"]
    p1 = os.path.join(temp_files["temp_dir"], "a.json")
    p2 = os.path.join(temp_files["temp_dir"], "b.json")
    with open(p1, 'w') as f: json.dump(data, f)
    with open(p2, 'w') as f: json.dump(data, f)

    a = TrafficAnalyzer(p1, p2)
    a.load_data()
    assert len(a.new_device()) == 0


def test_missing_device(analyzer):
    """Ппоисв пропавших устройств"""
    missing = analyzer.missing_device()
    assert missing == {"192.168.1.3", "10.0.0.1", "10.0.0.2"}


def test_missing_device_empty(temp_files):
    """нет пропавших устройств"""
    data = ["192.168.1.1"]
    p1 = os.path.join(temp_files["temp_dir"], "a.json")
    p2 = os.path.join(temp_files["temp_dir"], "b.json")
    with open(p1, 'w') as f: json.dump(data, f)
    with open(p2, 'w') as f: json.dump(data, f)

    a = TrafficAnalyzer(p1, p2)
    a.load_data()
    assert len(a.missing_device()) == 0


def test_count_connections(analyzer):
    """подсчет соединений"""
    counts = analyzer.count_connections(["192.168.1.1", "192.168.1.1", "192.168.1.2"])
    assert counts == {"192.168.1.1": 2, "192.168.1.2": 1}


def test_count_connections_empty(analyzer):
    """пустой список"""
    assert analyzer.count_connections([]) == {}


def test_anomalies(analyzer):
    """поиск аномалий"""
    analyzer.new_device()
    suspicious = analyzer.anomalies()
    assert "192.168.1.4" in suspicious
    assert "10.0.0.3" not in suspicious


def test_anomalies_none(temp_files):
    """нет аномалий"""
    base = ["192.168.1.1", "192.168.1.2"]
    curr = ["192.168.1.1", "192.168.1.3"]
    p1 = os.path.join(temp_files["temp_dir"], "a.json")
    p2 = os.path.join(temp_files["temp_dir"], "b.json")
    with open(p1, 'w') as f: json.dump(base, f)
    with open(p2, 'w') as f: json.dump(curr, f)

    a = TrafficAnalyzer(p1, p2, sigma=3)
    a.load_data()
    a.new_device()
    assert len(a.anomalies()) == 0


def test_to_dict(analyzer):
    """сериализация"""
    analyzer.new_device()
    state = analyzer.to_dict()
    assert "settings" in state
    assert state["settings"]["sigma"] == 2


def test_from_dict(analyzer):
    """десериализация"""
    analyzer.new_device()
    state = analyzer.to_dict()
    new_a = TrafficAnalyzer.from_dict(state)
    assert new_a._sigma == 2
    assert len(new_a._new_dev) == 2


def test_save_load_state(analyzer, temp_files):
    """сохранение и загрузка состояния"""
    analyzer.new_device()
    analyzer.anomalies()

    path = os.path.join(temp_files["temp_dir"], "state.json")
    analyzer.save_state(path)

    a2 = TrafficAnalyzer()
    a2.load_state(path)
    assert len(a2._new_dev) == len(analyzer._new_dev)


def test_report(analyzer, temp_files):
    """генерацич отчета"""
    analyzer.new_device()
    analyzer.anomalies()

    path = os.path.join(temp_files["temp_dir"], "report.json")
    report = analyzer.report(path)
    assert os.path.exists(path)
    assert "suspicious_devices" in report


def test_sigma_property(analyzer):
    """свойство сигма"""
    assert analyzer.sigma == 2
    analyzer.sigma = 5
    assert analyzer.sigma == 5
    with pytest.raises(ValueError):
        analyzer.sigma = -1

