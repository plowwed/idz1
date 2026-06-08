"""модуль для запуска программы"""

from traffic_analyzer import TrafficAnalyzer

analyzer = TrafficAnalyzer(baseline="baseline.json",current="current.json",sigma=3)
analyzer.load_data()
print(f"baseline: {len(analyzer.baseline_all)}")
print(f"current: {len(analyzer.current_all)}")

new_devices = analyzer.new_device()
print(f"новые устройства: {len(new_devices)}")

missing_devices = analyzer.missing_device()
print(f"пропавшие устройства: {len(missing_devices)}")

suspicious = analyzer.anomalies()
print(f"подозрительные устройства: {len(suspicious)}")
print(f"μ: {analyzer._mean:.2f}")
print(f"σ: {analyzer._std:.2f}")
print(f"μ + 3σ: {analyzer._threshold:.2f}")

analyzer.save_state("analyzer_state.json")

report = analyzer.report("report.json")

analyzer2 = TrafficAnalyzer()
analyzer2.load_state("analyzer_state.json")
print(f"новые устройства: {len(analyzer2._new_dev)}")
print(f"подозрительные: {len(analyzer2._suspicious_dev)}")
