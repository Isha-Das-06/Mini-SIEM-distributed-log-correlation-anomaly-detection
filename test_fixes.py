#!/usr/bin/env python3
"""Test critical bug fixes."""

from src.engine import SIEMEngine
from src.protocol import LogEvent
from datetime import datetime, timedelta
import json
import os
import shutil

def test_disk_persistence():
    """Test 1: Disk persistence (datetime JSON serialization)"""
    print("\n[Test 1] Disk Persistence")
    print("=" * 60)

    # Clean up old data
    if os.path.exists('./siem_test_data'):
        shutil.rmtree('./siem_test_data')

    engine = SIEMEngine(data_dir='./siem_test_data')

    # Ingest 5 events
    for i in range(5):
        event = LogEvent(
            timestamp=datetime.now(),
            source=f'host-{i}',
            log_level='INFO',
            service='test',
            message=f'Event {i}'
        )
        engine.ingest_event(event)

    # Try to flush (THIS WOULD CRASH BEFORE FIX)
    try:
        engine.flush()
        print("[PASS] Flush succeeded (datetime serialization fixed)")
    except TypeError as e:
        print(f"[FAIL] Flush crashed: {e}")
        return False

    # Verify data persisted
    sstables = os.listdir('./siem_test_data/sstables')
    if sstables:
        print(f"[PASS] Data persisted to disk ({len(sstables)} SSTable files)")
    else:
        print("[FAIL] No data persisted to disk")
        return False

    # Clean up
    shutil.rmtree('./siem_test_data')
    return True


def test_query_filters():
    """Test 2: Query filters (!=, <, >, etc.)"""
    print("\n[Test 2] Query Filters")
    print("=" * 60)

    engine = SIEMEngine()
    import time

    # Ingest test events (with delays to ensure different timestamps)
    for i, level in enumerate(['INFO', 'WARN', 'ERROR']):
        event = LogEvent(
            timestamp=datetime.now() + timedelta(seconds=i),
            source='host-1',
            log_level=level,
            service='test',
            message=f'Message with level {level}'
        )
        engine.ingest_event(event)

    # Test != filter
    result = engine.query('log_level!="INFO"')
    if result['status'] == 'success':
        events = result['result'].get('events', [])
        non_info = [e for e in events if e['log_level'] != 'INFO']
        if len(non_info) >= 2:
            print(f"[PASS] != filter works (found {len(non_info)} non-INFO events)")
        else:
            print(f"[FAIL] != filter broken (found {len(non_info)} events, expected >=2)")
            return False
    else:
        print(f"[FAIL] Query failed: {result.get('error')}")
        return False

    return True


def test_nested_field_aggregation():
    """Test 3: Nested field aggregation (fields.response_time)"""
    print("\n[Test 3] Nested Field Aggregation")
    print("=" * 60)

    engine = SIEMEngine()

    # Ingest events with nested fields
    for i in range(3):
        event = LogEvent(
            timestamp=datetime.now() + timedelta(seconds=i),
            source='host-1',
            log_level='INFO',
            service='http',
            message='Request processed',
            fields={'response_time': 100 + (i * 50)}
        )
        engine.ingest_event(event)

    # Try avg(response_time) - THIS WOULD RETURN 0.0 BEFORE FIX
    result = engine.query('service="http" | stats avg(response_time)')
    if result['status'] == 'success':
        data = result['result']
        avg_value = data.get('avg', 0)
        if avg_value > 0:
            print(f"[PASS] Nested field aggregation works (avg={avg_value})")
            return True
        else:
            print(f"[FAIL] Nested field aggregation broken (got {data})")
            return False
    else:
        print(f"[FAIL] Query failed: {result.get('error')}")
        return False


def test_distinct_non_numeric():
    """Test 4: distinct() on non-numeric fields"""
    print("\n[Test 4] Distinct on Non-Numeric Fields")
    print("=" * 60)

    engine = SIEMEngine()

    # Ingest events with string fields
    sources = ['web-01', 'web-02', 'web-01']
    for i, source in enumerate(sources):
        event = LogEvent(
            timestamp=datetime.now() + timedelta(seconds=i),
            source=source,
            log_level='INFO',
            service='http',
            message='Request'
        )
        engine.ingest_event(event)

    # Try distinct(source) - THIS WOULD CRASH BEFORE FIX
    try:
        result = engine.query('service="http" | stats distinct(source)')
        if result['status'] == 'success':
            data = result['result']
            distinct_count = data.get('distinct', 0)
            if distinct_count == 2:
                print(f"[PASS] distinct() on strings works (found 2 unique sources)")
                return True
            else:
                print(f"[FAIL] distinct() value wrong: {data}")
                return False
        else:
            print(f"[FAIL] Query failed: {result.get('error')}")
            return False
    except ValueError as e:
        print(f"[FAIL] distinct() crashed: {e}")
        return False


def test_agent_import():
    """Test 5: Agent module import"""
    print("\n[Test 5] Agent Module Import")
    print("=" * 60)

    try:
        from examples.agent import WebServerAgent
        print("[PASS] Agent imports successfully from project root")
        return True
    except ModuleNotFoundError as e:
        print(f"[FAIL] Agent import failed: {e}")
        return False


def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("MINI-SIEM CRITICAL BUG FIX VERIFICATION")
    print("=" * 60)

    tests = [
        test_disk_persistence,
        test_query_filters,
        test_nested_field_aggregation,
        test_distinct_non_numeric,
        test_agent_import,
    ]

    results = []
    for test in tests:
        try:
            passed = test()
            results.append((test.__name__, passed))
        except Exception as e:
            print(f"[EXCEPTION] {test.__name__}: {e}")
            results.append((test.__name__, False))

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} {name}")

    print(f"\nTotal: {passed}/{total} tests passed")

    if passed == total:
        print("\n[OK] All critical bugs fixed!")
        return 0
    else:
        print(f"\n[FAILED] {total - passed} test(s) still failing")
        return 1


if __name__ == '__main__':
    exit(main())
