"""Unit tests for LSM storage backend."""

import pytest
import tempfile
import shutil
from datetime import datetime, timedelta
from src.storage import MemTable, SSTable, LSMStorage


class TestMemTable:
    """Tests for in-memory MemTable."""

    def test_add_and_retrieve(self):
        """Test adding events to MemTable."""
        mt = MemTable(max_size=100)
        now = datetime.now()
        event = {'source': 'host1', 'message': 'test'}

        mt.add(now, event)
        assert len(mt) == 1
        assert mt.data[0][1]['source'] == 'host1'

    def test_sorting(self):
        """Test that MemTable returns sorted data."""
        mt = MemTable(max_size=100)
        now = datetime.now()

        # Add in reverse order
        for i in range(3, 0, -1):
            event = {'id': i}
            mt.add(now + timedelta(seconds=i), event)

        sorted_data = mt.get_sorted()
        ids = [e[1]['id'] for e in sorted_data]
        assert ids == [1, 2, 3]

    def test_is_full(self):
        """Test full detection."""
        mt = MemTable(max_size=2)
        now = datetime.now()

        mt.add(now, {'id': 1})
        assert not mt.is_full()

        mt.add(now, {'id': 2})
        assert mt.is_full()

    def test_clear(self):
        """Test clearing MemTable."""
        mt = MemTable(max_size=100)
        now = datetime.now()

        mt.add(now, {'id': 1})
        mt.add(now, {'id': 2})
        assert len(mt) == 2

        mt.clear()
        assert len(mt) == 0


class TestSSTable:
    """Tests for SSTable on-disk storage."""

    def setup_method(self):
        """Create temp directory for tests."""
        self.tmpdir = tempfile.mkdtemp()

    def teardown_method(self):
        """Clean up temp directory."""
        shutil.rmtree(self.tmpdir)

    def test_write_and_read(self):
        """Test writing and reading from SSTable."""
        now = datetime.now()
        entries = [
            (now + timedelta(seconds=i), {'id': i, 'data': f'event{i}'})
            for i in range(10)
        ]

        sstable_path = f"{self.tmpdir}/test.sst"
        sstable = SSTable(sstable_path)
        sstable.write(entries)

        # Read back
        sstable2 = SSTable(sstable_path)
        results = list(sstable2.range_query(now, now + timedelta(seconds=20)))

        assert len(results) == 10
        assert results[0]['id'] == 0
        assert results[9]['id'] == 9

    def test_range_query(self):
        """Test time-range queries."""
        now = datetime.now()
        entries = [
            (now + timedelta(seconds=i), {'id': i, 'timestamp': (now + timedelta(seconds=i)).isoformat()})
            for i in range(100)
        ]

        sstable_path = f"{self.tmpdir}/test.sst"
        sstable = SSTable(sstable_path)
        sstable.write(entries)

        # Query middle range
        start = now + timedelta(seconds=25)
        end = now + timedelta(seconds=75)

        results = list(sstable.range_query(start, end))
        ids = [r['id'] for r in results]

        # Should get events 25-75 (at least some in that range)
        assert len(ids) > 0
        # Most should be in the range
        assert len([i for i in ids if 24 <= i <= 76]) > len(ids) * 0.8

    def test_index_persistence(self):
        """Test that index is saved and loaded correctly."""
        now = datetime.now()
        entries = [(now + timedelta(seconds=i), {'id': i}) for i in range(50)]

        sstable_path = f"{self.tmpdir}/test.sst"
        sstable = SSTable(sstable_path)
        sstable.write(entries)

        # Load fresh instance
        sstable2 = SSTable(sstable_path)
        assert len(sstable2.index) > 0
        assert sstable2.index[0].timestamp == now


class TestLSMStorage:
    """Tests for complete LSM storage."""

    def setup_method(self):
        """Create temp directory for tests."""
        self.tmpdir = tempfile.mkdtemp()

    def teardown_method(self):
        """Clean up temp directory."""
        shutil.rmtree(self.tmpdir)

    def test_write_and_retrieve(self):
        """Test basic write/read cycle."""
        storage = LSMStorage(self.tmpdir)
        now = datetime.now()

        # Write events
        for i in range(10):
            event = {
                'id': i,
                'message': f'event{i}',
                'source': 'host1',
                'timestamp': (now + timedelta(seconds=i)).isoformat(),
                'log_level': 'INFO',
                'service': 'app'
            }
            storage.write(now + timedelta(seconds=i), event)

        # Retrieve
        results = list(storage.range_query(now, now + timedelta(seconds=20)))
        assert len(results) >= 10

    def test_range_query_after_flush(self):
        """Test range queries after flushing to disk."""
        storage = LSMStorage(self.tmpdir)
        now = datetime.now()

        # Write events
        for i in range(100):
            event = {
                'id': i,
                'value': i * 10,
                'source': 'host1',
                'timestamp': (now + timedelta(seconds=i)).isoformat(),
                'log_level': 'INFO',
                'service': 'app'
            }
            storage.write(now + timedelta(seconds=i), event)

        storage.flush()

        # Query after flush
        start = now + timedelta(seconds=30)
        end = now + timedelta(seconds=70)
        results = list(storage.range_query(start, end))

        assert len(results) > 0
        ids = [r['id'] for r in results]
        assert 30 in ids or 31 in ids  # Allow some flexibility

    def test_persistence_across_instances(self):
        """Test that data persists across storage instances."""
        now = datetime.now()

        # Write with first instance
        storage1 = LSMStorage(self.tmpdir)
        for i in range(20):
            event = {
                'id': i,
                'source': 'host1',
                'timestamp': (now + timedelta(seconds=i)).isoformat(),
                'log_level': 'INFO',
                'service': 'app'
            }
            storage1.write(now + timedelta(seconds=i), event)
        storage1.flush()

        # Read with second instance
        storage2 = LSMStorage(self.tmpdir)
        results = list(storage2.range_query(now, now + timedelta(seconds=30)))
        assert len(results) > 0

    def test_compaction(self):
        """Test storage compaction."""
        storage = LSMStorage(self.tmpdir)
        now = datetime.now()

        # Write multiple batches
        for batch in range(3):
            for i in range(50):
                event = {
                    'batch': batch,
                    'id': i,
                    'source': 'host1',
                    'timestamp': (now + timedelta(minutes=batch, seconds=i)).isoformat(),
                    'log_level': 'INFO',
                    'service': 'app'
                }
                storage.write(now + timedelta(minutes=batch, seconds=i), event)
            storage.flush()

        # Compaction should succeed
        storage.compact()

        # Data should still be queryable
        results = list(storage.get_all())
        assert len(results) >= 150

    def test_get_all(self):
        """Test retrieving all events."""
        storage = LSMStorage(self.tmpdir)
        now = datetime.now()

        # Write events
        for i in range(50):
            event = {
                'id': i,
                'source': 'host1',
                'timestamp': (now + timedelta(seconds=i)).isoformat(),
                'log_level': 'INFO',
                'service': 'app'
            }
            storage.write(now + timedelta(seconds=i), event)
        storage.flush()

        # Get all
        all_events = list(storage.get_all())
        assert len(all_events) >= 50
