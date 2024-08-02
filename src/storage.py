"""
LSM-tree style storage backend for efficient time-range queries.

Architecture:
- MemTable: in-memory buffer for recent writes (sorted by timestamp)
- SSTables (Sorted String Tables): immutable disk files with indexed blocks
- Block-level indexing: O(log B + K) range queries where B=blocks, K=results
- Auto-compaction: merges SSTables to maintain read performance

For this SIEM, we focus on:
- Fast time-range queries (most common pattern in log search)
- Efficient append-only writes (log ingestion)
- Minimal CPU overhead for real-time processing
"""

import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Iterator
from dataclasses import dataclass
from bisect import bisect_left, bisect_right


@dataclass
class IndexEntry:
    """Index entry pointing to a block in an SSTable."""
    timestamp: datetime
    offset: int
    size: int


class MemTable:
    """In-memory buffer for recent writes, sorted by timestamp."""

    def __init__(self, max_size: int = 10000):
        self.data: List[tuple] = []  # [(timestamp, event_dict), ...]
        self.max_size = max_size
        self.size = 0

    def add(self, timestamp: datetime, event: Dict[str, Any]):
        """Add event to MemTable."""
        self.data.append((timestamp, event))
        self.size += 1

    def is_full(self) -> bool:
        return self.size >= self.max_size

    def get_sorted(self) -> List[tuple]:
        """Return data sorted by timestamp."""
        return sorted(self.data, key=lambda x: x[0])

    def clear(self):
        self.data.clear()
        self.size = 0

    def __len__(self) -> int:
        return self.size


class SSTable:
    """Immutable sorted table on disk."""

    def __init__(self, path: str):
        self.path = path
        self.index: List[IndexEntry] = []
        self.load()

    def load(self):
        """Load index from disk."""
        index_path = self.path + '.idx'
        if os.path.exists(index_path):
            with open(index_path, 'r') as f:
                data = json.load(f)
                self.index = [
                    IndexEntry(
                        timestamp=datetime.fromisoformat(entry['timestamp']),
                        offset=entry['offset'],
                        size=entry['size']
                    )
                    for entry in data
                ]

    def save_index(self):
        """Save index to disk."""
        index_path = self.path + '.idx'
        os.makedirs(os.path.dirname(index_path), exist_ok=True)
        with open(index_path, 'w') as f:
            data = [
                {'timestamp': entry.timestamp.isoformat(), 'offset': entry.offset, 'size': entry.size}
                for entry in self.index
            ]
            json.dump(data, f)

    def write(self, entries: List[tuple]):
        """Write sorted entries to disk."""
        os.makedirs(os.path.dirname(self.path), exist_ok=True)

        self.index = []
        with open(self.path, 'w') as f:
            offset = 0
            block_size = 100  # events per block
            block_data = []

            for timestamp, event_dict in entries:
                # Convert datetime to ISO string for JSON serialization
                ts_str = timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp
                block_data.append([ts_str, event_dict])

                if len(block_data) >= block_size:
                    # Write block and update index
                    block_json = json.dumps(block_data)
                    block_bytes = block_json.encode('utf-8')
                    f.write(block_json + '\n')

                    # Parse timestamp for index
                    first_ts = datetime.fromisoformat(block_data[0][0]) if isinstance(block_data[0][0], str) else block_data[0][0]
                    self.index.append(IndexEntry(
                        timestamp=first_ts,
                        offset=offset,
                        size=len(block_bytes)
                    ))
                    offset += len(block_bytes) + 1  # +1 for newline
                    block_data = []

            # Write remaining data
            if block_data:
                block_json = json.dumps(block_data)
                block_bytes = block_json.encode('utf-8')
                f.write(block_json + '\n')
                first_ts = datetime.fromisoformat(block_data[0][0]) if isinstance(block_data[0][0], str) else block_data[0][0]
                self.index.append(IndexEntry(
                    timestamp=first_ts,
                    offset=offset,
                    size=len(block_bytes)
                ))

        self.save_index()

    def range_query(self, start: datetime, end: datetime) -> Iterator[Dict[str, Any]]:
        """Query events within time range."""
        if not os.path.exists(self.path):
            return

        # Find relevant blocks using index
        # bisect_left returns insertion point, but we need to include the block that contains
        # events at the start time, so subtract 1 (the previous block might have matching events)
        start_idx = max(0, bisect_left(self.index, start, key=lambda x: x.timestamp) - 1)
        end_idx = bisect_right(self.index, end, key=lambda x: x.timestamp)

        with open(self.path, 'r') as f:
            for i in range(start_idx, min(end_idx + 1, len(self.index))):
                f.seek(self.index[i].offset)
                block_json = f.readline().strip()
                block_data = json.loads(block_json)

                for timestamp_str, event_dict in block_data:
                    if isinstance(timestamp_str, str):
                        ts = datetime.fromisoformat(timestamp_str)
                    else:
                        ts = timestamp_str

                    if start <= ts <= end:
                        yield event_dict

    def get_all(self) -> Iterator[Dict[str, Any]]:
        """Get all events in SSTable."""
        if not os.path.exists(self.path):
            return

        with open(self.path, 'r') as f:
            for line in f:
                block_data = json.loads(line.strip())
                for _, event_dict in block_data:
                    yield event_dict


class LSMStorage:
    """Log-Structured Merge tree storage engine."""

    def __init__(self, data_dir: str = './siem_data'):
        self.data_dir = data_dir
        self.memtable = MemTable()
        self.sstables: List[SSTable] = []
        os.makedirs(data_dir, exist_ok=True)
        self._load_sstables()

    def _load_sstables(self):
        """Load existing SSTables from disk."""
        sstables_dir = os.path.join(self.data_dir, 'sstables')
        if not os.path.exists(sstables_dir):
            return

        for filename in sorted(os.listdir(sstables_dir)):
            if filename.endswith('.sst'):
                path = os.path.join(sstables_dir, filename)
                self.sstables.append(SSTable(path))

    def write(self, timestamp: datetime, event: Dict[str, Any]):
        """Write event to storage."""
        self.memtable.add(timestamp, event)

        if self.memtable.is_full():
            self._flush_memtable()

    def _flush_memtable(self):
        """Flush MemTable to SSTable on disk."""
        if len(self.memtable) == 0:
            return

        sstable_id = len(self.sstables)
        sstable_path = os.path.join(
            self.data_dir, 'sstables', f'sstable_{sstable_id}.sst'
        )
        sstable = SSTable(sstable_path)
        sstable.write(self.memtable.get_sorted())

        self.sstables.append(sstable)
        self.memtable.clear()

    def range_query(self, start: datetime, end: datetime) -> Iterator[Dict[str, Any]]:
        """Query events within time range."""
        seen = set()

        # Query MemTable first (most recent)
        for ts, event in self.memtable.get_sorted():
            if start <= ts <= end:
                event_id = (event['source'], event['timestamp'])
                if event_id not in seen:
                    seen.add(event_id)
                    yield event

        # Query SSTables (newest first)
        for sstable in reversed(self.sstables):
            for event in sstable.range_query(start, end):
                event_id = (event['source'], event['timestamp'])
                if event_id not in seen:
                    seen.add(event_id)
                    yield event

    def get_all(self) -> Iterator[Dict[str, Any]]:
        """Get all events."""
        seen = set()

        # MemTable first
        for ts, event in self.memtable.get_sorted():
            event_id = (event['source'], event['timestamp'])
            if event_id not in seen:
                seen.add(event_id)
                yield event

        # SSTables
        for sstable in reversed(self.sstables):
            for event in sstable.get_all():
                event_id = (event['source'], event['timestamp'])
                if event_id not in seen:
                    seen.add(event_id)
                    yield event

    def compact(self):
        """Merge SSTables (simple single-pass compaction)."""
        if len(self.sstables) < 2:
            return

        self._flush_memtable()

        # Merge all SSTables
        merged_entries = []
        old_sstables = self.sstables  # Save reference before loop
        for old_sstable in old_sstables:
            for event in old_sstable.get_all():
                ts_val = event['timestamp']
                if isinstance(ts_val, str):
                    ts = datetime.fromisoformat(ts_val)
                else:
                    ts = ts_val
                merged_entries.append((ts, event))

        merged_entries.sort(key=lambda x: x[0])

        # Write single merged SSTable
        merged_path = os.path.join(
            self.data_dir, 'sstables', f'sstable_merged.sst'
        )
        merged_sstable = SSTable(merged_path)
        merged_sstable.write(merged_entries)

        # Cleanup old SSTables
        for old_sstable in old_sstables:
            try:
                os.remove(old_sstable.path)
                os.remove(old_sstable.path + '.idx')
            except:
                pass

        self.sstables = [merged_sstable]

    def flush(self):
        """Flush MemTable to disk."""
        self._flush_memtable()
