"""
Query DSL inspired by Splunk SPL and Elastic KQL.

Supports:
- source="value" field matching
- time range queries (earliest, latest)
- field extraction and statistics
- filtering and aggregation

Examples:
  service="auth" log_level="ERROR" | stats count by source
  source="db*" message="*failed*" | stats count by log_level
  earliest=2024-01-01T00:00:00 latest=2024-01-02T00:00:00 | stats avg(response_time) by service
"""

from datetime import datetime
from typing import Dict, List, Any, Optional, Iterator
import re


class QueryFilter:
    """Represents a filter condition."""

    def __init__(self, field: str, operator: str, value: Any):
        self.field = field
        self.operator = operator
        self.value = value

    def matches(self, event: Dict[str, Any]) -> bool:
        """Check if event matches filter."""
        event_value = event.get(self.field)

        if self.operator == '=':
            return self._match_wildcard(str(event_value), str(self.value))
        elif self.operator == '!=':
            return not self._match_wildcard(str(event_value), str(self.value))
        elif self.operator == '<':
            return float(event_value or 0) < float(self.value)
        elif self.operator == '>':
            return float(event_value or 0) > float(self.value)
        elif self.operator == '<=':
            return float(event_value or 0) <= float(self.value)
        elif self.operator == '>=':
            return float(event_value or 0) >= float(self.value)
        elif self.operator == 'contains':
            return str(self.value).lower() in str(event_value).lower()
        elif self.operator == 'starts_with':
            return str(event_value).startswith(str(self.value))

        return False

    @staticmethod
    def _match_wildcard(text: str, pattern: str) -> bool:
        """Match with wildcard support (* = any chars)."""
        pattern = pattern.replace('*', '.*')
        return re.fullmatch(pattern, text) is not None


class QueryAggregation:
    """Represents aggregation (stats) operation."""

    def __init__(self, func: str, field: Optional[str] = None, group_by: Optional[List[str]] = None):
        self.func = func.lower()
        self.field = field
        self.group_by = group_by or []

    def aggregate(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate events."""
        if not events:
            return {}

        if self.group_by:
            return self._group_aggregate(events)
        else:
            return self._simple_aggregate(events)

    def _simple_aggregate(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Simple aggregation without grouping."""
        if self.func == 'count':
            return {self.func: len(events)}
        elif self.func == 'distinct':
            # For distinct, don't convert to float - just count unique values
            unique_vals = set()
            for e in events:
                if self.field:
                    val = e.get(self.field) or e.get('fields', {}).get(self.field)
                    if val is not None:
                        unique_vals.add(str(val))
            return {self.func: len(unique_vals)}

        # For numeric functions, extract and convert values
        values = []
        for e in events:
            if self.field:
                # Try direct field first, then nested in 'fields'
                val = e.get(self.field)
                if val is None:
                    val = e.get('fields', {}).get(self.field)
                if val is not None:
                    try:
                        values.append(float(val))
                    except (ValueError, TypeError):
                        pass

        if not values:
            return {self.func: 0.0}

        if self.func == 'sum':
            return {self.func: sum(values)}
        elif self.func == 'avg':
            return {self.func: sum(values) / len(values) if values else 0}
        elif self.func == 'min':
            return {self.func: min(values) if values else 0}
        elif self.func == 'max':
            return {self.func: max(values) if values else 0}

        return {}

    def _group_aggregate(self, events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Aggregation with grouping."""
        groups: Dict[str, List[Dict[str, Any]]] = {}

        for event in events:
            key_parts = [str(event.get(field, 'unknown')) for field in self.group_by]
            key = ' | '.join(key_parts)

            if key not in groups:
                groups[key] = []
            groups[key].append(event)

        results = []
        for key, group_events in groups.items():
            row = {}
            key_parts = key.split(' | ')
            for i, field in enumerate(self.group_by):
                row[field] = key_parts[i] if i < len(key_parts) else 'unknown'

            if self.func == 'count':
                row['count'] = len(group_events)
            elif self.func == 'distinct':
                unique_vals = set()
                for e in group_events:
                    if self.field:
                        val = e.get(self.field) or e.get('fields', {}).get(self.field)
                        if val is not None:
                            unique_vals.add(str(val))
                row['distinct'] = len(unique_vals)
            else:
                # Numeric aggregations
                values = []
                for e in group_events:
                    if self.field:
                        val = e.get(self.field)
                        if val is None:
                            val = e.get('fields', {}).get(self.field)
                        if val is not None:
                            try:
                                values.append(float(val))
                            except (ValueError, TypeError):
                                pass

                if self.func == 'sum':
                    row['sum'] = sum(values) if values else 0
                elif self.func == 'avg':
                    row['avg'] = sum(values) / len(values) if values else 0
                elif self.func == 'min':
                    row['min'] = min(values) if values else 0
                elif self.func == 'max':
                    row['max'] = max(values) if values else 0

            results.append(row)

        return {'results': results}


class QueryParser:
    """Parses query DSL strings."""

    @staticmethod
    def parse(query: str) -> tuple[List[QueryFilter], Optional[tuple[datetime, datetime]], Optional[QueryAggregation]]:
        """
        Parse query string.
        Returns (filters, time_range, aggregation)
        """
        filters = []
        time_range = None
        aggregation = None

        # Split on pipe
        parts = query.split('|')
        main_part = parts[0].strip()

        # Parse time range
        earliest_match = re.search(r'earliest=([^\s]+)', main_part)
        latest_match = re.search(r'latest=([^\s]+)', main_part)

        if earliest_match and latest_match:
            try:
                earliest = datetime.fromisoformat(earliest_match.group(1))
                latest = datetime.fromisoformat(latest_match.group(1))
                time_range = (earliest, latest)
            except:
                pass

        # Parse filters: support !=, <=, >=, <, >, contains, starts_with, =
        # Match operators in order of precedence (longest first)
        filter_patterns = [
            (r'(\w+)!=(["\']?)([^\s"\'\|]+)\2', '!='),
            (r'(\w+)<=(["\']?)([^\s"\'\|]+)\2', '<='),
            (r'(\w+)>=(["\']?)([^\s"\'\|]+)\2', '>='),
            (r'(\w+)<(["\']?)([^\s"\'\|]+)\2', '<'),
            (r'(\w+)>(["\']?)([^\s"\'\|]+)\2', '>'),
            (r'(\w+)\s+contains\s+(["\']?)([^\s"\'\|]+)\2', 'contains'),
            (r'(\w+)\s+starts_with\s+(["\']?)([^\s"\'\|]+)\2', 'starts_with'),
            (r'(\w+)=(["\']?)([^\s"\'\|]+)\2', '='),
        ]

        for pattern, op in filter_patterns:
            for match in re.finditer(pattern, main_part):
                field = match.group(1)
                if field not in ['earliest', 'latest']:
                    value = match.group(3)
                    filters.append(QueryFilter(field, op, value))

        # Parse aggregation (stats command)
        if len(parts) > 1:
            stats_part = parts[1].strip()
            if stats_part.startswith('stats'):
                aggregation = QueryParser._parse_stats(stats_part)

        return filters, time_range, aggregation

    @staticmethod
    def _parse_stats(stats_part: str) -> Optional[QueryAggregation]:
        """Parse stats command. Supports: count, sum(field), avg(field), etc."""
        # Format: stats count | stats sum(field) | stats count by field1, field2
        # Note: Only parses first stat. Multiple stats not yet supported.
        # Match first stat function and field, then extract "by" clause

        # Remove 'stats ' prefix
        if not stats_part.startswith('stats'):
            return None
        stats_part = stats_part[5:].strip()

        # Look for "by" to separate aggregation from grouping
        by_pos = stats_part.rfind(' by ')
        if by_pos != -1:
            agg_part = stats_part[:by_pos].strip()
            group_part = stats_part[by_pos+4:].strip()
            group_by = [f.strip() for f in group_part.split(',')]
        else:
            agg_part = stats_part
            group_by = None

        # Parse first aggregation function
        match = re.match(r'(\w+)(?:\((\w+)\))?', agg_part)
        if not match:
            return None

        func = match.group(1)
        field = match.group(2)

        # Validate function name
        valid_funcs = {'count', 'sum', 'avg', 'min', 'max', 'distinct'}
        if func.lower() not in valid_funcs:
            return None

        return QueryAggregation(func, field, group_by)


class QueryEngine:
    """Executes queries on event streams."""

    def __init__(self, storage):
        self.storage = storage

    def execute(self, query: str) -> Dict[str, Any]:
        """Execute query and return results."""
        filters, time_range, aggregation = QueryParser.parse(query)

        # Fetch events
        if time_range:
            events = list(self.storage.range_query(time_range[0], time_range[1]))
        else:
            events = list(self.storage.get_all())

        # Apply filters
        for filter_obj in filters:
            events = [e for e in events if filter_obj.matches(e)]

        # Aggregate if requested
        if aggregation:
            result = aggregation.aggregate(events)
        else:
            result = {'events': events, 'count': len(events)}

        return result
