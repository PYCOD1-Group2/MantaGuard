#!/usr/bin/env python3
"""
Training repository database management for MantaGuard.

This module provides functionality to manage training data, labels, and
connection metadata in a structured database format.
"""

import sqlite3
import json
import pandas as pd
import numpy as np
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

from mantaguard.utils.logger import get_logger
from mantaguard.utils.file_utils import safe_create_directory

logger = get_logger(__name__)


class ReviewStatus(Enum):
    """Review status for training connections."""
    PENDING = "pending"
    REVIEWED = "reviewed" 
    NEEDS_REVIEW = "needs_review"
    VERIFIED = "verified"


class ConfidenceLevel(Enum):
    """Confidence levels for labels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class TrainingConnection:
    """Data class representing a training connection."""
    uid: str
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: Optional[int]
    dest_port: Optional[int]
    proto: str
    service: Optional[str]
    duration: Optional[float]
    orig_bytes: Optional[int]
    resp_bytes: Optional[int]
    orig_pkts: Optional[int]
    resp_pkts: Optional[int]
    history: Optional[str]
    feature_vector: Optional[np.ndarray]
    anomaly_score: Optional[float]
    is_anomaly: bool
    label_category: Optional[str]
    label_subcategory: Optional[str]
    confidence_level: Optional[ConfidenceLevel]
    labeled_by: Optional[str]
    labeled_at: Optional[datetime]
    training_source: str
    review_status: ReviewStatus = ReviewStatus.PENDING
    notes: Optional[str] = None
    has_extracted_pcap: bool = False


@dataclass
class LabelDefinition:
    """Data class representing a label definition."""
    category: str
    subcategory: str
    description: str
    color_hex: str
    is_active: bool = True
    created_at: Optional[datetime] = None


class TrainingRepository:
    """Manages the training data repository database."""
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the training repository.
        
        Args:
            db_path: Path to SQLite database file
        """
        if db_path is None:
            project_root = Path(__file__).parent.parent.parent.parent
            self.db_path = project_root / "data" / "training_repository.db"
        else:
            self.db_path = Path(db_path)
            
        # Ensure directory exists
        safe_create_directory(self.db_path.parent)
        
        # Initialize database
        self._init_database()
        self._run_migrations()
        self._populate_default_labels()
    
    def _init_database(self) -> None:
        """Initialize the database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript('''
                -- Training connections table
                CREATE TABLE IF NOT EXISTS training_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    uid TEXT UNIQUE NOT NULL,
                    timestamp DATETIME NOT NULL,
                    source_ip TEXT NOT NULL,
                    dest_ip TEXT NOT NULL,
                    source_port INTEGER,
                    dest_port INTEGER,
                    proto TEXT NOT NULL,
                    service TEXT,
                    duration REAL,
                    orig_bytes INTEGER,
                    resp_bytes INTEGER,
                    orig_pkts INTEGER,
                    resp_pkts INTEGER,
                    history TEXT,
                    feature_vector TEXT,  -- JSON serialized numpy array
                    anomaly_score REAL,
                    is_anomaly BOOLEAN NOT NULL DEFAULT 0,
                    label_category TEXT,
                    label_subcategory TEXT,
                    confidence_level TEXT,
                    labeled_by TEXT,
                    labeled_at DATETIME,
                    training_source TEXT NOT NULL,
                    review_status TEXT DEFAULT 'pending',
                    notes TEXT,
                    has_extracted_pcap BOOLEAN DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                
                -- Label definitions table
                CREATE TABLE IF NOT EXISTS label_definitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    subcategory TEXT NOT NULL,
                    description TEXT NOT NULL,
                    color_hex TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(category, subcategory)
                );
                
                -- Training sessions table
                CREATE TABLE IF NOT EXISTS training_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_name TEXT NOT NULL,
                    model_version TEXT,
                    training_data_count INTEGER,
                    accuracy_score REAL,
                    precision_score REAL,
                    recall_score REAL,
                    f1_score REAL,
                    confusion_matrix TEXT,  -- JSON serialized
                    started_at DATETIME,
                    completed_at DATETIME,
                    notes TEXT
                );
                
                -- Indexes for performance
                CREATE INDEX IF NOT EXISTS idx_connections_timestamp ON training_connections(timestamp);
                CREATE INDEX IF NOT EXISTS idx_connections_label ON training_connections(label_category, label_subcategory);
                CREATE INDEX IF NOT EXISTS idx_connections_source ON training_connections(training_source);
                CREATE INDEX IF NOT EXISTS idx_connections_review ON training_connections(review_status);
                CREATE INDEX IF NOT EXISTS idx_connections_anomaly ON training_connections(is_anomaly);
                
                -- Triggers for updated_at
                CREATE TRIGGER IF NOT EXISTS update_training_connections_timestamp 
                    AFTER UPDATE ON training_connections
                    FOR EACH ROW
                BEGIN
                    UPDATE training_connections 
                    SET updated_at = CURRENT_TIMESTAMP 
                    WHERE id = NEW.id;
                END;
            ''')
            conn.commit()
    
    def _run_migrations(self) -> None:
        """Run database migrations for schema updates."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Check if has_extracted_pcap column exists
            cursor.execute("PRAGMA table_info(training_connections)")
            columns = [row[1] for row in cursor.fetchall()]
            
            if 'has_extracted_pcap' not in columns:
                # Add the column
                cursor.execute('ALTER TABLE training_connections ADD COLUMN has_extracted_pcap BOOLEAN DEFAULT 0')
                logger.info("Added has_extracted_pcap column to training_connections table")
            
            conn.commit()
    
    def _populate_default_labels(self) -> None:
        """Populate default label definitions."""
        default_labels = [
            # Reconnaissance
            ('reconnaissance', 'port-scan', 'Port scanning activity', '#FF6B6B'),
            ('reconnaissance', 'host-discovery', 'Network host discovery', '#FF8E8E'),
            ('reconnaissance', 'service-enumeration', 'Service enumeration attempts', '#FFB3B3'),
            
            # Exploitation
            ('exploitation', 'brute-force-attack', 'Brute force login attempts', '#4ECDC4'),
            ('exploitation', 'buffer-overflow', 'Buffer overflow exploitation', '#45B7B8'),
            ('exploitation', 'privilege-escalation', 'Privilege escalation attempts', '#26D0CE'),
            
            # Persistence
            ('persistence', 'backdoor', 'Backdoor installation', '#FFE66D'),
            ('persistence', 'lateral-movement', 'Lateral network movement', '#FFD93D'),
            ('persistence', 'data-exfiltration', 'Data exfiltration activity', '#FFCC02'),
            
            # Denial of Service
            ('denial-of-service', 'ddos-attack', 'Distributed denial of service', '#A8E6CF'),
            ('denial-of-service', 'resource-exhaustion', 'Resource exhaustion attacks', '#7FCDCD'),
            
            # Malware
            ('malware', 'c2-communication', 'Command and control communication', '#B19CD9'),
            ('malware', 'malware-download', 'Malware download activity', '#C7A2FF'),
            ('malware', 'infected-host', 'Infected host behavior', '#DDA0DD'),
            
            # Unknown/Suspicious
            ('unknown', 'unknown', 'Uncategorized anomalous activity', '#95A5A6'),
            ('unknown', 'suspicious', 'Suspicious but unclassified activity', '#7F8C8D'),
            
            # Normal/Benign
            ('normal', 'benign', 'Normal network activity', '#2ECC71'),
            ('normal', 'maintenance', 'Maintenance activity', '#27AE60'),
        ]
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for category, subcategory, description, color in default_labels:
                cursor.execute('''
                    INSERT OR IGNORE INTO label_definitions 
                    (category, subcategory, description, color_hex)
                    VALUES (?, ?, ?, ?)
                ''', (category, subcategory, description, color))
            conn.commit()
    
    def add_connection(self, connection: TrainingConnection) -> int:
        """
        Add a new training connection to the repository.
        
        Args:
            connection: TrainingConnection object
            
        Returns:
            Database ID of the inserted connection
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Serialize feature vector if present
            feature_vector_json = None
            if connection.feature_vector is not None:
                feature_vector_json = json.dumps(connection.feature_vector.tolist())
            
            cursor.execute('''
                INSERT OR REPLACE INTO training_connections (
                    uid, timestamp, source_ip, dest_ip, source_port, dest_port,
                    proto, service, duration, orig_bytes, resp_bytes, orig_pkts,
                    resp_pkts, history, feature_vector, anomaly_score, is_anomaly,
                    label_category, label_subcategory, confidence_level, labeled_by,
                    labeled_at, training_source, review_status, notes, has_extracted_pcap
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                connection.uid,
                connection.timestamp,
                connection.source_ip,
                connection.dest_ip,
                connection.source_port,
                connection.dest_port,
                connection.proto,
                connection.service,
                connection.duration,
                connection.orig_bytes,
                connection.resp_bytes,
                connection.orig_pkts,
                connection.resp_pkts,
                connection.history,
                feature_vector_json,
                connection.anomaly_score,
                connection.is_anomaly,
                connection.label_category,
                connection.label_subcategory,
                connection.confidence_level.value if connection.confidence_level else None,
                connection.labeled_by,
                connection.labeled_at,
                connection.training_source,
                connection.review_status.value,
                connection.notes,
                connection.has_extracted_pcap
            ))
            
            return cursor.lastrowid
    
    def get_connections(
        self, 
        limit: int = 100,
        offset: int = 0,
        filter_params: Optional[Dict] = None
    ) -> List[TrainingConnection]:
        """
        Retrieve training connections with optional filtering.
        
        Args:
            limit: Maximum number of connections to return
            offset: Number of connections to skip
            filter_params: Dictionary of filter parameters
            
        Returns:
            List of TrainingConnection objects
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Build query with filters
            base_query = '''
                SELECT * FROM training_connections
                WHERE 1=1
            '''
            params = []
            
            if filter_params:
                if filter_params.get('is_anomaly') is not None:
                    base_query += ' AND is_anomaly = ?'
                    params.append(filter_params['is_anomaly'])
                
                if filter_params.get('label_category'):
                    base_query += ' AND label_category = ?'
                    params.append(filter_params['label_category'])
                
                if filter_params.get('review_status'):
                    base_query += ' AND review_status = ?'
                    params.append(filter_params['review_status'])
                
                if filter_params.get('training_source'):
                    base_query += ' AND training_source = ?'
                    params.append(filter_params['training_source'])
                
                if filter_params.get('start_date'):
                    base_query += ' AND timestamp >= ?'
                    params.append(filter_params['start_date'])
                
                if filter_params.get('end_date'):
                    base_query += ' AND timestamp <= ?'
                    params.append(filter_params['end_date'])
            
            base_query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            
            cursor = conn.cursor()
            cursor.execute(base_query, params)
            rows = cursor.fetchall()
            
            connections = []
            for row in rows:
                # Deserialize feature vector
                feature_vector = None
                if row['feature_vector']:
                    try:
                        feature_vector = np.array(json.loads(row['feature_vector']))
                    except Exception as e:
                        logger.warning(f"Failed to deserialize feature vector for UID {row['uid']}: {e}")
                
                # Parse datetime fields
                timestamp = datetime.fromisoformat(row['timestamp']) if row['timestamp'] else None
                labeled_at = datetime.fromisoformat(row['labeled_at']) if row['labeled_at'] else None
                
                connection = TrainingConnection(
                    uid=row['uid'],
                    timestamp=timestamp,
                    source_ip=row['source_ip'],
                    dest_ip=row['dest_ip'],
                    source_port=row['source_port'],
                    dest_port=row['dest_port'],
                    proto=row['proto'],
                    service=row['service'],
                    duration=row['duration'],
                    orig_bytes=row['orig_bytes'],
                    resp_bytes=row['resp_bytes'],
                    orig_pkts=row['orig_pkts'],
                    resp_pkts=row['resp_pkts'],
                    history=row['history'],
                    feature_vector=feature_vector,
                    anomaly_score=row['anomaly_score'],
                    is_anomaly=bool(row['is_anomaly']),
                    label_category=row['label_category'],
                    label_subcategory=row['label_subcategory'],
                    confidence_level=ConfidenceLevel(row['confidence_level']) if row['confidence_level'] else None,
                    labeled_by=row['labeled_by'],
                    labeled_at=labeled_at,
                    training_source=row['training_source'],
                    review_status=ReviewStatus(row['review_status']) if row['review_status'] else ReviewStatus.PENDING,
                    notes=row['notes'],
                    has_extracted_pcap=bool(row['has_extracted_pcap']) if 'has_extracted_pcap' in row.keys() else False
                )
                connections.append(connection)
            
            return connections
    
    def update_labels(
        self, 
        uids: List[str], 
        category: str, 
        subcategory: str,
        confidence: ConfidenceLevel,
        labeled_by: str,
        notes: Optional[str] = None
    ) -> int:
        """
        Update labels for multiple connections.
        
        Args:
            uids: List of connection UIDs to update
            category: Label category
            subcategory: Label subcategory
            confidence: Confidence level
            labeled_by: Username of person labeling
            notes: Optional notes
            
        Returns:
            Number of connections updated
        """
        if not uids:
            return 0
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            placeholders = ','.join(['?' for _ in uids])
            query = f'''
                UPDATE training_connections 
                SET label_category = ?, 
                    label_subcategory = ?,
                    confidence_level = ?,
                    labeled_by = ?,
                    labeled_at = ?,
                    review_status = ?,
                    notes = ?
                WHERE uid IN ({placeholders})
            '''
            
            params = [
                category, subcategory, confidence.value, labeled_by, 
                datetime.now(), ReviewStatus.REVIEWED.value, notes
            ] + uids
            
            cursor.execute(query, params)
            return cursor.rowcount
    
    def update_extraction_status(self, uid: str, has_extracted: bool) -> bool:
        """
        Update PCAP extraction status for a connection.
        
        Args:
            uid: Connection UID
            has_extracted: Whether PCAP has been extracted
            
        Returns:
            True if update was successful
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE training_connections SET has_extracted_pcap = ? WHERE uid = ?',
                (has_extracted, uid)
            )
            return cursor.rowcount > 0
    
    def delete_connections(self, uids: List[str]) -> int:
        """
        Delete connections from the training repository.
        
        Args:
            uids: List of connection UIDs to delete
            
        Returns:
            Number of connections deleted
        """
        if not uids:
            return 0
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            placeholders = ','.join(['?' for _ in uids])
            query = f'DELETE FROM training_connections WHERE uid IN ({placeholders})'
            
            cursor.execute(query, uids)
            deleted_count = cursor.rowcount
            
            logger.info(f"Deleted {deleted_count} connections from training repository")
            return deleted_count
    
    def delete_connection(self, uid: str) -> bool:
        """
        Delete a single connection from the training repository.
        
        Args:
            uid: Connection UID to delete
            
        Returns:
            True if connection was deleted, False if not found
        """
        return self.delete_connections([uid]) > 0
    
    def get_label_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about labels in the training repository.
        
        Returns:
            Dictionary containing label statistics
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Overall statistics
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_connections,
                    SUM(CASE WHEN is_anomaly THEN 1 ELSE 0 END) as anomaly_count,
                    SUM(CASE WHEN label_category IS NOT NULL THEN 1 ELSE 0 END) as labeled_count,
                    SUM(CASE WHEN review_status = 'verified' THEN 1 ELSE 0 END) as verified_count
                FROM training_connections
            ''')
            overall_stats = dict(cursor.fetchone())
            
            # Label distribution
            cursor.execute('''
                SELECT label_category, label_subcategory, COUNT(*) as count
                FROM training_connections
                WHERE label_category IS NOT NULL
                GROUP BY label_category, label_subcategory
                ORDER BY count DESC
            ''')
            label_distribution = [dict(row) for row in cursor.fetchall()]
            
            # Training source breakdown
            cursor.execute('''
                SELECT training_source, COUNT(*) as count
                FROM training_connections
                GROUP BY training_source
                ORDER BY count DESC
            ''')
            source_breakdown = [dict(row) for row in cursor.fetchall()]
            
            # Review status breakdown
            cursor.execute('''
                SELECT review_status, COUNT(*) as count
                FROM training_connections
                GROUP BY review_status
                ORDER BY count DESC
            ''')
            review_breakdown = [dict(row) for row in cursor.fetchall()]
            
            return {
                'overall': overall_stats,
                'label_distribution': label_distribution,
                'source_breakdown': source_breakdown,
                'review_breakdown': review_breakdown
            }
    
    def get_label_definitions(self, active_only: bool = True) -> List[LabelDefinition]:
        """
        Get all label definitions.
        
        Args:
            active_only: If True, only return active labels
            
        Returns:
            List of LabelDefinition objects
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = 'SELECT * FROM label_definitions'
            if active_only:
                query += ' WHERE is_active = 1'
            query += ' ORDER BY category, subcategory'
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            definitions = []
            for row in rows:
                created_at = datetime.fromisoformat(row['created_at']) if row['created_at'] else None
                definition = LabelDefinition(
                    category=row['category'],
                    subcategory=row['subcategory'],
                    description=row['description'],
                    color_hex=row['color_hex'],
                    is_active=bool(row['is_active']),
                    created_at=created_at
                )
                definitions.append(definition)
            
            return definitions
    
    def add_label_definition(self, definition: LabelDefinition) -> None:
        """
        Add a new label definition.
        
        Args:
            definition: LabelDefinition object
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO label_definitions 
                (category, subcategory, description, color_hex, is_active)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                definition.category,
                definition.subcategory,
                definition.description,
                definition.color_hex,
                definition.is_active
            ))
            conn.commit()
    
    def export_training_data(self, file_path: str, format: str = 'csv') -> None:
        """
        Export training data to file.
        
        Args:
            file_path: Output file path
            format: Export format ('csv' or 'json')
        """
        connections = self.get_connections(limit=100000)  # Get all connections
        
        if format.lower() == 'csv':
            df_data = []
            for conn in connections:
                row = {
                    'uid': conn.uid,
                    'timestamp': conn.timestamp,
                    'source_ip': conn.source_ip,
                    'dest_ip': conn.dest_ip,
                    'proto': conn.proto,
                    'service': conn.service,
                    'anomaly_score': conn.anomaly_score,
                    'is_anomaly': conn.is_anomaly,
                    'label_category': conn.label_category,
                    'label_subcategory': conn.label_subcategory,
                    'confidence_level': conn.confidence_level.value if conn.confidence_level else None,
                    'training_source': conn.training_source,
                    'review_status': conn.review_status.value
                }
                df_data.append(row)
            
            df = pd.DataFrame(df_data)
            df.to_csv(file_path, index=False)
        
        elif format.lower() == 'json':
            data = []
            for conn in connections:
                conn_dict = {
                    'uid': conn.uid,
                    'timestamp': conn.timestamp.isoformat() if conn.timestamp else None,
                    'source_ip': conn.source_ip,
                    'dest_ip': conn.dest_ip,
                    'proto': conn.proto,
                    'service': conn.service,
                    'anomaly_score': conn.anomaly_score,
                    'is_anomaly': conn.is_anomaly,
                    'label_category': conn.label_category,
                    'label_subcategory': conn.label_subcategory,
                    'confidence_level': conn.confidence_level.value if conn.confidence_level else None,
                    'training_source': conn.training_source,
                    'review_status': conn.review_status.value,
                    'feature_vector': conn.feature_vector.tolist() if conn.feature_vector is not None else None
                }
                data.append(conn_dict)
            
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
        
        logger.info(f"Exported {len(connections)} connections to {file_path}")