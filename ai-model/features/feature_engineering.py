import pandas as pd
import numpy as np
from sklearn.preprocessing import OneHotEncoder, StandardScaler

class NetworkFeatureEngineering:
    def __init__(self):
        self.categorical_encoders = {}
        self.numerical_scalers = {}
        
    def transform_features(self, df, training=False):
        """Transform raw features into model-ready features"""
        result_df = df.copy()
        
        # 1. Handle timestamps
        result_df['hour'] = pd.to_datetime(result_df['timestamp']).dt.hour
        result_df['minute'] = pd.to_datetime(result_df['timestamp']).dt.minute
        result_df['day_of_week'] = pd.to_datetime(result_df['timestamp']).dt.dayofweek
        
        # 2. Create protocol features
        if training:
            self.categorical_encoders['protocol'] = OneHotEncoder(sparse=False, handle_unknown='ignore')
            protocol_encoded = self.categorical_encoders['protocol'].fit_transform(result_df[['protocol']])
        else:
            protocol_encoded = self.categorical_encoders['protocol'].transform(result_df[['protocol']])
            
        protocol_cols = [f'protocol_{x}' for x in self.categorical_encoders['protocol'].categories_[0]]
        protocol_df = pd.DataFrame(protocol_encoded, columns=protocol_cols)
        result_df = pd.concat([result_df, protocol_df], axis=1)
        
        # 3. Handle ports
        result_df['src_port'] = pd.to_numeric(result_df['src_port'], errors='coerce')
        result_df['dst_port'] = pd.to_numeric(result_df['dst_port'], errors='coerce')
        
        # Fill missing ports
        result_df['src_port'].fillna(-1, inplace=True)
        result_df['dst_port'].fillna(-1, inplace=True)
        
        # Create port range features
        result_df['src_port_system'] = (result_df['src_port'] < 1024).astype(int)
        result_df['src_port_user'] = ((result_df['src_port'] >= 1024) & (result_df['src_port'] < 49152)).astype(int)
        result_df['src_port_dynamic'] = (result_df['src_port'] >= 49152).astype(int)
        
        result_df['dst_port_system'] = (result_df['dst_port'] < 1024).astype(int)
        result_df['dst_port_user'] = ((result_df['dst_port'] >= 1024) & (result_df['dst_port'] < 49152)).astype(int)
        result_df['dst_port_dynamic'] = (result_df['dst_port'] >= 49152).astype(int)
        
        # 4. Extract IP address features
        result_df['src_ip_private'] = result_df['source_ip'].apply(self._is_private_ip).astype(int)
        result_df['dst_ip_private'] = result_df['destination_ip'].apply(self._is_private_ip).astype(int)
        result_df['src_ip_multicast'] = result_df['source_ip'].apply(self._is_multicast_ip).astype(int)
        result_df['dst_ip_multicast'] = result_df['destination_ip'].apply(self._is_multicast_ip).astype(int)
        
        # 5. Create numerical features
        num_cols = ['length', 'hour', 'minute', 'src_port', 'dst_port']
        if training:
            self.numerical_scalers['standard'] = StandardScaler()
            scaled_features = self.numerical_scalers['standard'].fit_transform(result_df[num_cols])
        else:
            scaled_features = self.numerical_scalers['standard'].transform(result_df[num_cols])
            
        scaled_df = pd.DataFrame(scaled_features, columns=[f'{col}_scaled' for col in num_cols])
        result_df = pd.concat([result_df, scaled_df], axis=1)
        
        # 6. Extract flow features (connections over time)
        if 'flow_features' not in result_df.columns:
            result_df = self._add_flow_features(result_df)
            
        # Select final feature columns for model
        feature_cols = [
            # Time features
            'hour', 'minute', 'day_of_week',
            
            # Protocol features
            *protocol_cols,
            
            # Port features
            'src_port_system', 'src_port_user', 'src_port_dynamic',
            'dst_port_system', 'dst_port_user', 'dst_port_dynamic',
            
            # IP features
            'src_ip_private', 'dst_ip_private', 
            'src_ip_multicast', 'dst_ip_multicast',
            
            # Scaled features
            'length_scaled', 'hour_scaled', 'minute_scaled',
            'src_port_scaled', 'dst_port_scaled',
            
            # Flow features
            'packets_in_flow', 'bytes_in_flow', 'flow_duration'
        ]
        
        return result_df[feature_cols]
    
    def _is_private_ip(self, ip):
        """Check if an IP address is private"""
        if not isinstance(ip, str):
            return False
            
        # Handle IPv6, multicast, etc.
        if ':' in ip:
            return 'fe80:' in ip  # Simple check for link-local IPv6
            
        # Check for private IPv4 ranges
        octets = ip.split('.')
        if len(octets) != 4:
            return False
            
        try:
            first = int(octets[0])
            second = int(octets[1])
            
            # Class A private: 10.0.0.0 to 10.255.255.255
            if first == 10:
                return True
                
            # Class B private: 172.16.0.0 to 172.31.255.255
            if first == 172 and (16 <= second <= 31):
                return True
                
            # Class C private: 192.168.0.0 to 192.168.255.255
            if first == 192 and second == 168:
                return True
                
            return False
        except:
            return False
    
    def _is_multicast_ip(self, ip):
        """Check if an IP address is multicast"""
        if not isinstance(ip, str):
            return False
            
        # IPv6 multicast
        if ':' in ip:
            return 'ff0' in ip
            
        # IPv4 multicast: 224.0.0.0 to 239.255.255.255
        octets = ip.split('.')
        if len(octets) != 4:
            return False
            
        try:
            first = int(octets[0])
            return 224 <= first <= 239
        except:
            return False
            
    def _add_flow_features(self, df):
        """Add flow-based features (connection tracking)"""
        # Create flow identifier (connection)
        df['flow_id'] = df.apply(lambda row: f"{row['source_ip']}:{row.get('src_port', 0)}-{row['destination_ip']}:{row.get('dst_port', 0)}", axis=1)
        
        # Group by flow and calculate statistics
        flow_stats = df.groupby('flow_id').agg({
            'no': 'count',
            'length': 'sum',
            'timestamp': lambda x: (pd.to_datetime(x.max()) - pd.to_datetime(x.min())).total_seconds()
        }).reset_index()
        
        flow_stats.columns = ['flow_id', 'packets_in_flow', 'bytes_in_flow', 'flow_duration']
        
        # Replace 0 duration with a small value to avoid division by zero
        flow_stats['flow_duration'] = flow_stats['flow_duration'].replace(0, 0.001)
        
        # Merge flow stats back to original dataframe
        df = df.merge(flow_stats, on='flow_id', how='left')
        
        return df