#!/usr/bin/env python3
"""
Parse OMNeT++ .vec file to extract packet-level communications
Each row = 1 communication between 2 vehicles
For DoS attack detection in V2V networks
"""

import re
import pandas as pd
from pathlib import Path

def parse_vec_file(vec_file):
    """
    Parse .vec file to extract packet communications
    Returns DataFrame with each row = 1 packet received
    """
    
    # Step 1: Parse vector definitions (which vector belongs to which node)
    vector_map = {}
    node_map = {}
    
    with open(vec_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Parse vector definition lines
            # Format: vector <id> <module> <name> ETV
            if line.startswith('vector'):
                match = re.match(r'vector\s+(\d+)\s+(DoSScenario\.node\[(\d+)\]\.app\[0\])\s+(\S+)', line)
                if match:
                    vector_id = int(match.group(1))
                    node_id = int(match.group(3))
                    vector_name = match.group(4)
                    
                    vector_map[vector_id] = {
                        'node_id': node_id,
                        'vector_name': vector_name
                    }
    
    print(f"Found {len(vector_map)} relevant vectors")
    
    # Step 2: Parse vector data (timestamp and values)
    packet_data = []
    
    with open(vec_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Parse data lines: <vector_id> <event_number> <timestamp> <value>
            if line.strip() and not line.startswith(('version', 'run', 'attr', 'param', 'vector')):
                parts = line.strip().split()
                if len(parts) >= 4:
                    try:
                        vector_id = int(parts[0])
                        event_num = int(parts[1])
                        timestamp = float(parts[2])
                        value = float(parts[3])
                        
                        # Only keep packetReceived vectors (20, 44, 63 for node 0, 1, 2)
                        if vector_id in vector_map:
                            vec_info = vector_map[vector_id]
                            
                            # Filter for packet received events
                            if 'packetReceived' in vec_info['vector_name'] or \
                               'packetSize' in vec_info['vector_name'] or \
                               'interArrivalTime' in vec_info['vector_name']:
                                
                                packet_data.append({
                                    'vector_id': vector_id,
                                    'receiver_node_id': vec_info['node_id'],
                                    'vector_name': vec_info['vector_name'],
                                    'timestamp': timestamp,
                                    'value': value,
                                    'event_num': event_num
                                })
                    except (ValueError, IndexError):
                        continue
    
    print(f"Extracted {len(packet_data)} data points")
    
    return pd.DataFrame(packet_data)


def create_communication_dataset(vec_file):
    """
    Create dataset where each row = 1 communication between vehicles
    """
    
    # Parse vector file
    df = parse_vec_file(vec_file)
    
    if df.empty:
        print("ERROR: No packet data found!")
        return None
    
    # Group data by vector type
    packet_received_data = df[df['vector_name'].str.contains('packetReceived', na=False)]
    packet_size_data = df[df['vector_name'] == 'packetSize']
    iat_data = df[df['vector_name'] == 'interArrivalTime']
    
    print(f"\nPacket received events: {len(packet_received_data)}")
    print(f"Packet size events: {len(packet_size_data)}")
    print(f"IAT events: {len(iat_data)}")
    print(f"Nodes with received packets: {sorted(packet_received_data['receiver_node_id'].unique())}")
    
    # Create communications list
    communications = []
    
    # Process each packet received event
    for idx, pkt_row in packet_received_data.iterrows():
        receiver_id = pkt_row['receiver_node_id']
        timestamp = pkt_row['timestamp']
        event_num = pkt_row['event_num']
        packet_bytes = pkt_row['value']
        
        # Find matching packet size (same receiver, close timestamp)
        size_match = packet_size_data[
            (packet_size_data['receiver_node_id'] == receiver_id) &
            (abs(packet_size_data['timestamp'] - timestamp) < 0.01)
        ]
        packet_size = int(size_match['value'].iloc[0]) if not size_match.empty else int(packet_bytes)
        
        # Find matching IAT (same receiver, close timestamp)
        iat_match = iat_data[
            (iat_data['receiver_node_id'] == receiver_id) &
            (abs(iat_data['timestamp'] - timestamp) < 0.01)
        ]
        inter_arrival_time = iat_match['value'].iloc[0] if not iat_match.empty else 0.0
        
        # In this scenario: node[0] = attacker (sends), node[1,2] = victims (receive)
        sender_node_id = 0  # Attacker always sends
        is_attack = True  # All packets in this scenario are attack packets
        packet_type = "ATTACK"
        label = "ATTACK"
        
        communications.append({
            'timestamp': round(timestamp, 3),
            'sender_node_id': sender_node_id,
            'receiver_node_id': receiver_id,
            'packet_size': packet_size,
            'inter_arrival_time': round(inter_arrival_time, 4),
            'packet_type': packet_type,
            'is_sender_attacker': 1 if is_attack else 0,
            'label': label
        })
    
    if not communications:
        print("WARNING: No communications found!")
        return pd.DataFrame()
    
    return pd.DataFrame(communications).sort_values('timestamp').reset_index(drop=True)


def main():
    # Input file
    vec_file = Path('results/DoSAttack-#0.vec')
    
    if not vec_file.exists():
        print(f"ERROR: {vec_file} not found!")
        print("Make sure simulation has completed")
        return
    
    print("="*60)
    print("PARSING OMNeT++ VECTOR FILE")
    print("="*60)
    
    # Create communication dataset
    df = create_communication_dataset(vec_file)
    
    if df is None or df.empty:
        print("ERROR: Could not create dataset!")
        return
    
    # Save to Excel
    excel_file = Path('v2v_communications.xlsx')
    df.to_excel(excel_file, index=False, sheet_name='Communications')
    
    print(f"\n{'='*60}")
    print(f"SUCCESS!")
    print(f"{'='*60}")
    print(f"File created: {excel_file}")
    print(f"Total communications: {len(df)}")
    print(f"\nBreakdown:")
    print(f"  ATTACK: {(df['label']=='ATTACK').sum()}")
    print(f"  NORMAL: {(df['label']=='NORMAL').sum()}")
    
    # Show sample data
    print(f"\n{'='*60}")
    print("SAMPLE DATA (first 10 rows):")
    print(f"{'='*60}")
    print(df.head(10).to_string(index=False))
    
    # Statistics
    print(f"\n{'='*60}")
    print("STATISTICS:")
    print(f"{'='*60}")
    print(df.describe())
    
    # Save summary
    summary_file = Path('dataset_summary.txt')
    with open(summary_file, 'w') as f:
        f.write("V2V COMMUNICATION DATASET SUMMARY\n")
        f.write("="*60 + "\n\n")
        f.write(f"Total communications: {len(df)}\n")
        f.write(f"ATTACK communications: {(df['label']=='ATTACK').sum()}\n")
        f.write(f"NORMAL communications: {(df['label']=='NORMAL').sum()}\n")
        f.write(f"\nColumns:\n")
        for col in df.columns:
            f.write(f"  - {col}\n")
        f.write(f"\nStatistics:\n")
        f.write(df.describe().to_string())
    
    print(f"\nSummary saved: {summary_file}")
    
    # ML example
    print(f"\n{'='*60}")
    print("MACHINE LEARNING EXAMPLE")
    print(f"{'='*60}")
    print("""
To train ML model:

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Load data
df = pd.read_excel('v2v_communications.xlsx')

# Features
X = df[['sender_node_id', 'receiver_node_id', 'packet_size', 
        'inter_arrival_time', 'is_sender_attacker']]
y = df['label']

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)

# Train
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# Evaluate
accuracy = model.score(X_test, y_test)
print(f"Accuracy: {accuracy:.2%}")
""")
    
    print(f"{'='*60}")
    print("COMPLETE!")
    print(f"{'='*60}\n")


if __name__ == '__main__':
    main()
