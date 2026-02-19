#!/usr/bin/env python3
"""
Convert OMNeT++ results to CSV for ML training
Simple feature extraction for DoS attack detection
"""

import re
import pandas as pd
from pathlib import Path

def parse_sca_file(sca_file):
    """Extract all metrics from .sca file"""
    data = []
    
    with open(sca_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if not line.startswith('scalar'):
                continue
            
            # Parse: scalar DoSScenario.node[X].app[0] metricName value
            match = re.match(r'scalar\s+DoSScenario\.node\[(\d+)\]\.app\[0\]\s+(\S+)\s+([\d.e+-]+)', line)
            if match:
                node_id = int(match.group(1))
                metric = match.group(2)
                value = float(match.group(3))
                
                data.append({
                    'node_id': node_id,
                    'metric': metric,
                    'value': value
                })
    
    return pd.DataFrame(data)


def create_ml_dataset(sca_file):
    """Convert to ML-ready CSV"""
    
    df = parse_sca_file(sca_file)
    
    if df.empty:
        print("ERROR: No data found!")
        return None
    
    print(f"Reading: {sca_file.name}")
    print(f"  Nodes: {sorted(df['node_id'].unique().tolist())}")
    print(f"  Metrics: {df['metric'].nunique()}")
    
    # Pivot: rows=nodes, columns=metrics
    pivot = df.pivot_table(index='node_id', columns='metric', values='value', aggfunc='first')
    pivot = pivot.fillna(0)
    
    # Add calculated features
    if 'totalBytesSent' in pivot.columns and 'totalPacketsSent' in pivot.columns:
        pivot['avgPacketSizeSent'] = pivot['totalBytesSent'] / (pivot['totalPacketsSent'] + 0.001)
    
    if 'totalBytesReceived' in pivot.columns and 'totalPacketsReceived' in pivot.columns:
        pivot['avgPacketSizeRecv'] = pivot['totalBytesReceived'] / (pivot['totalPacketsReceived'] + 0.001)
    
    # Send/Receive ratio
    if 'totalPacketsSent' in pivot.columns and 'totalPacketsReceived' in pivot.columns:
        pivot['sendRecvRatio'] = pivot['totalPacketsSent'] / (pivot['totalPacketsReceived'] + 1)
    
    # Label: node 0 = ATTACK, others = NORMAL
    pivot['label'] = 'NORMAL'
    if 0 in pivot.index:
        pivot.loc[0, 'label'] = 'ATTACK'
    
    # Node type (0=attacker, 1=victim)
    pivot['nodeType'] = pivot.index.map(lambda x: 0 if x == 0 else 1)
    
    print(f"  Features: {len(pivot.columns)}")
    
    return pivot


def print_summary(df):
    """Show extracted data"""
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    
    for idx, row in df.iterrows():
        print(f"\nNode {idx} - {row['label']}")
        print("-" * 60)
        
        # Key metrics
        metrics = [
            'totalPacketsSent', 'totalPacketsReceived',
            'totalBytesSent', 'totalBytesReceived',
            'packetSendRate', 'packetRecvRate',
            'avgInterArrivalTime', 'burstiness',
            'avgPacketSize', 'throughputEfficiency'
        ]
        
        for m in metrics:
            if m in row.index:
                print(f"  {m:25s}: {row[m]:12.4f}")
    
    print("\n" + "="*60)


def main():
    # Input file
    sca_file = Path('results/DoSAttack-#0.sca')
    
    if not sca_file.exists():
        print(f"ERROR: {sca_file} not found!")
        print("Run simulation in OMNeT++ first")
        return
    
    # Extract features
    df = create_ml_dataset(sca_file)
    if df is None:
        return
    
    # Save to CSV
    output = Path('ml_dataset.csv')
    df.to_csv(output, index=True, index_label='node_id')
    
    print(f"\nSaved: {output}")
    print(f"  Rows: {df.shape[0]} vehicles")
    print(f"  Columns: {df.shape[1]} features")
    
    # Show summary
    print_summary(df)
    
    # Save feature names
    feature_file = Path('feature_names.txt')
    with open(feature_file, 'w') as f:
        f.write("ML FEATURES\n")
        f.write("="*50 + "\n\n")
        
        features = [col for col in df.columns if col not in ['label', 'nodeType']]
        for i, feat in enumerate(features, 1):
            f.write(f"{i:3d}. {feat}\n")
        
        f.write(f"\nTotal: {len(features)} features\n")
    
    print(f"\nFeature list: {feature_file}")
    
    # Example ML code
    print("\n" + "="*60)
    print("MACHINE LEARNING EXAMPLE")
    print("="*60)
    print("""
# Python code to train ML model:

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Load dataset
df = pd.read_csv('ml_dataset.csv', index_col=0)
X = df.drop(['label', 'nodeType'], axis=1)
y = df['label']

# Split and train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# Test accuracy
accuracy = model.score(X_test, y_test)
print(f"Accuracy: {accuracy:.2%}")

# Important features
importance = pd.DataFrame({
    'feature': X.columns,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)
print(importance.head(10))
""")
    
    print("="*60)
    print("COMPLETE!")


if __name__ == '__main__':
    main()
