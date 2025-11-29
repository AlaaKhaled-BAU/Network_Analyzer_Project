"""
ML Prediction Service - Separated from aggregator
Reads features from database and runs Random Forest predictions
"""

import os
import sys
import time
import json
import asyncio
import logging
import pandas as pd
import joblib
from datetime import datetime, timedelta
from sqlalchemy import create_engine, select, and_
from sqlalchemy.orm import Session

# Add parent directory to path to import from app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.main import (
    predictions_5s_table,
    predictions_30s_table, 
    predictions_3min_table,
    traffic_table,
    engine
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load ML Model (Random Forest)
try:
    model_path = os.path.join(os.path.dirname(__file__), 'models', 'AI_model.pkl')
    model = joblib.load(model_path)
    logger.info(f"Random Forest model loaded from {model_path}")
    logger.info(f"Model type: {type(model)}")
    logger.info(f"Expected features: {model.feature_names_in_ if hasattr(model, 'feature_names_in_') else 'Unknown'}")
except Exception as e:
    logger.error(f"Failed to load ML model: {e}")
    model = None
    sys.exit(1)

# Database session
session = Session(engine)

def prepare_features_for_ml(feature_dict):
    """
    Prepare features for Random Forest model
    Handles one-hot encoding for categorical variables
    """
    try:
        # Create DataFrame from features
        df = pd.DataFrame([feature_dict])
        
        # One-hot encode categorical features if present
        categorical_cols = []
        for col in df.columns:
            if df[col].dtype == 'object':
                categorical_cols.append(col)
        
        if categorical_cols:
            df = pd.get_dummies(df, columns=categorical_cols)
        
        # Ensure all model features are present (add missing as 0)
        if hasattr(model, 'feature_names_in_'):
            for feature in model.feature_names_in_:
                if feature not in df.columns:
                    df[feature] = 0
            
            # Reorder columns to match model training
            df = df[model.feature_names_in_]
        
        # Convert to float
        df = df.astype(float)
        
        return df
    
    except Exception as e:
        logger.error(f"Error preparing features: {e}")
        return None

def predict_with_confidence(features_df):
    """
    Run Random Forest prediction with confidence score
    """
    try:
        # Get prediction
        prediction = model.predict(features_df)[0]
        
        # Get probability/confidence if available
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(features_df)[0]
            confidence = float(max(probabilities))  # Confidence = max probability
        else:
            confidence = None
        
        return prediction, confidence
    
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return "unknown", None

async def process_prediction_request(window_name, table, feature_dict):
    """
    Process ML prediction request for a specific time window
    """
    try:
        # Prepare features
        features_df = prepare_features_for_ml(feature_dict)
        if features_df is None:
            logger.error(f"Failed to prepare features for {window_name}")
            return None
        
        # Run prediction
        predicted_label, confidence = predict_with_confidence(features_df)
        
        logger.info(f"{window_name} prediction: {predicted_label} (confidence: {confidence})")
        
        # Store prediction in appropriate table
        insert_query = table.insert().values(
            window_start=feature_dict['window_start'],
            window_end=feature_dict['window_end'],
            total_packets=feature_dict.get('total_packets', 0),
            unique_src_ips=feature_dict.get('unique_src_ips', 0),
            unique_dst_ips=feature_dict.get('unique_dst_ips', 0),
            flow_count=feature_dict.get('flow_count', 0),
            avg_packet_rate=feature_dict.get('avg_packet_rate', 0.0),
            avg_byte_rate=feature_dict.get('avg_byte_rate', 0.0),
            predicted_label=str(predicted_label),
            confidence=confidence,
            features_json=json.dumps(feature_dict)
        )
        
        session.execute(insert_query)
        session.commit()
        
        return predicted_label, confidence
    
    except Exception as e:
        logger.error(f"Error processing {window_name} prediction: {e}")
        session.rollback()
        return None

async def monitor_for_prediction_requests():
    """
    Monitor traffic_data table for new flow entries that need ML prediction
    This service is triggered by aggregator inserting rows
    """
    logger.info("ML Prediction Service started")
    logger.info("Monitoring traffic_data for new entries requiring prediction...")
    
    last_processed_id = 0
    
    while True:
        try:
            # Check for new flows in traffic_data that need prediction
            query = select(traffic_table).where(
                traffic_table.c.id_num > last_processed_id
            ).order_by(traffic_table.c.id_num)
            
            result = session.execute(query).fetchall()
            
            if result:
                for row in result:
                    # Extract features from traffic_data
                    features = {
                        'dest_ip': row.dest_ip,
                        'packet_count': row.packet_count,
                        'packet_per_sec': row.packet_per_sec,
                        'byte_count': row.byte_count,
                        'byte_per_sec': row.byte_per_sec,
                        'tcp_flags': row.tcp_flags,
                        'connection_attempts': row.connection_attempts,
                        'unique_ports': row.unique_ports,
                        'protocol': row.protocol
                    }
                    
                    # Prepare and predict
                    features_df = prepare_features_for_ml(features)
                    if features_df is not None:
                        predicted_label, confidence = predict_with_confidence(features_df)
                        
                        # Update the row with prediction
                        update_query = traffic_table.update().where(
                            traffic_table.c.id_num == row.id_num
                        ).values(predicted_label=str(predicted_label))
                        
                        session.execute(update_query)
                        session.commit()
                        
                        logger.info(f"Predicted for flow {row.id_num}: {predicted_label}")
                    
                    last_processed_id = row.id_num
            
            # Wait before checking again
            await asyncio.sleep(2)
        
        except Exception as e:
            logger.error(f"Error in prediction monitoring: {e}")
            session.rollback()
            await asyncio.sleep(5)

async def main():
    """Main entry point for ML prediction service"""
    logger.info("=" * 60)
    logger.info("ML Prediction Service - Random Forest Classifier")
    logger.info("=" * 60)
    
    if model is None:
        logger.error("ML model not loaded. Exiting.")
        return
    
    # Run prediction monitoring
    await monitor_for_prediction_requests()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("ML Prediction Service stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
