#!/usr/bin/env python3
"""
PCAP file analysis for anomaly detection.

This module provides functionality to analyze existing PCAP files
with Zeek and machine learning models for security analysis.
"""

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd

from mantaguard.utils.config import config
from mantaguard.utils.logger import get_logger
from mantaguard.data.models.metadata import (
    create_metadata, update_metadata_with_analysis
)

logger = get_logger(__name__)


class PcapAnalyzer:
    """PCAP file analyzer for anomaly detection."""
    
    def __init__(self):
        self.network_analyzer = None
    
    def analyze_pcap(
        self,
        pcap_path: str,
        model_dir: Optional[str] = None,
        model_version: Optional[str] = None
    ) -> Tuple[List[Dict], str]:
        """
        Analyze a PCAP file with Zeek and ML models.
        
        Args:
            pcap_path: Path to the PCAP file to analyze
            model_dir: Directory containing model files (optional)
            model_version: Version suffix for model files (optional)
            
        Returns:
            Tuple of (analysis_results, output_directory)
        """
        logger.info(f"Analyzing PCAP file: {pcap_path}")
        
        # Validate input file
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        
        # Set default model directory if not provided
        if not model_dir:
            model_dir = config.get_retrained_models_dir()
        
        logger.info(f"Using model directory: {model_dir}")
        if model_version:
            logger.info(f"Using model version: {model_version}")
        else:
            logger.info("Model version: Auto-detect")
        
        try:
            # Import and initialize NetworkAnalyzer dynamically to avoid circular imports
            try:
                from mantaguard.core.network.analyzer import NetworkAnalyzer
                if self.network_analyzer is None:
                    # Check for preferred version override
                    effective_version = getattr(self, 'preferred_model_version', model_version)
                    # Let NetworkAnalyzer auto-detect the latest version if not specified
                    self.network_analyzer = NetworkAnalyzer(model_dir, effective_version)
            except ImportError as e:
                logger.error(f"Failed to import NetworkAnalyzer: {e}")
                raise Exception("Network analyzer module not available")
            
            # Use NetworkAnalyzer to process the PCAP
            results, output_dir = self.network_analyzer.analyze_pcap_with_zeek(
                str(pcap_path)
            )
            
            # Count anomalies
            anomaly_count = sum(1 for r in results if r['prediction'] == 'anomaly')
            total_connections = len(results)
            
            logger.info(f"Analysis completed: {anomaly_count} anomalies out of {total_connections} connections")
            
            # Save results to CSV
            csv_path = Path(output_dir) / 'prediction_results.csv'
            df = pd.DataFrame(results)
            df.to_csv(csv_path, index=False)
            logger.info(f"Results saved to CSV: {csv_path}")
            
            # Update metadata if it exists
            try:
                update_metadata_with_analysis(
                    str(pcap_path),
                    output_dir,
                    str(csv_path),
                    anomaly_count,
                    total_connections
                )
            except Exception as e:
                logger.warning(f"Failed to update metadata: {e}")
            
            # Generate visualizations
            self._generate_visualizations(str(csv_path), output_dir)
            
            return results, output_dir
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            raise
    
    def _generate_visualizations(self, csv_path: str, output_dir: str) -> bool:
        """
        Generate visualization charts for analysis results.
        
        Args:
            csv_path: Path to the prediction results CSV
            output_dir: Directory to save visualizations
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Import and use the visualization module
            from mantaguard.utils.visualizations import generate_analysis_visualizations
            
            logger.info("Generating visualizations...")
            generate_analysis_visualizations(csv_path, output_dir)
            logger.info(f"Visualizations saved to: {output_dir}")
            return True
            
        except ImportError:
            # Fallback to subprocess call to legacy script
            try:
                vis_script_path = config.PROJECT_ROOT / "mantaguard" / "utils" / "visualize_results.py"
                if vis_script_path.exists():
                    logger.info("Using legacy visualization script")
                    vis_cmd = [sys.executable, str(vis_script_path), csv_path, output_dir]
                    subprocess.run(vis_cmd, check=True)
                    logger.info(f"Visualizations saved to: {output_dir}")
                    return True
                else:
                    logger.warning("Visualization script not found")
                    return False
            except Exception as e:
                logger.warning(f"Failed to generate visualizations: {e}")
                return False
        except Exception as e:
            logger.warning(f"Failed to generate visualizations: {e}")
            return False
    
    def batch_analyze(
        self,
        pcap_dir: str,
        model_dir: Optional[str] = None,
        model_version: Optional[str] = None
    ) -> List[Tuple[str, List[Dict], str]]:
        """
        Analyze multiple PCAP files in a directory.
        
        Args:
            pcap_dir: Directory containing PCAP files
            model_dir: Directory containing model files (optional)
            model_version: Version suffix for model files (optional)
            
        Returns:
            List of (pcap_file, results, output_dir) tuples
        """
        pcap_dir = Path(pcap_dir)
        if not pcap_dir.exists():
            raise FileNotFoundError(f"Directory not found: {pcap_dir}")
        
        # Find all PCAP files
        pcap_files = list(pcap_dir.glob('*.pcap')) + list(pcap_dir.glob('*.pcapng'))
        
        if not pcap_files:
            logger.warning(f"No PCAP files found in {pcap_dir}")
            return []
        
        logger.info(f"Found {len(pcap_files)} PCAP files to analyze")
        
        results = []
        for pcap_file in pcap_files:
            try:
                logger.info(f"Analyzing {pcap_file.name}...")
                analysis_results, output_dir = self.analyze_pcap(
                    str(pcap_file), model_dir, model_version
                )
                results.append((str(pcap_file), analysis_results, output_dir))
            except Exception as e:
                logger.error(f"Failed to analyze {pcap_file.name}: {e}")
                continue
        
        logger.info(f"Batch analysis completed: {len(results)} files processed")
        return results


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Analyze an existing PCAP file with Zeek and ML models.'
    )
    parser.add_argument('pcap_path', help='Path to the existing PCAP file to analyze')
    parser.add_argument('--model-dir', help='Directory containing the AI model files')
    parser.add_argument('--model-version', help='Version suffix for model files (e.g., "v2")')
    parser.add_argument('--batch', action='store_true', help='Treat pcap_path as a directory and analyze all PCAP files')
    return parser.parse_args()


def main():
    """Main function for command-line usage."""
    args = parse_args()
    
    try:
        analyzer = PcapAnalyzer()
        
        if args.batch:
            # Batch analysis mode
            results = analyzer.batch_analyze(
                args.pcap_path, args.model_dir, args.model_version
            )
            
            print(f"\nBatch Analysis Complete: {len(results)} files processed")
            for pcap_file, analysis_results, output_dir in results:
                anomaly_count = sum(1 for r in analysis_results if r['prediction'] == 'anomaly')
                total_connections = len(analysis_results)
                print(f"  {Path(pcap_file).name}: {anomaly_count}/{total_connections} anomalies")
        else:
            # Single file analysis
            results, output_dir = analyzer.analyze_pcap(
                args.pcap_path, args.model_dir, args.model_version
            )
            
            # Print summary
            anomaly_count = sum(1 for r in results if r['prediction'] == 'anomaly')
            total_connections = len(results)
            print(f"\nAnalysis Results: {anomaly_count} anomalies out of {total_connections} connections")
            
            # Print detailed results
            for result in results:
                print(f"UID: {result['uid']}, Score: {result['score']:.6f}, Prediction: {result['prediction']}")
            
            print(f"\nResults and visualizations saved to: {output_dir}")
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()