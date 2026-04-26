"""
REST API for Sanitizer Engine with Yara-X Integration
Provides HTTP endpoints for file scanning and threat detection.
"""

from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
import os
import tempfile
from pathlib import Path
import logging

from sanitizer_integration import SanitizerYaraIntegration, SanitizerConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Initialize sanitizer
config = SanitizerConfig(
    rules_path=os.environ.get('YARA_RULES_PATH', './rules'),
    quarantine_dir=os.environ.get('QUARANTINE_DIR', '/tmp/quarantine'),
    enable_auto_quarantine=True,
    scan_timeout=int(os.environ.get('SCAN_TIMEOUT', '60'))
)

sanitizer = SanitizerYaraIntegration(config)


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'sanitizer-yara-engine',
        'version': '1.0.0'
    })


@app.route('/scan/file', methods=['POST'])
def scan_file():
    """
    Scan an uploaded file.
    
    Request:
        - multipart/form-data with 'file' field
        
    Response:
        JSON with scan results
    """
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({
                'error': 'No file provided',
                'safe': False
            }), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({
                'error': 'Empty filename',
                'safe': False
            }), 400
        
        # Read file data
        file_data = file.read()
        filename = secure_filename(file.filename)
        
        # Scan the upload
        result = sanitizer.scan_upload(file_data, filename)
        
        status_code = 200 if result['safe'] else 403
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"Error in scan_file endpoint: {e}")
        return jsonify({
            'error': str(e),
            'safe': False
        }), 500


@app.route('/scan/path', methods=['POST'])
def scan_path():
    """
    Scan a file by path.
    
    Request:
        JSON with 'path' field
        
    Response:
        JSON with scan results
    """
    try:
        data = request.get_json()
        
        if not data or 'path' not in data:
            return jsonify({
                'error': 'No path provided',
                'safe': False
            }), 400
        
        file_path = data['path']
        
        # Scan the file
        result = sanitizer.sanitize_file(file_path)
        
        status_code = 200 if result['safe'] else 403
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"Error in scan_path endpoint: {e}")
        return jsonify({
            'error': str(e),
            'safe': False
        }), 500


@app.route('/scan/batch', methods=['POST'])
def scan_batch():
    """
    Scan multiple files.
    
    Request:
        JSON with 'paths' array
        
    Response:
        JSON with array of scan results
    """
    try:
        data = request.get_json()
        
        if not data or 'paths' not in data:
            return jsonify({
                'error': 'No paths provided'
            }), 400
        
        paths = data['paths']
        
        if not isinstance(paths, list):
            return jsonify({
                'error': 'paths must be an array'
            }), 400
        
        # Scan all files
        results = []
        for path in paths:
            result = sanitizer.sanitize_file(path)
            results.append(result)
        
        # Summary
        total = len(results)
        safe_count = sum(1 for r in results if r['safe'])
        malicious_count = total - safe_count
        
        return jsonify({
            'summary': {
                'total': total,
                'safe': safe_count,
                'malicious': malicious_count
            },
            'results': results
        }), 200
        
    except Exception as e:
        logger.error(f"Error in scan_batch endpoint: {e}")
        return jsonify({
            'error': str(e)
        }), 500


@app.route('/stats', methods=['GET'])
def get_stats():
    """Get scanning statistics."""
    try:
        stats = sanitizer.get_statistics()
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"Error in get_stats endpoint: {e}")
        return jsonify({
            'error': str(e)
        }), 500


@app.route('/stats/reset', methods=['POST'])
def reset_stats():
    """Reset scanning statistics."""
    try:
        sanitizer.reset_statistics()
        return jsonify({
            'message': 'Statistics reset successfully'
        }), 200
    except Exception as e:
        logger.error(f"Error in reset_stats endpoint: {e}")
        return jsonify({
            'error': str(e)
        }), 500


@app.route('/quarantine/list', methods=['GET'])
def list_quarantine():
    """List files in quarantine."""
    try:
        quarantine_dir = Path(config.quarantine_dir)
        
        if not quarantine_dir.exists():
            return jsonify({
                'files': []
            }), 200
        
        files = []
        for file_path in quarantine_dir.iterdir():
            if file_path.is_file() and not file_path.suffix == '.meta':
                stat = file_path.stat()
                files.append({
                    'filename': file_path.name,
                    'size': stat.st_size,
                    'quarantined_at': stat.st_mtime
                })
        
        return jsonify({
            'count': len(files),
            'files': files
        }), 200
        
    except Exception as e:
        logger.error(f"Error in list_quarantine endpoint: {e}")
        return jsonify({
            'error': str(e)
        }), 500


@app.route('/quarantine/delete/<filename>', methods=['DELETE'])
def delete_quarantine(filename):
    """Delete a file from quarantine."""
    try:
        filename = secure_filename(filename)
        file_path = Path(config.quarantine_dir) / filename
        
        if not file_path.exists():
            return jsonify({
                'error': 'File not found in quarantine'
            }), 404
        
        # Delete file and metadata
        file_path.unlink()
        meta_path = file_path.with_suffix(file_path.suffix + '.meta')
        if meta_path.exists():
            meta_path.unlink()
        
        return jsonify({
            'message': f'File {filename} deleted from quarantine'
        }), 200
        
    except Exception as e:
        logger.error(f"Error in delete_quarantine endpoint: {e}")
        return jsonify({
            'error': str(e)
        }), 500


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error."""
    return jsonify({
        'error': 'File too large',
        'max_size': app.config['MAX_CONTENT_LENGTH']
    }), 413


@app.errorhandler(500)
def internal_server_error(error):
    """Handle internal server errors."""
    logger.error(f"Internal server error: {error}")
    return jsonify({
        'error': 'Internal server error'
    }), 500


def main():
    """Run the Flask application."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Sanitizer Yara-X API Server")
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    logger.info(f"Starting Sanitizer Yara-X API on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
