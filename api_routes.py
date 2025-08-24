from flask import render_template, request, jsonify, flash, redirect, url_for
from app import app
from ml_pipeline import pipeline
import logging
import urllib.parse

logger = logging.getLogger(__name__)

@app.route('/')
def index():
    """Main page with URL input form."""
    model_info = pipeline.get_model_info()
    return render_template('index.html', model_info=model_info)

@app.route('/predict', methods=['POST'])
def predict_url():
    """Handle URL prediction from web form."""
    try:
        url = request.form.get('url', '').strip()
        
        if not url:
            flash('Please enter a URL', 'error')
            return redirect(url_for('index'))
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Validate URL format
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.netloc:
                flash('Invalid URL format', 'error')
                return redirect(url_for('index'))
        except Exception:
            flash('Invalid URL format', 'error')
            return redirect(url_for('index'))
        
        # Make prediction
        result = pipeline.predict(url)
        
        if 'error' in result:
            flash(result['error'], 'error')
            return redirect(url_for('index'))
        
        return render_template('results.html', result=result)
        
    except Exception as e:
        logger.error(f"Error in predict_url: {e}")
        flash('An error occurred while processing the URL', 'error')
        return redirect(url_for('index'))

@app.route('/api/predict', methods=['POST'])
def api_predict():
    """API endpoint for URL prediction."""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'URL is required',
                'success': False
            }), 400
        
        url = data['url'].strip()
        
        if not url:
            return jsonify({
                'error': 'URL cannot be empty',
                'success': False
            }), 400
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Make prediction
        result = pipeline.predict(url)
        
        if 'error' in result:
            return jsonify({
                'error': result['error'],
                'success': False
            }), 500
        
        return jsonify({
            'success': True,
            'data': result
        })
        
    except Exception as e:
        logger.error(f"Error in api_predict: {e}")
        return jsonify({
            'error': 'Internal server error',
            'success': False
        }), 500

@app.route('/api/predict/batch', methods=['POST'])
def api_predict_batch():
    """API endpoint for batch URL prediction."""
    try:
        data = request.get_json()
        
        if not data or 'urls' not in data:
            return jsonify({
                'error': 'URLs list is required',
                'success': False
            }), 400
        
        urls = data['urls']
        
        if not isinstance(urls, list) or len(urls) == 0:
            return jsonify({
                'error': 'URLs must be a non-empty list',
                'success': False
            }), 400
        
        if len(urls) > 100:  # Limit batch size
            return jsonify({
                'error': 'Batch size limited to 100 URLs',
                'success': False
            }), 400
        
        # Process URLs
        processed_urls = []
        for url in urls:
            url = str(url).strip()
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            processed_urls.append(url)
        
        # Make predictions
        results = pipeline.predict_batch(processed_urls)
        
        return jsonify({
            'success': True,
            'data': {
                'predictions': results,
                'count': len(results)
            }
        })
        
    except Exception as e:
        logger.error(f"Error in api_predict_batch: {e}")
        return jsonify({
            'error': 'Internal server error',
            'success': False
        }), 500

@app.route('/api/model/info')
def api_model_info():
    """API endpoint for model information."""
    try:
        info = pipeline.get_model_info()
        return jsonify({
            'success': True,
            'data': info
        })
    except Exception as e:
        logger.error(f"Error in api_model_info: {e}")
        return jsonify({
            'error': 'Internal server error',
            'success': False
        }), 500

@app.route('/api/train', methods=['POST'])
def api_train():
    """API endpoint for training the model with provided data."""
    try:
        data = request.get_json()
        
        if not data or 'urls' not in data or 'labels' not in data:
            return jsonify({
                'error': 'URLs and labels are required',
                'success': False
            }), 400
        
        urls = data['urls']
        labels = data['labels']
        
        if len(urls) != len(labels):
            return jsonify({
                'error': 'URLs and labels must have the same length',
                'success': False
            }), 400
        
        if len(urls) < 10:
            return jsonify({
                'error': 'At least 10 samples are required for training',
                'success': False
            }), 400
        
        # Convert labels to binary (0 for legitimate, 1 for phishing)
        binary_labels = []
        for label in labels:
            if str(label).lower() in ['1', 'true', 'phishing', 'malicious']:
                binary_labels.append(1)
            else:
                binary_labels.append(0)
        
        # Train model
        results = pipeline.train_model(urls, binary_labels)
        
        return jsonify({
            'success': True,
            'data': results
        })
        
    except Exception as e:
        logger.error(f"Error in api_train: {e}")
        return jsonify({
            'error': f'Training failed: {str(e)}',
            'success': False
        }), 500

@app.route('/docs')
def api_docs():
    """API documentation page."""
    docs = {
        'endpoints': [
            {
                'method': 'POST',
                'path': '/api/predict',
                'description': 'Predict if a single URL is phishing',
                'request_body': {
                    'url': 'string (required)'
                },
                'response': {
                    'success': 'boolean',
                    'data': {
                        'prediction': 'string (phishing/legitimate)',
                        'confidence': 'float',
                        'probabilities': 'object',
                        'features': 'object'
                    }
                }
            },
            {
                'method': 'POST',
                'path': '/api/predict/batch',
                'description': 'Predict multiple URLs at once (max 100)',
                'request_body': {
                    'urls': 'array of strings (required)'
                },
                'response': {
                    'success': 'boolean',
                    'data': {
                        'predictions': 'array of prediction objects',
                        'count': 'integer'
                    }
                }
            },
            {
                'method': 'GET',
                'path': '/api/model/info',
                'description': 'Get information about the current model',
                'response': {
                    'success': 'boolean',
                    'data': {
                        'is_trained': 'boolean',
                        'feature_count': 'integer',
                        'model_type': 'string'
                    }
                }
            },
            {
                'method': 'POST',
                'path': '/api/train',
                'description': 'Train the model with provided data',
                'request_body': {
                    'urls': 'array of strings (required)',
                    'labels': 'array of labels (0/1 or legitimate/phishing) (required)'
                },
                'response': {
                    'success': 'boolean',
                    'data': 'training results object'
                }
            }
        ]
    }
    
    return render_template('api_docs.html', docs=docs)

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'success': False
    }), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({
        'error': 'Internal server error',
        'success': False
    }), 500
