# PhishGuard - Phishing URL Detection System

## Overview

PhishGuard is a machine learning-powered web application that detects phishing URLs in real-time. The system uses a Flask web framework to provide both a user-friendly web interface and RESTful API endpoints for URL analysis. At its core, it employs a Random Forest classifier trained on comprehensive URL features to identify potentially malicious websites and protect users from phishing attacks.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Web Interface**: Bootstrap-based responsive UI with dark theme styling
- **Template Engine**: Jinja2 templates for server-side rendering
- **Client-side Enhancement**: Vanilla JavaScript for form interactions and user experience improvements
- **Styling Framework**: Bootstrap with custom CSS variables and backdrop filters for modern glassmorphic design

### Backend Architecture
- **Web Framework**: Flask application with modular route organization
- **ML Pipeline**: Custom `PhishingDetectionPipeline` class managing the complete machine learning workflow
- **Feature Engineering**: Dedicated `URLFeatureExtractor` for comprehensive URL analysis including domain properties, character patterns, and security indicators
- **Model Architecture**: Random Forest classifier with StandardScaler for feature normalization
- **Model Persistence**: Joblib-based model serialization for trained model storage and loading

### Data Processing Pipeline
- **Feature Extraction**: Multi-dimensional URL analysis covering basic properties, domain characteristics, character-based patterns, structural elements, and security features
- **Data Validation**: URL format validation with urllib.parse and error handling
- **Preprocessing**: Feature standardization and data cleaning before model training/prediction
- **Cross-validation**: Built-in model evaluation using scikit-learn's cross-validation capabilities

### Application Structure
- **Route Separation**: API routes isolated in separate module to avoid circular imports
- **Error Handling**: Comprehensive exception handling with logging and user-friendly error messages
- **Session Management**: Flask sessions with configurable secret key for flash messaging
- **Production Readiness**: ProxyFix middleware for proper handling behind reverse proxies

### Security and Reliability
- **Input Validation**: URL format validation and sanitization
- **Error Logging**: Structured logging throughout the application
- **Graceful Degradation**: Default feature values when feature extraction fails
- **Model Fallback**: Error handling for cases when ML model is unavailable

## External Dependencies

### Python Libraries
- **Flask**: Web framework for application structure and routing
- **scikit-learn**: Machine learning library providing Random Forest classifier and evaluation metrics
- **pandas**: Data manipulation and analysis
- **numpy**: Numerical computing for array operations
- **joblib**: Model serialization and deserialization

### Frontend Dependencies
- **Bootstrap**: UI framework loaded from CDN for responsive design
- **Font Awesome**: Icon library for enhanced visual interface
- **Custom Bootstrap Theme**: Replit agent dark theme for consistent styling

### System Dependencies
- **Python 3.x**: Runtime environment
- **Werkzeug**: WSGI utilities including ProxyFix middleware for production deployment

### Model Storage
- **Local File System**: Models stored in `models/` directory using joblib format
- **Feature Persistence**: Feature names and model metadata stored alongside trained models