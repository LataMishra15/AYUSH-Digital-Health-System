from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import json
import jwt
from functools import wraps

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

# Secret key for JWT
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'

# In-memory storage (Use database in production)
audit_logs = []
sessions = {}

# Load NAMASTE CodeSystem Data
NAMASTE_DATA = {
    "concept": [
        {"code":"AY-001","display":"Jwara","definition":"Fever or pyrexia in Ayurvedic context","property":[{"code":"ayushSystem","valueString":"Ayurveda"},{"code":"icd11TM2","valueCode":"XM7NK5"},{"code":"icd11Biomedicine","valueCode":"1A20"}]},
        {"code":"AY-002","display":"Kasa","definition":"Cough or respiratory disorder","property":[{"code":"ayushSystem","valueString":"Ayurveda"},{"code":"icd11TM2","valueCode":"XM4LE5"},{"code":"icd11Biomedicine","valueCode":"DA63"}]},
        {"code":"AY-003","display":"Shwasa","definition":"Breathlessness or asthma","property":[{"code":"ayushSystem","valueString":"Ayurveda"},{"code":"icd11TM2","valueCode":"XM5LD3"},{"code":"icd11Biomedicine","valueCode":"CA23"}]},
        {"code":"AY-004","display":"Arsha","definition":"Hemorrhoids or piles","property":[{"code":"ayushSystem","valueString":"Ayurveda"},{"code":"icd11TM2","valueCode":"XM8AR2"},{"code":"icd11Biomedicine","valueCode":"DD12"}]},
        {"code":"AY-005","display":"Atisara","definition":"Diarrhea or loose motions","property":[{"code":"ayushSystem","valueString":"Ayurveda"},{"code":"icd11TM2","valueCode":"XM7NKS"},{"code":"icd11Biomedicine","valueCode":"1A20"}]},
        {"code":"AY-006","display":"Grahani","definition":"Irritable bowel syndrome","property":[{"code":"ayushSystem","valueString":"Ayurveda"},{"code":"icd11TM2","valueCode":"XM4LE5"},{"code":"icd11Biomedicine","valueCode":"DA63"}]},
        {"code":"AY-007","display":"Prameha","definition":"Diabetes mellitus in Ayurvedic context","property":[{"code":"ayushSystem","valueString":"Ayurveda"},{"code":"icd11TM2","valueCode":"XM5LD3"},{"code":"icd11Biomedicine","valueCode":"CA23"}]},
        {"code":"AY-008","display":"Madhumeha","definition":"Type 2 diabetes mellitus","property":[{"code":"ayushSystem","valueString":"Ayurveda"},{"code":"icd11TM2","valueCode":"XM5LD3"},{"code":"icd11Biomedicine","valueCode":"5A11.0"},{"code":"parentCode","valueCode":"AY-007"}]},
        {"code":"AY-009","display":"Shirahshool","definition":"Headache or cephalgia","property":[{"code":"ayushSystem","valueString":"Ayurveda"},{"code":"icd11TM2","valueCode":"XM8AR2"},{"code":"icd11Biomedicine","valueCode":"MG22"}]},
        {"code":"AY-010","display":"Kamala","definition":"Jaundice or hepatic disorder","property":[{"code":"ayushSystem","valueString":"Ayurveda"},{"code":"icd11TM2","valueCode":"XM8AR2"},{"code":"icd11Biomedicine","valueCode":"DB94"}]},
        {"code":"SID-001","display":"Suram","definition":"Fever in Siddha medicine","property":[{"code":"ayushSystem","valueString":"Siddha"},{"code":"icd11TM2","valueCode":"XM7NK5"},{"code":"icd11Biomedicine","valueCode":"1A20"}]},
        {"code":"SID-002","display":"Irumul","definition":"Cough in Siddha system","property":[{"code":"ayushSystem","valueString":"Siddha"},{"code":"icd11TM2","valueCode":"XM7NK5"},{"code":"icd11Biomedicine","valueCode":"MD10"}]},
        {"code":"UN-001","display":"Hummah","definition":"Fever in Unani medicine","property":[{"code":"ayushSystem","valueString":"Unani"},{"code":"icd11TM2","valueCode":"XM7NK5"},{"code":"icd11Biomedicine","valueCode":"1A20"}]},
        {"code":"UN-002","display":"Su'al","definition":"Cough in Unani system","property":[{"code":"ayushSystem","valueString":"Unani"},{"code":"icd11TM2","valueCode":"XM7NK5"},{"code":"icd11Biomedicine","valueCode":"MD10"}]}
    ]
}

# Helper Functions
def get_property_value(properties, code):
    for prop in properties:
        if prop.get('code') == code:
            return prop.get('valueString') or prop.get('valueCode')
    return None

def log_audit(user_id, action, resource, ip_address, details=None):
    audit_logs.append({
        'timestamp': datetime.utcnow().isoformat(),
        'user_id': user_id,
        'action': action,
        'resource': resource,
        'ip_address': ip_address,
        'details': details
    })

# JWT Token Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            token = token.split(' ')[1] if ' ' in token else token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['user_id']
        except:
            return jsonify({'error': 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# Routes

@app.route('/api/auth/token', methods=['POST'])
def authenticate():
    """Generate JWT token for authentication"""
    data = request.get_json()
    user_id = data.get('user_id')
    abha_id = data.get('abha_id')
    
    if not user_id or not abha_id:
        return jsonify({'error': 'user_id and abha_id required'}), 400
    
    # Generate JWT token
    token = jwt.encode({
        'user_id': user_id,
        'abha_id': abha_id,
        'exp': datetime.utcnow().timestamp() + 86400  # 24 hours
    }, app.config['SECRET_KEY'], algorithm='HS256')
    
    log_audit(user_id, 'LOGIN', 'Authentication', request.remote_addr)
    
    return jsonify({
        'status': 'success',
        'token': token,
        'user_id': user_id
    })

@app.route('/api/search/autocomplete', methods=['GET'])
@token_required
def search_concepts(current_user):
    """Search NAMASTE concepts"""
    query = request.args.get('q', '').lower()
    system = request.args.get('system', 'all')
    
    if len(query) < 2:
        return jsonify({'results': []})
    
    results = []
    for concept in NAMASTE_DATA['concept']:
        ayush_system = get_property_value(concept['property'], 'ayushSystem')
        
        # Filter by system
        if system != 'all' and ayush_system != system:
            continue
        
        # Search in code, display, definition, and ICD codes
        icd11_tm2 = get_property_value(concept['property'], 'icd11TM2') or ''
        icd11_bio = get_property_value(concept['property'], 'icd11Biomedicine') or ''
        
        if (query in concept['code'].lower() or 
            query in concept['display'].lower() or 
            query in concept['definition'].lower() or
            query in icd11_tm2.lower() or
            query in icd11_bio.lower()):
            
            parent_code = get_property_value(concept['property'], 'parentCode')
            
            results.append({
                'code': concept['code'],
                'display': concept['display'],
                'definition': concept['definition'],
                'ayushSystem': ayush_system,
                'icd11TM2': icd11_tm2,
                'icd11Biomedicine': icd11_bio,
                'parentCode': parent_code
            })
    
    log_audit(current_user, 'SEARCH', 'CodeSystem', request.remote_addr, 
              {'query': query, 'results_count': len(results)})
    
    return jsonify({'results': results})

@app.route('/api/translate', methods=['POST'])
@token_required
def translate_code(current_user):
    """Translate codes between NAMASTE and ICD-11"""
    data = request.get_json()
    source_system = data.get('source_system')
    source_code = data.get('source_code')
    target_system = data.get('target_system')
    
    if not all([source_system, source_code, target_system]):
        return jsonify({'error': 'Missing required parameters'}), 400
    
    concept = None
    
    # Find concept based on source system
    if source_system == 'namaste':
        concept = next((c for c in NAMASTE_DATA['concept'] if c['code'] == source_code), None)
    elif source_system == 'icd11_tm2':
        concept = next((c for c in NAMASTE_DATA['concept'] 
                       if get_property_value(c['property'], 'icd11TM2') == source_code), None)
    elif source_system == 'icd11_biomedicine':
        concept = next((c for c in NAMASTE_DATA['concept'] 
                       if source_code in (get_property_value(c['property'], 'icd11Biomedicine') or '')), None)
    
    if not concept:
        return jsonify({'status': 'error', 'error': 'Source code not found'}), 404
    
    # Prepare translation result
    icd11_tm2 = get_property_value(concept['property'], 'icd11TM2')
    icd11_bio = get_property_value(concept['property'], 'icd11Biomedicine')
    
    source_info = {
        'system': source_system,
        'code': source_code,
        'display': concept['display']
    }
    
    if target_system == 'namaste':
        target_info = {
            'system': 'namaste',
            'code': concept['code'],
            'display': concept['display']
        }
    elif target_system == 'icd11_tm2':
        target_info = {
            'system': 'icd11_tm2',
            'code': icd11_tm2,
            'display': concept['definition']
        }
    else:  # icd11_biomedicine
        target_info = {
            'system': 'icd11_biomedicine',
            'code': icd11_bio,
            'display': concept['definition']
        }
    
    log_audit(current_user, 'TRANSLATE', 'CodeSystem', request.remote_addr,
              {'source': source_system, 'target': target_system})
    
    return jsonify({
        'status': 'success',
        'translation': {
            'source': source_info,
            'target': target_info
        }
    })

@app.route('/api/encounter/upload', methods=['POST'])
@token_required
def upload_bundle(current_user):
    """Upload FHIR Bundle"""
    bundle = request.get_json()
    
    if not bundle or bundle.get('resourceType') != 'Bundle':
        return jsonify({'error': 'Invalid FHIR Bundle'}), 400
    
    resources_processed = 0
    if 'entry' in bundle:
        resources_processed = len(bundle['entry'])
    
    bundle_id = f"bundle-{datetime.utcnow().timestamp()}"
    
    log_audit(current_user, 'BUNDLE_UPLOAD', 'Bundle', request.remote_addr,
              {'bundle_id': bundle_id, 'resources': resources_processed})
    
    return jsonify({
        'status': 'success',
        'bundle_id': bundle_id,
        'resources_processed': resources_processed
    })

@app.route('/api/ingest/namaste', methods=['POST'])
@token_required
def ingest_csv(current_user):
    """Ingest NAMASTE CSV file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    # Process CSV (simplified for demo)
    concepts_loaded = len(NAMASTE_DATA['concept'])
    
    log_audit(current_user, 'CSV_INGEST', 'CodeSystem', request.remote_addr,
              {'concepts_loaded': concepts_loaded})
    
    return jsonify({
        'status': 'success',
        'codesystem': {
            'count': concepts_loaded,
            'version': '1.0.0',
            'status': 'active'
        }
    })

@app.route('/api/audit/logs', methods=['GET'])
@token_required
def get_audit_logs(current_user):
    """Get audit logs"""
    user_filter = request.args.get('user_id')
    action_filter = request.args.get('action')
    
    filtered_logs = audit_logs
    
    if user_filter:
        filtered_logs = [log for log in filtered_logs if log['user_id'] == user_filter]
    
    if action_filter:
        filtered_logs = [log for log in filtered_logs if log['action'] == action_filter]
    
    return jsonify({
        'status': 'success',
        'total': len(filtered_logs),
        'logs': filtered_logs[-50:]  # Last 50 logs
    })

@app.route('/api/codesystem', methods=['GET'])
def get_codesystem():
    """Get complete CodeSystem"""
    return jsonify({
        'resourceType': 'CodeSystem',
        'id': 'namaste-ayush-codes',
        'url': 'http://abdm.gov.in/fhir/CodeSystem/namaste-ayush',
        'version': '1.0.0',
        'name': 'NAMASTEAyushCodes',
        'title': 'NAMASTE AYUSH Traditional Medicine Codes',
        'status': 'active',
        'count': len(NAMASTE_DATA['concept']),
        'concept': NAMASTE_DATA['concept']
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'concepts_loaded': len(NAMASTE_DATA['concept'])
    })

if __name__ == '__main__':
    print("🚀 NAMASTE AYUSH Backend API Starting...")
    print("📊 Loaded concepts:", len(NAMASTE_DATA['concept']))
    print("🌐 Server running on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)