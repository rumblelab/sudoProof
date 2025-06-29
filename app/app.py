from flask import Flask, request, jsonify, send_from_directory, render_template_string
import requests
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json
import logging
from bitcoin_utils import BitcoinProofOfFunds

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///proofs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Models
class ProofRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    proof_id = db.Column(db.String(64), unique=True, nullable=False)
    proof_name = db.Column(db.String(200), nullable=True)
    addresses = db.Column(db.Text, nullable=False)  # JSON string
    total_amount = db.Column(db.Float, nullable=False)
    target_amount = db.Column(db.Float, nullable=True)
    message = db.Column(db.Text, nullable=False)
    signatures = db.Column(db.Text, nullable=False)  # JSON string
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime, nullable=True)
    verified = db.Column(db.Boolean, default=False)
    
    def to_dict(self):
        return {
            'proof_id': self.proof_id,
            'proof_name': self.proof_name,
            'addresses': json.loads(self.addresses),
            'total_amount': self.total_amount,
            'target_amount': self.target_amount,
            'message': self.message,
            'signatures': json.loads(self.signatures),
            'timestamp': self.timestamp.isoformat(),
            'expiry_date': self.expiry_date.isoformat() if self.expiry_date else None,
            'verified': self.verified
        }

# Create tables
with app.app_context():
    db.create_all()

# Serve the main page
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/create-proof', methods=['POST'])
def create_proof():
    """
    Create a new proof of funds request
    """
    try:
        data = request.json
        addresses = data.get('addresses', [])
        proof_name = data.get('proof_name')  # <-- ADDED
        
        if not addresses:
            return jsonify({'error': 'No addresses provided'}), 400
        
        # Generate proof message
        timestamp = datetime.utcnow()
        total_amount = sum([addr.get('balance', 0) for addr in addresses])
        address_list = [addr['address'] for addr in addresses]
        
        # Pass the proof_name to the message creation function
        message = BitcoinProofOfFunds.create_proof_message(
            address_list, 
            total_amount,
            proof_name=proof_name,  # <-- ADDED
            timestamp=timestamp.isoformat()
        )
        
        # Generate proof ID
        import hashlib
        proof_id = hashlib.sha256(
            f"{timestamp}{json.dumps(address_list)}".encode()
        ).hexdigest()[:16]
        
        logger.info(f"Created proof {proof_id} for {len(addresses)} addresses")
        
        return jsonify({
            'proof_id': proof_id,
            'message': message,
            'addresses': address_list,
            'total_amount': total_amount,
            'timestamp': timestamp.isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error creating proof: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/verify-proof', methods=['POST'])
def verify_proof():
    """
    Verify a proof of funds with signatures
    """
    try:
        data = request.json
        proof_id = data.get('proof_id')
        addresses = data.get('addresses', [])
        signatures = data.get('signatures', {})
        message = data.get('message')
        proof_name = data.get('proof_name')
        target_amount = data.get('target_amount')
        expiry_date = data.get('expiry_date')

        if not all([proof_id, addresses, signatures, message]):
            return jsonify({'error': 'Missing required fields'}), 400

        logger.info(f"Verifying proof {proof_id} with {len(signatures)} signatures")

        # Use the enhanced validation method
        validation_result = BitcoinProofOfFunds.validate_proof_data(
            addresses, signatures, message
        )

        # Save proof record ONLY if all signatures are valid
        if validation_result['valid']:
            # Check if a record with this proof_id already exists to avoid duplicates
            existing_proof = ProofRecord.query.filter_by(proof_id=proof_id).first()
            if not existing_proof:
                total_amount = sum([addr.get('balance', 0) for addr in addresses])
                
                # Parse expiry date if provided
                expiry_dt = None
                if expiry_date:
                    try:
                        expiry_dt = datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
                    except:
                        expiry_dt = datetime.strptime(expiry_date, '%Y-%m-%d')
                
                proof_record = ProofRecord(
                    proof_id=proof_id,
                    proof_name=proof_name,
                    addresses=json.dumps([{
                        'address': a['address'], 
                        'balance': a.get('balance', 0)
                    } for a in addresses]),
                    total_amount=total_amount,
                    target_amount=target_amount,
                    message=message,
                    signatures=json.dumps(signatures),
                    expiry_date=expiry_dt,
                    verified=True
                )
                db.session.add(proof_record)
                db.session.commit()
                logger.info(f"Proof {proof_id} saved successfully")

        return jsonify({
            'proof_id': proof_id,
            'verified': validation_result['valid'],
            'verification_results': validation_result['results'],
            'summary': {
                'total_addresses': validation_result['total_addresses'],
                'valid_signatures': validation_result['valid_signatures']
            },
            'warnings': validation_result.get('warnings', []),
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error verifying proof: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/proof/<proof_id>', methods=['GET'])
def get_proof(proof_id):
    """
    Retrieve a proof record
    """
    try:
        proof = ProofRecord.query.filter_by(proof_id=proof_id).first()
        
        if not proof:
            return jsonify({'error': 'Proof not found'}), 404
        
        logger.info(f"Retrieved proof {proof_id}")
        return jsonify(proof.to_dict())
        
    except Exception as e:
        logger.error(f"Error retrieving proof: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/address-balance/<address>', methods=['GET'])
def get_address_balance(address):
    """
    Get real balance for a Bitcoin address using blockchain APIs
    """
    try:
        logger.info(f"Fetching balance for address: {address[:10]}...")
        
        # Use the enhanced balance fetching method
        balance = BitcoinProofOfFunds.get_address_balance(address)
        
        return jsonify({
            'address': address,
            'balance': balance,
            'confirmed': True,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error fetching balance for {address}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/verify-address/<address>', methods=['POST'])
def verify_single_address():
    """
    Verify a single address signature (for HTMX integration)
    """
    try:
        data = request.json
        signature = data.get('signature')
        message = data.get('message')
        
        if not all([signature, message]):
            return jsonify({'error': 'Missing signature or message'}), 400
        
        # Verify the signature
        is_valid = BitcoinProofOfFunds.verify_message_signature(
            address, signature, message
        )
        
        return jsonify({
            'address': address,
            'valid': is_valid,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error verifying address signature: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/proofs', methods=['GET'])
def list_proofs():
    """
    List all proof records (for admin/debugging)
    """
    try:
        proofs = ProofRecord.query.order_by(ProofRecord.timestamp.desc()).limit(50).all()
        return jsonify({
            'proofs': [proof.to_dict() for proof in proofs],
            'count': len(proofs)
        })
        
    except Exception as e:
        logger.error(f"Error listing proofs: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """
    Get system statistics
    """
    try:
        total_proofs = ProofRecord.query.count()
        verified_proofs = ProofRecord.query.filter_by(verified=True).count()
        total_btc = db.session.query(db.func.sum(ProofRecord.total_amount)).scalar() or 0
        
        return jsonify({
            'total_proofs': total_proofs,
            'verified_proofs': verified_proofs,
            'total_btc_proven': float(total_btc),
            'bitcoin_utils_available': BitcoinProofOfFunds is not None
        })
        
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint
    """
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'bitcoin_utils': 'available' if BitcoinProofOfFunds else 'unavailable'
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    logger.info("Starting Bitcoin Proof of Funds server...")
    logger.info("Available endpoints:")
    logger.info("  GET  /                     - Main application")
    logger.info("  POST /api/create-proof     - Create proof message")
    logger.info("  POST /api/verify-proof     - Verify signatures")
    logger.info("  GET  /api/proof/<id>       - Get proof by ID")
    logger.info("  GET  /api/address-balance/<address> - Get address balance")
    logger.info("  GET  /api/proofs           - List all proofs")
    logger.info("  GET  /api/stats            - System statistics")
    logger.info("  GET  /health               - Health check")
    
    app.run(debug=True, host='0.0.0.0', port=3000)