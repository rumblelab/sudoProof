from flask import Flask, request, jsonify, send_from_directory, render_template, Response, render_template_string
import requests
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import json
import logging
from bitcoin_utils import BitcoinProofOfFunds
from fpdf import FPDF
import secrets
import secrets  # <-- ADDED: Import the secrets library

app = Flask(__name__)
CORS(app)

# Add a template folder
app.template_folder = '.'

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
    delete_token = db.Column(db.String(64), unique=True, nullable=False)

    
    def to_dict(self):
        return {
            'proof_id': self.proof_id,
            'proof_name': self.proof_name,
            'addresses': json.loads(self.addresses),
            'total_amount': self.total_amount,
            'target_amount': self.target_amount,
            'message': self.message,
            'signatures': json.loads(self.signatures),
            'timestamp': self.timestamp, # Return datetime object
            'expiry_date': self.expiry_date, # Return datetime object
            'verified': self.verified
        }

# Create tables
with app.app_context():
    db.create_all()

# --- NEW PDF HELPER CLASS ---
class PDF(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 16)
        self.cell(0, 10, 'Cryptographic Proof of Funds', 0, 1, 'L')
        self.set_font('helvetica', '', 10)
        self.set_text_color(128)
        self.cell(0, 10, 'This document verifies control over the listed Bitcoin assets.', 0, 1, 'L')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')
        self.cell(0, 10, f'Generated on {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}', 0, 0, 'R')

# --- Web Pages ---
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/proof/<proof_id>')
def proof_record_page(proof_id):
    proof_data = ProofRecord.query.filter_by(proof_id=proof_id).first_or_404()
    return render_template('proof_record.html', proof=proof_data.to_dict())


# --- API Endpoints ---
@app.route('/proof/<proof_id>/pdf')
def generate_proof_pdf(proof_id):
    """
    Generates a clear, lender-friendly PDF for the proof record.
    """
    proof = ProofRecord.query.filter_by(proof_id=proof_id).first_or_404().to_dict()
    
    pdf = PDF('P', 'mm', 'A4')
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font('helvetica', '', 10)

    # --- Section 1: Summary ---
    pdf.set_font('helvetica', 'B', 14)
    pdf.cell(0, 10, 'Proof of Funds Summary', 0, 1, 'L')
    
    col1_width = 45
    col2_width = 0
    line_height = 7

    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(col1_width, line_height, 'Proof Name:', 0, 0)
    pdf.set_font('helvetica', '', 10)
    pdf.cell(col2_width, line_height, str(proof['proof_name']), 0, 1)

    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(col1_width, line_height, 'Total Verified Amount:', 0, 0)
    pdf.set_font('helvetica', 'B', 10)
    pdf.set_text_color(0, 100, 0)
    pdf.cell(col2_width, line_height, f"{proof['total_amount']:.8f} BTC", 0, 1)
    pdf.set_text_color(0)

    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(col1_width, line_height, 'Proof Generated On:', 0, 0)
    pdf.set_font('helvetica', '', 10)
    pdf.cell(col2_width, line_height, proof['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC'), 0, 1)
    
    pdf.ln(10)

    # --- Section 2: Detailed Address Proofs ---
    pdf.set_font('helvetica', 'B', 14)
    pdf.cell(0, 10, 'Detailed Address Verification', 0, 1, 'L')

    messages = json.loads(proof['message'])

    for i, addr_info in enumerate(proof['addresses']):
        address = addr_info['address']
        balance = addr_info['balance']
        message = messages[i] if i < len(messages) else ""
        signature = proof['signatures'].get(address, "Signature not found")

        pdf.set_font('helvetica', 'B', 11)
        pdf.cell(0, 9, f"Proof for Address {i+1}", 0, 1, 'L')
        
        # We'll manually control the layout instead of using a single large box
        
        # Address
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(25, 8, 'Address:', 0, 0)
        pdf.set_font('courier', '', 9)
        pdf.cell(0, 8, address, 0, 1)
        
        # Balance
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(25, 8, 'Balance:', 0, 0)
        pdf.set_font('courier', '', 9)
        pdf.cell(0, 8, f"{balance:.8f} BTC", 0, 1)

        # Message Signed
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(0, 8, 'Message Signed:', 0, 1)
        pdf.set_font('courier', '', 8)
        # CORRECTED: Removed invalid new_x and new_y arguments
        pdf.multi_cell(0, 4, message, border=1)
        # pdf.ln() is not strictly needed after multi_cell as it moves the cursor
        
        # Signature
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(0, 8, 'Verification Signature:', 0, 1)
        pdf.set_font('courier', '', 7)
        # CORRECTED: Removed invalid new_x and new_y arguments
        pdf.multi_cell(0, 3, signature, border=1)
        
        pdf.ln(10) # Add space between each proof block
        
    # --- Output ---
    # The .encode('latin-1') is needed by the Response object
    response = Response(
            pdf.output(dest='S').encode('latin-1'),
            mimetype='application/pdf',
            headers={'Content-Disposition': f'inline; filename=proof_{proof_id}.pdf'}
        )
    return response
    
@app.route('/api/verify-signature-only', methods=['POST'])
def verify_signature_only():
    """
    Verifies a single signature without saving a proof record.
    This is used for immediate feedback in the UI.
    """
    try:
        data = request.json
        address = data.get('address')
        signature = data.get('signature')
        message = data.get('message')

        if not all([address, signature, message]):
            return jsonify({'error': 'Missing required fields'}), 400

        is_valid = BitcoinProofOfFunds.verify_message_signature(
            address, signature, message
        )
        
        return jsonify({'valid': is_valid})

    except Exception as e:
        logger.error(f"Error in verify-signature-only: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/create-proof', methods=['POST'])
def create_proof():
    """
    Create a new proof of funds request
    """
    try:
        data = request.json
        addresses = data.get('addresses', [])
        proof_name = data.get('proof_name')
        
        if not addresses:
            return jsonify({'error': 'No addresses provided'}), 400
        
        timestamp = datetime.utcnow()
        total_amount = sum([addr.get('balance', 0) for addr in addresses])
        address_list = [addr['address'] for addr in addresses]
        
        message = BitcoinProofOfFunds.create_proof_message(
            address_list, 
            total_amount,
            proof_name=proof_name,
            timestamp=timestamp.isoformat()
        )
        
        # --- CHANGED: Use a secure, random token for the proof ID ---
        proof_id = secrets.token_urlsafe(32)
        
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

@app.route('/proof/delete/<delete_token>')
def delete_proof(delete_token):
    """
    Finds a proof by its secret delete_token and deletes it.
    """
    proof_to_delete = ProofRecord.query.filter_by(delete_token=delete_token).first_or_404()
    
    if proof_to_delete:
        db.session.delete(proof_to_delete)
        db.session.commit()
        logger.info(f"Proof {proof_to_delete.proof_id} deleted successfully.")
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head><title>Proof Deleted</title><script src="https://cdn.tailwindcss.com"></script></head>
            <body class="bg-slate-100 flex items-center justify-center h-screen">
                <div class="text-center p-8 bg-white rounded-lg shadow-md">
                    <h1 class="text-2xl font-bold text-emerald-700">💨 POOF! 💨</h1>
                    <h2 class="text-xl font-bold text-emerald-700">Proof Record Deleted</h2>
                    <p class="text-slate-600 mt-2">The proof has been permanently removed from the database.</p>
                    <a href="/" class="mt-6 inline-block px-4 py-2 text-sm font-medium text-white bg-indigo-600 rounded-lg hover:bg-indigo-700">Create New Proof</a>
                </div>
            </body>
            </html>
        """)   
    
@app.route('/api/verify-proof', methods=['POST'])
def verify_proof():
    """
    Verify a COMPLETE proof of funds with ALL signatures and save it.
    This now acts as the "finalize" endpoint.
    """
    try:
        data = request.json        
        addresses = data.get('addresses', [])
        signatures = data.get('signatures', {})
        proof_name = data.get('proof_name')
        target_amount = data.get('target_amount')
        expiry_date = data.get('expiry_date')

        # The single 'message' is no longer needed here, it's inside the 'addresses' list
        if not all([addresses, signatures, proof_name]):
            return jsonify({'error': 'Missing required fields for finalization'}), 400

        # Pass only addresses and signatures to the updated validation function
        validation_result = BitcoinProofOfFunds.validate_proof_data(
            addresses, signatures
        )

        if validation_result['valid']:
            proof_id = secrets.token_urlsafe(32)
            
            delete_token = secrets.token_urlsafe(32) # The new secret delete token

            total_amount = sum([addr.get('balance', 0) for addr in addresses])
            
            # Extract all messages to save them
            all_messages = [addr.get('message', '') for addr in addresses]

            expiry_dt = None
            if expiry_date:
                try:
                    # First, try to parse a full ISO 8601 timestamp (e.g., from JavaScript's toISOString())
                    # The replace() handles the 'Z' for Zulu/UTC time.
                    expiry_dt = datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
                except ValueError:
                    # If that fails, it's likely a simple date format (e.g., '2025-06-30')
                    # from an <input type="date"> element.
                    expiry_dt = datetime.strptime(expiry_date, '%Y-%m-%d')
            
            proof_record = ProofRecord(
                proof_id=proof_id,
                proof_name=proof_name,
                delete_token=delete_token,
                addresses=json.dumps(addresses),
                total_amount=total_amount,
                target_amount=target_amount,
                # Store all messages as a JSON string in the message field
                message=json.dumps(all_messages),
                signatures=json.dumps(signatures),
                expiry_date=expiry_dt,
                verified=True
            )
            db.session.add(proof_record)
            db.session.commit()
            logger.info(f"Proof {proof_id} saved successfully")
        else:
            return jsonify({
                'error': 'Final validation failed. Please re-check signatures.',
                'details': validation_result['results']
            }), 400

        return jsonify({
            'proof_id': proof_id,
            'delete_token': delete_token,
            'verified': True,
            'message': 'Proof finalized successfully.'
        })
        
    except Exception as e:
        logger.error(f"Error finalizing proof: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/proof/<proof_id>', methods=['GET'])
def get_proof(proof_id):
    try:
        proof = ProofRecord.query.filter_by(proof_id=proof_id).first()
        if not proof:
            return jsonify({'error': 'Proof not found'}), 404
        
        proof_dict = proof.to_dict()
        proof_dict['timestamp'] = proof.timestamp.isoformat()
        if proof.expiry_date:
            proof_dict['expiry_date'] = proof.expiry_date.isoformat()

        logger.info(f"Retrieved proof {proof_id}")
        return jsonify(proof_dict)
        
    except Exception as e:
        logger.error(f"Error retrieving proof: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/address-balance/<address>', methods=['GET'])
def get_address_balance(address):
    try:
        logger.info(f"Fetching balance for address: {address[:10]}...")
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
    try:
        data = request.json
        signature = data.get('signature')
        message = data.get('message')
        if not all([signature, message]):
            return jsonify({'error': 'Missing signature or message'}), 400
        is_valid = BitcoinProofOfFunds.verify_message_signature(address, signature, message)
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
    try:
        proofs = ProofRecord.query.order_by(ProofRecord.timestamp.desc()).limit(50).all()
        proof_list = []
        for proof in proofs:
            p_dict = proof.to_dict()
            p_dict['timestamp'] = proof.timestamp.isoformat()
            if proof.expiry_date:
                p_dict['expiry_date'] = proof.expiry_date.isoformat()
            proof_list.append(p_dict)
        return jsonify({'proofs': proof_list, 'count': len(proof_list)})
    except Exception as e:
        logger.error(f"Error listing proofs: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
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
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'bitcoin_utils': 'available' if BitcoinProofOfFunds else 'unavailable'
    })

@app.errorhandler(404)
def not_found(error):
    # This will now serve a basic 404 page if a proof is not found
    return "<h1>404 - Not Found</h1><p>The page you are looking for does not exist.</p>", 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    logger.info("Starting Bitcoin Proof of Funds server...")
    app.run(debug=True, host='0.0.0.0', port=3000)