import hashlib
import time
import logging
import json
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, Column, String, Integer, Float, Sequence
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import requests

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

# Database setup
Base = declarative_base()
engine = create_engine('sqlite:///blockchain.db')
Session = sessionmaker(bind=engine)

class Transaction(Base):
    """Class representing a transaction."""
    __tablename__ = 'transactions'
    id = Column(Integer, Sequence('transaction_id_seq'), primary_key=True)
    sender = Column(String)
    recipient = Column(String)
    amount = Column(Float)
    signature = Column(String)

class Block(Base):
    """Class representing a block in the blockchain."""
    __tablename__ = 'blocks'
    id = Column(Integer, Sequence('block_id_seq'), primary_key=True)
    block_number = Column(Integer)
    previous_hash = Column(String)
    nonce = Column(Integer)
    block_hash = Column(String)
    transactions = Column(String)  # Store JSON string of transactions

Base.metadata.create_all(engine)

class Blockchain:
    """Class representing the blockchain."""
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.difficulty = 4  # Difficulty level
        self.block_reward = 50.0  # Reward for mining a block
        self.load_chain_from_db()
        self.nodes = set()  # Set of nodes in the network

    def load_chain_from_db(self) -> None:
        """Load the blockchain from the SQLite database."""
        session = Session()
        blocks = session.query(Block).all()
        for block in blocks:
            transactions = json.loads(block.transactions)
            self.chain.append(block)
            self.pending_transactions = [Transaction(sender=tx['sender'], recipient=tx['recipient'], amount=tx['amount'], signature=tx['signature']) for tx in transactions]
        session.close()

    def create_transaction(self, sender: str, recipient: str, amount: float, private_key: str) -> None:
        """Add a transaction to the list of pending transactions with a signature."""
        if amount <= 0:
            raise ValueError("Transaction amount must be positive.")
        # Sign the transaction
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        tx_data = f"{sender}{recipient}{amount}"
        signature = sk.sign(tx_data.encode()).hex()
        self.pending_transactions.append(Transaction(sender=sender, recipient=recipient, amount=amount, signature=signature))

    def validate_transaction(self, transaction: Transaction) -> bool:
        """Validate a transaction by checking its signature."""
        try:
            vk = VerifyingKey.from_string(bytes.fromhex(transaction.sender), curve=SECP256k1)
            tx_data = f"{transaction.sender}{transaction.recipient}{transaction.amount}"
            return vk.verify(bytes.fromhex(transaction.signature), tx_data.encode())
        except Exception as e:
            logging.warning(f"Transaction validation failed: {e}")
            return False

    def mine(self, miner_address: str) -> Optional[Block]:
        """Mine a block and reward the miner."""
        if not self.pending_transactions:
            logging.warning("No transactions to mine")
            return None
        
        previous_hash = self.chain[-1].block_hash if self.chain else "0" * 64
        block_number = len(self.chain) + 1
        nonce = 0
        
        transactions_json = json.dumps([tx.__dict__ for tx in self.pending_transactions])
        block = Block(block_number=block_number, transactions=transactions_json, previous_hash=previous_hash, nonce=nonce)
        
        while not block.block_hash.startswith('0' * self.difficulty):
            nonce += 1
            block.nonce = nonce
            block.block_hash = self.calculate_hash(block)

        logging.info(f"Block mined: {block.block_hash} with nonce: {nonce}")
        self.chain.append(block)

        # Store block in the database
        session = Session()
        session.add(block)
        session.commit()
        session.close()

        # Clear pending transactions and reward the miner
        self.pending_transactions = [Transaction(sender="System", recipient=miner_address, amount=self.block_reward, signature="")]
        return block

    def calculate_hash(self, block: Block) -> str:
        """Calculate the SHA-256 hash of a block."""
        block_string = f"{block.block_number}{block.transactions}{block.previous_hash}{block.nonce}".encode()
        return hashlib.sha256(block_string).hexdigest()

    def add_node(self, address: str) -> None:
        """Add a node to the network."""
        self.nodes.add(address)

    def replace_chain(self, new_chain: List[Block]) -> None:
        """Replace the chain with a new one if it's longer."""
        if len(new_chain) > len(self.chain):
            self.chain = new_chain
            logging.info("Blockchain synchronized with a new chain.")

app = Flask(__name__)
blockchain = Blockchain()

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    """Endpoint to create a new transaction."""
    data = request.get_json()
    try:
        blockchain.create_transaction(data['sender'], data['recipient'], data['amount'], data['private_key'])
        return jsonify({"message": "Transaction added!"}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route('/mine', methods=['GET'])
def mine_block():
    """Endpoint to mine a new block."""
    miner_address = request.args.get('miner')
    block = blockchain.mine(miner_address)
    if block:
        return jsonify({
            "block_number": block.block_number,
            "block_hash": block.block_hash,
            "transactions": json.loads(block.transactions)
        }), 200
    return jsonify({"error": "No transactions to mine"}), 400

@app.route('/chain', methods=['GET'])
def get_chain():
    """Endpoint to retrieve the blockchain."""
    chain_data = [{
        "block_number": block.block_number,
        "block_hash": block.block_hash,
        "transactions": json.loads(block.transactions)
    } for block in blockchain.chain]
    return jsonify(chain_data), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    """Endpoint to register new nodes."""
    data = request.get_json()
    nodes = data.get('nodes')
    if nodes is None:
        return jsonify({"error": "No nodes provided"}), 400
    for node in nodes:
        blockchain.add_node(node)
    return jsonify({"message": "Nodes added!"}), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    """Consensus algorithm to resolve conflicts."""
    longest_chain = None
    max_length = len(blockchain.chain)

    for node in blockchain.nodes:
        response = requests.get(f'http://{node}/chain')
        if response.status_code == 200:
            length = response.json()['length']
            chain = response.json()['chain']
            if length > max_length:
                max_length = length
                longest_chain = chain

    if longest_chain:
        blockchain.replace_chain(longest_chain)
        return jsonify({"message": "Chain replaced!"}), 200
    return jsonify({"message": "No replacement made."}), 200

if __name__ == "__main__":
    app.run(port=5000, ssl_context='adhoc')  # Replace 'adhoc' with your actual certificate and key file in production
