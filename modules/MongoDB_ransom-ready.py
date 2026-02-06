"""
MongoDB Honeypot Module for OpenCanary - Enhanced Ransomware Trap Edition

This module emulates a MongoDB instance to lure attackers into authentication traps.
It implements the MongoDB wire protocol and includes advanced ransomware detection
with canary token integration for tracking attacker behavior.

Features:
- Allows attackers to "drop" databases (fake deletions)
- Captures attacker-deployed ransom notes
- Serves synthetic encrypted data mixed with canary tokens
- Extracts crypto addresses, emails, and contact info from ransom notes
- Tracks data exfiltration attempts
- Embeds multiple canary token types (web bugs, DNS, credit cards, AWS tokens, etc.)
"""

from opencanary.modules import CanaryService
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from opencanary import logger
import struct
import json
import re
import os
import random
import base64
import time
from datetime import datetime, timedelta

def ObjectId():
    """Generate a fake MongoDB ObjectId-like string"""
    timestamp = hex(int(time.time()))[2:]
    random_part = ''.join(random.choices('0123456789abcdef', k=16))
    return timestamp + random_part

class MongoDBProtocol(Protocol):
    """
    Implements MongoDB wire protocol to handle incoming connections.
    Supports OP_QUERY, OP_MSG (MongoDB 3.6+), and logs all authentication attempts.
    Includes ransomware trap functionality with canary token deployment.
    """
    
    def __init__(self, factory):
        self.factory = factory
        self.buffer = b''
        self.authenticated = False
        
        # Ransomware trap state (per-connection)
        self.ransomed = False
        self.ransom_note = None
        self.ransom_db_name = None
        self.ransom_collection_name = None
        self.deleted_databases = []
        self.crypto_addresses = {
            'bitcoin': [],
            'ethereum': [],
            'monero': []
        }
        self.contact_info = {
            'emails': [],
            'telegram': [],
            'other': []
        }
        self.exfiltration_stats = {
            'documents_sent': 0,
            'bytes_sent': 0,
            'canary_tokens_sent': 0,
            'start_time': None
        }
        
    def connectionMade(self):
        """Log new connection attempts"""
        self.factory.log_connection(self.transport)
        
    def dataReceived(self, data):
        """
        Process incoming MongoDB wire protocol messages.
        Handles OP_QUERY (legacy) and OP_MSG (modern) opcodes.
        """
        self.buffer += data
        
        # MongoDB message format: length (4 bytes), requestID (4), responseTo (4), opCode (4), payload
        while len(self.buffer) >= 16:
            # Parse message header
            if len(self.buffer) < 4:
                break
                
            msg_length = struct.unpack('<i', self.buffer[0:4])[0]
            
            if len(self.buffer) < msg_length:
                break  # Wait for complete message
                
            # Extract full message
            message = self.buffer[:msg_length]
            self.buffer = self.buffer[msg_length:]
            
            try:
                self.process_message(message)
            except Exception as e:
                self.factory.log_error(self.transport, str(e))
                
    def process_message(self, message):
        """Process a complete MongoDB wire protocol message"""
        if len(message) < 16:
            return
            
        msg_length, request_id, response_to, opcode = struct.unpack('<iiii', message[0:16])
        payload = message[16:]
        
        # OP_QUERY (2004) - Legacy query operation
        if opcode == 2004:
            self.handle_op_query(request_id, payload)
            
        # OP_MSG (2013) - Modern message operation (MongoDB 3.6+)
        elif opcode == 2013:
            self.handle_op_msg(request_id, payload)
            
        # OP_REPLY (1) - Should not receive this from client
        # OP_INSERT (2002), OP_UPDATE (2001), OP_DELETE (2006) - Legacy operations
        else:
            # Send generic error response
            self.send_error_response(request_id, f"Unsupported opcode: {opcode}")
    
    def handle_op_query(self, request_id, payload):
        """Handle OP_QUERY messages (legacy MongoDB protocol)"""
        if len(payload) < 8:
            return
            
        flags = struct.unpack('<i', payload[0:4])[0]
        
        # Parse collection name (null-terminated string)
        null_pos = payload.find(b'\x00', 4)
        if null_pos == -1:
            return
            
        collection_name = payload[4:null_pos].decode('utf-8', errors='ignore')
        
        # Extract BSON query document
        query_start = null_pos + 1 + 8  # +1 for null, +8 for numberToSkip and numberToReturn
        if query_start < len(payload):
            try:
                query_doc = self.parse_bson(payload[query_start:])
                self.handle_query(request_id, collection_name, query_doc)
            except:
                self.send_error_response(request_id, "Invalid BSON")
    
    def handle_op_msg(self, request_id, payload):
        """Handle OP_MSG messages (modern MongoDB protocol)"""
        if len(payload) < 5:
            return
            
        flag_bits = struct.unpack('<I', payload[0:4])[0]
        
        # Store raw payload for potential document extraction
        self.last_payload = payload
        
        # Parse sections
        pos = 4
        doc = {}
        document_sequences = {}
        
        while pos < len(payload):
            if pos >= len(payload):
                break
                
            section_kind = payload[pos]
            pos += 1
            
            if section_kind == 0:  # Single document body
                try:
                    doc = self.parse_bson(payload[pos:])
                    # Move position forward by document length
                    if len(payload[pos:]) >= 4:
                        doc_length = struct.unpack('<i', payload[pos:pos+4])[0]
                        pos += doc_length
                except:
                    break
                    
            elif section_kind == 1:  # Document sequence
                # Format: identifier (null-terminated string) + size (int32) + documents  
                # Note: size includes the identifier length + null + size field itself
                try:
                    null_pos = payload.find(b'\x00', pos)
                    if null_pos == -1:
                        break
                    identifier = payload[pos:null_pos].decode('utf-8', errors='ignore')
                    pos = null_pos + 1
                    
                    if pos + 4 > len(payload):
                        break
                    sequence_size = struct.unpack('<i', payload[pos:pos+4])[0]
                    pos += 4
                    
                    # Parse documents in sequence
                    # The size includes everything after the size field
                    sequence_docs = []
                    sequence_end = min(pos + sequence_size - 4, len(payload))  
                    
                    while pos < sequence_end:
                        if pos + 4 > len(payload):
                            break
                        doc_len = struct.unpack('<i', payload[pos:pos+4])[0]
                        if doc_len < 5 or pos + doc_len > len(payload):
                            break
                        sequence_doc = self.parse_bson(payload[pos:pos+doc_len])
                        if sequence_doc:  # Only add if we got something
                            sequence_docs.append(sequence_doc)
                        pos += doc_len
                    
                    # Use 'documents' as the key
                    if sequence_docs:  # Only add if we actually parsed documents
                        document_sequences['documents'] = sequence_docs
                except Exception as e:
                    # Log parsing errors
                    self.factory.log_error(self.transport, f"Section 1 parse error: {str(e)}")
                    break
            else:
                # Unknown section type, stop parsing
                break
        
        # Add document sequences to the main doc
        if document_sequences:
            doc.update(document_sequences)
        
        try:
            # Check if this is an authentication attempt
            if 'saslStart' in doc or 'authenticate' in doc:
                self.handle_auth_attempt(request_id, doc)
            # Check for isMaster/hello command
            elif 'ismaster' in doc or 'isMaster' in doc or 'hello' in doc:
                self.send_ismaster_response(request_id)
            # Check for listDatabases
            elif 'listDatabases' in doc:
                self.handle_list_databases(request_id, doc)
            # Check for dropDatabase
            elif 'dropDatabase' in doc:
                self.handle_drop_database(request_id, doc)
            # Check for insert (potential ransom note deployment)
            elif 'insert' in doc:
                self.handle_insert(request_id, doc)
            # Check for find (potential data exfiltration)
            elif 'find' in doc:
                self.handle_find(request_id, doc)
            # Other commands
            else:
                command = list(doc.keys())[0] if doc else 'unknown'
                
                # Log all commands to help debug
                self.factory.log_command(self.transport, command, doc)
                
                # Check if it's a dropDatabase command (sent as {"dropDatabase": 1} with $db field)
                if command.lower() == 'dropdatabase' or command == 'dropDatabase':
                    self.handle_drop_database(request_id, doc)
                else:
                    self.send_error_response(request_id, "Authentication required")
        except Exception as e:
            self.factory.log_error(self.transport, str(e))
            self.send_error_response(request_id, "Invalid BSON")
    
    def handle_query(self, request_id, collection, query):
        """Handle query operations and check for authentication"""
        self.factory.log_command(self.transport, f"query:{collection}", query)
        
        # Check for authentication queries
        if '$cmd' in collection and query:
            if 'authenticate' in query or 'saslStart' in query:
                self.handle_auth_attempt(request_id, query)
                return
            elif 'ismaster' in query or 'isMaster' in query:
                self.send_ismaster_response(request_id)
                return
            elif 'listDatabases' in query:
                self.handle_list_databases(request_id, query)
                return
            elif 'dropDatabase' in query:
                self.handle_drop_database(request_id, query)
                return
                
        # Require authentication for other queries
        self.send_error_response(request_id, "Authentication required")
    
    def handle_auth_attempt(self, request_id, auth_doc):
        """Log authentication attempts and send response"""
        username = auth_doc.get('user', auth_doc.get('username', 'unknown'))
        mechanism = auth_doc.get('mechanism', 'SCRAM-SHA-1')

        # If username is unknown, try to extract it from the SASL binary payload
        if username == 'unknown' and 'payload' in auth_doc:
            payload = auth_doc['payload']
            if isinstance(payload, bytes):
                payload_str = payload.decode('utf-8', errors='ignore')
                # SCRAM-SHA-1/256 client first message: n,,n=user,r=nonce
                match = re.search(r'n=(.+?),', payload_str)
                if match:
                    username = match.group(1)
        
        # Log the authentication attempt
        # Convert bytes to string for JSON logging
        printable_doc = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in auth_doc.items()}
        
        self.factory.log_auth_attempt(
            self.transport,
            username,
            mechanism,
            printable_doc
        )
        
        # Send authentication failure response
        self.send_auth_failure(request_id)
    
    def handle_list_databases(self, request_id, query):
        """Handle listDatabases command - shows fake databases or ransom DB"""
        self.factory.log_command(self.transport, "listDatabases", query)
        
        if self.ransomed:
            # After ransomware deployment, show ONLY the ransom database
            response_doc = {
                'databases': [
                    {
                        'name': self.ransom_db_name,
                        'sizeOnDisk': 4096,
                        'empty': False
                    }
                ],
                'totalSize': 4096,
                'ok': 1.0
            }
        else:
            # Before ransomware, show fake databases (the bait!)
            fake_dbs = self.factory.get_fake_databases()
            response_doc = {
                'databases': fake_dbs,
                'totalSize': sum(db['sizeOnDisk'] for db in fake_dbs),
                'ok': 1.0
            }
        
        self.send_op_msg_response(request_id, response_doc)
    
    def handle_drop_database(self, request_id, query):
        """Handle dropDatabase - fake deletion, always succeeds"""
        # PyMongo sends dropDatabase: 1 and the db name is in $db
        # Or it might be dropDatabase: "dbname"
        db_name = query.get('$db', 'unknown')
        
        # Sometimes the database name is the value of dropDatabase key
        if 'dropDatabase' in query and isinstance(query['dropDatabase'], str):
            db_name = query['dropDatabase']
        
        # Track which databases they "deleted"
        if db_name not in self.deleted_databases:
            self.deleted_databases.append(db_name)
        
        # Log the deletion attempt
        self.factory.log_database_drop(
            self.transport,
            db_name,
            len(self.deleted_databases)
        )
        
        # Always respond with success (fake deletion)
        response_doc = {
            'dropped': db_name,
            'ok': 1.0
        }
        
        self.send_op_msg_response(request_id, response_doc)
    
    def handle_insert(self, request_id, query):
        """Handle insert - detect ransom note deployment"""
        collection = query.get('insert', 'unknown')
        documents = query.get('documents', [])
        db_name = query.get('$db', 'unknown')
        
        # Log the insert
        self.factory.log_command(self.transport, f"insert:{db_name}.{collection}", query)
        
        # If documents is empty but this looks like a ransom note, extract from raw payload
        if not documents and self.is_ransom_note_by_name(db_name, collection):
            # Try to extract text content from the raw payload
            if hasattr(self, 'last_payload'):
                try:
                    # Convert payload to string, looking for readable text
                    payload_str = self.last_payload.decode('utf-8', errors='ignore')
                    
                    # Extract any readable text chunks (likely the ransom note)
                    # Look for Bitcoin addresses as markers
                    if 'bc1' in payload_str or 'BTC' in payload_str or '@' in payload_str:
                        documents = [{
                            'extracted_from_payload': payload_str,
                            'note': 'Extracted from raw wire protocol payload'
                        }]
                except:
                    documents = [{'raw_query': str(query), 'note': 'Could not parse, check logs'}]
        
        # Check if this is a ransom note deployment
        if self.is_ransom_note(db_name, collection, documents):
            self.deploy_ransom_note(db_name, collection, documents)
        
        # Always respond with success
        response_doc = {
            'n': len(documents) if documents else 1,
            'ok': 1.0
        }
        
        self.send_op_msg_response(request_id, response_doc)
    
    def is_ransom_note_by_name(self, db_name, collection):
        """Quick check if db/collection name indicates ransom note"""
        keywords = ['readme', 'warning', 'pwned', 'hacked', 'encrypted', 
                   'attention', 'ransom', 'decrypt', 'restore', 'recover']
        return any(kw in db_name.lower() or kw in collection.lower() for kw in keywords)
    
    def is_ransom_note(self, db_name, collection, documents):
        """Detect if this is a ransom note based on keywords"""
        # Check database name for ransom keywords
        db_keywords = ['readme', 'warning', 'pwned', 'hacked', 'encrypted', 
                       'attention', 'ransom', 'decrypt', 'restore', 'recover']
        
        db_lower = db_name.lower()
        if any(keyword in db_lower for keyword in db_keywords):
            return True
        
        # Check collection name
        coll_lower = collection.lower()
        if any(keyword in coll_lower for keyword in db_keywords):
            return True
        
        # Check document content for ransom indicators
        doc_str = json.dumps(documents).lower()
        ransom_indicators = ['bitcoin', 'btc', 'ethereum', 'eth', 'monero', 'xmr',
                            'encrypt', 'decrypt', 'ransom', 'payment', 'restore',
                            'recover', 'contact', 'deadline', 'wallet']
        
        if any(indicator in doc_str for indicator in ransom_indicators):
            return True
        
        return False
    
    def deploy_ransom_note(self, db_name, collection, documents):
        """Process ransom note deployment - extract all intelligence"""
        self.ransomed = True
        self.ransom_db_name = db_name
        self.ransom_collection_name = collection
        self.ransom_note = documents
        
        # Combine all document content for analysis
        # Handle both list of docs and single doc
        if isinstance(documents, list):
            full_content = ' '.join([self.doc_to_string(doc) for doc in documents])
        else:
            full_content = self.doc_to_string(documents)
        
        # Extract crypto addresses
        self.crypto_addresses['bitcoin'] = self.extract_bitcoin_addresses(full_content)
        self.crypto_addresses['ethereum'] = self.extract_ethereum_addresses(full_content)
        self.crypto_addresses['monero'] = self.extract_monero_addresses(full_content)
        
        # Extract contact information
        self.contact_info['emails'] = self.extract_emails(full_content)
        self.contact_info['telegram'] = self.extract_telegram(full_content)
        self.contact_info['other'] = self.extract_other_contacts(full_content)
        
        # Log the complete ransom deployment
        self.factory.log_ransom_deployment(
            self.transport,
            db_name,
            collection,
            full_content[:10000],  # Limit to 10KB for logging
            len(full_content),
            self.crypto_addresses,
            self.contact_info,
            self.deleted_databases
        )
    
    def doc_to_string(self, doc):
        """Convert a document to string for text analysis"""
        if isinstance(doc, dict):
            # Recursively extract all string values
            result = []
            for key, value in doc.items():
                if isinstance(value, str):
                    result.append(value)
                elif isinstance(value, dict):
                    result.append(self.doc_to_string(value))
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            result.append(item)
                        elif isinstance(item, dict):
                            result.append(self.doc_to_string(item))
            return ' '.join(result)
        elif isinstance(doc, str):
            return doc
        else:
            return str(doc)
    
    def handle_find(self, request_id, query):
        """Handle find command - serve synthetic data with canary tokens"""
        collection = query.get('find', 'unknown')
        db_name = query.get('$db', 'unknown')
        filter_doc = query.get('filter', {})
        limit = query.get('limit', 100)
        
        # Track exfiltration attempt
        if self.exfiltration_stats['start_time'] is None:
            self.exfiltration_stats['start_time'] = datetime.utcnow()
        
        self.factory.log_command(self.transport, f"find:{db_name}.{collection}", query)
        
        if self.ransomed and db_name == self.ransom_db_name:
            # Return the ransom note they deployed
            response_doc = {
                'cursor': {
                    'firstBatch': self.ransom_note,
                    'id': 0,
                    'ns': f'{db_name}.{collection}'
                },
                'ok': 1.0
            }
        else:
            # Generate synthetic encrypted data with canary tokens
            synthetic_docs = self.factory.generate_synthetic_data(
                collection, 
                limit,
                self.exfiltration_stats
            )
            
            response_doc = {
                'cursor': {
                    'firstBatch': synthetic_docs,
                    'id': 123456789 if limit > 100 else 0,  # Fake cursor for more data
                    'ns': f'{db_name}.{collection}'
                },
                'ok': 1.0
            }
            
            # Log exfiltration stats
            self.factory.log_data_exfiltration(
                self.transport,
                db_name,
                collection,
                self.exfiltration_stats
            )
        
        self.send_op_msg_response(request_id, response_doc)
    
    def extract_bitcoin_addresses(self, text):
        """Extract Bitcoin addresses from text"""
        # bc1 (Bech32), legacy (1...), P2SH (3...)
        patterns = [
            r'\b(bc1[a-zA-HJ-NP-Z0-9]{39,59})\b',  # Bech32
            r'\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b'  # Legacy & P2SH
        ]
        addresses = []
        for pattern in patterns:
            addresses.extend(re.findall(pattern, text))
        return list(set(addresses))
    
    def extract_ethereum_addresses(self, text):
        """Extract Ethereum addresses from text"""
        pattern = r'\b(0x[a-fA-F0-9]{40})\b'
        return list(set(re.findall(pattern, text)))
    
    def extract_monero_addresses(self, text):
        """Extract Monero addresses from text"""
        pattern = r'\b(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b'
        return list(set(re.findall(pattern, text)))
    
    def extract_emails(self, text):
        """Extract email addresses from text"""
        pattern = r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b'
        return list(set(re.findall(pattern, text)))
    
    def extract_telegram(self, text):
        """Extract Telegram handles from text"""
        pattern = r'@([a-zA-Z0-9_]{5,32})\b'
        return list(set(re.findall(pattern, text)))
    
    def extract_other_contacts(self, text):
        """Extract other contact methods (TOX, Session, etc.)"""
        patterns = [
            (r'\b([A-F0-9]{76})\b', 'tox_id'),  # TOX ID
            (r'\b(05[a-f0-9]{64})\b', 'session_id'),  # Session ID
        ]
        contacts = []
        for pattern, contact_type in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                contacts.append({'type': contact_type, 'value': match})
        return contacts
    
    def send_ismaster_response(self, request_id):
        """Send isMaster/hello response with MongoDB version info"""
        response_doc = {
            'ismaster': True,
            'maxBsonObjectSize': 16777216,
            'maxMessageSizeBytes': 48000000,
            'maxWriteBatchSize': 100000,
            'localTime': datetime.utcnow().isoformat(),
            'logicalSessionTimeoutMinutes': 30,
            'connectionId': 1,
            'minWireVersion': 0,
            'maxWireVersion': 8,
            'readOnly': False,
            'ok': 1.0,
            'version': self.factory.mongo_version
        }
        
        self.send_op_msg_response(request_id, response_doc)
    
    def send_auth_failure(self, request_id):
        """Send authentication failure response"""
        response_doc = {
            'ok': 0.0,
            'errmsg': 'Authentication failed.',
            'code': 18,
            'codeName': 'AuthenticationFailed'
        }
        
        self.send_op_msg_response(request_id, response_doc)
    
    def send_error_response(self, request_id, error_msg):
        """Send generic error response"""
        response_doc = {
            'ok': 0.0,
            'errmsg': error_msg,
            'code': 13,
            'codeName': 'Unauthorized'
        }
        
        self.send_op_msg_response(request_id, response_doc)
    
    def send_op_msg_response(self, request_id, doc):
        """Send OP_MSG response (opcode 2013)"""
        bson_doc = self.encode_bson(doc)
        
        # OP_MSG format: flagBits (4 bytes) + kind (1 byte) + document
        flag_bits = struct.pack('<I', 0)  # No flags
        kind = b'\x00'  # Kind 0: Body
        payload = flag_bits + kind + bson_doc
        
        # Message header: length, requestID, responseTo, opCode
        msg_length = 16 + len(payload)
        response_to = request_id
        opcode = 2013  # OP_MSG
        
        header = struct.pack('<iiii', msg_length, 9999, response_to, opcode)
        
        self.transport.write(header + payload)
    
    def parse_bson(self, data):
        """
        Minimal BSON parser for extracting key fields.
        This is simplified and handles common cases for authentication.
        """
        if len(data) < 5:
            return {}
            
        doc_length = struct.unpack('<i', data[0:4])[0]
        if len(data) < doc_length:
            return {}
            
        result = {}
        pos = 4
        
        while pos < len(data) - 1:
            element_type = data[pos]
            if element_type == 0:  # End of document
                break
                
            pos += 1
            
            # Extract field name (null-terminated)
            null_pos = data.find(b'\x00', pos)
            if null_pos == -1:
                break
                
            field_name = data[pos:null_pos].decode('utf-8', errors='ignore')
            pos = null_pos + 1
            
            # Extract value based on type
            if element_type == 0x02:  # String
                if pos + 4 > len(data):
                    break
                str_length = struct.unpack('<i', data[pos:pos+4])[0]
                pos += 4
                if pos + str_length > len(data):
                    break
                value = data[pos:pos+str_length-1].decode('utf-8', errors='ignore')
                pos += str_length
                result[field_name] = value
            elif element_type == 0x05:  # Binary data
                if pos + 4 > len(data):
                    break
                bin_length = struct.unpack('<i', data[pos:pos+4])[0]
                subtype = data[pos+4]
                pos += 5
                if pos + bin_length > len(data):
                    break
                value = data[pos:pos+bin_length]
                pos += bin_length
                result[field_name] = value
            elif element_type == 0x10:  # Int32
                if pos + 4 > len(data):
                    break
                value = struct.unpack('<i', data[pos:pos+4])[0]
                pos += 4
                result[field_name] = value
            elif element_type == 0x08:  # Boolean
                if pos + 1 > len(data):
                    break
                value = data[pos] != 0
                pos += 1
                result[field_name] = value
            elif element_type == 0x01:  # Double
                if pos + 8 > len(data):
                    break
                value = struct.unpack('<d', data[pos:pos+8])[0]
                pos += 8
                result[field_name] = value
            elif element_type == 0x04:  # Array
                if pos + 4 > len(data):
                    break
                arr_length = struct.unpack('<i', data[pos:pos+4])[0]
                if pos + arr_length > len(data):
                    break
                # Recursively parse array (simplified)
                arr_data = data[pos:pos+arr_length]
                result[field_name] = self.parse_bson_array(arr_data)
                pos += arr_length
            elif element_type == 0x03:  # Embedded document
                if pos + 4 > len(data):
                    break
                subdoc_length = struct.unpack('<i', data[pos:pos+4])[0]
                if pos + subdoc_length > len(data):
                    break
                # Recursively parse
                subdoc_data = data[pos:pos+subdoc_length]
                result[field_name] = self.parse_bson(subdoc_data)
                pos += subdoc_length
            else:
                # Skip unknown types
                break
                
        return result
    
    def parse_bson_array(self, data):
        """Parse BSON array"""
        if len(data) < 5:
            return []
        
        result = []
        doc = self.parse_bson(data)
        # Array elements are keyed by index as strings
        for i in range(len(doc)):
            if str(i) in doc:
                result.append(doc[str(i)])
        return result
    
    def encode_bson(self, doc):
        """
        Minimal BSON encoder for responses.
        Handles strings, numbers, booleans, and nested documents.
        """
        body = b''
        
        for key, value in doc.items():
            if isinstance(value, str):
                # String type (0x02)
                body += b'\x02' + key.encode('utf-8') + b'\x00'
                str_bytes = value.encode('utf-8') + b'\x00'
                body += struct.pack('<i', len(str_bytes)) + str_bytes
            elif isinstance(value, bool):
                # Boolean type (0x08)
                body += b'\x08' + key.encode('utf-8') + b'\x00'
                body += b'\x01' if value else b'\x00'
            elif isinstance(value, int):
                # Int32 type (0x10)
                body += b'\x10' + key.encode('utf-8') + b'\x00'
                body += struct.pack('<i', value)
            elif isinstance(value, float):
                # Double type (0x01)
                body += b'\x01' + key.encode('utf-8') + b'\x00'
                body += struct.pack('<d', value)
            elif isinstance(value, list):
                # Array type (0x04)
                body += b'\x04' + key.encode('utf-8') + b'\x00'
                array_doc = {str(i): v for i, v in enumerate(value)}
                array_bson = self.encode_bson(array_doc)
                body += array_bson
            elif isinstance(value, dict):
                # Embedded document type (0x03)
                body += b'\x03' + key.encode('utf-8') + b'\x00'
                subdoc_bson = self.encode_bson(value)
                body += subdoc_bson
        
        body += b'\x00'  # End of document
        
        # Prepend document length
        doc_length = len(body) + 4
        return struct.pack('<i', doc_length) + body
    
    def connectionLost(self, reason):
        """Log connection closure and reset state"""
        # Log any final exfiltration stats
        if self.exfiltration_stats['documents_sent'] > 0:
            duration = (datetime.utcnow() - self.exfiltration_stats['start_time']).total_seconds()
            self.factory.log_final_exfiltration_stats(
                self.transport,
                self.exfiltration_stats,
                duration
            )
        
        self.factory.log_disconnect(self.transport)


class CanaryMongoDB(Factory, CanaryService):
    """
    MongoDB Honeypot Service for OpenCanary
    
    Emulates a MongoDB instance on the configured port (default 27017).
    Logs all connection attempts, commands, and authentication attempts.
    Includes ransomware trap with canary token integration.
    """
    
    NAME = 'mongodb'
    
    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal('mongodb.port', default=27017))
        self.mongo_version = config.getVal('mongodb.version', default='4.4.6')
        self.listen_addr = config.getVal('device.listen_addr', default='')
        self.logtype = 20001  # LOG_MONGODB
        
        # Ransomware trap configuration
        self.ransom_trap_enabled = config.getVal('mongodb.ransom_trap.enabled', default=True)
        self.fake_db_names = config.getVal('mongodb.ransom_trap.fake_databases', 
            default=['admin', 'config', 'local', 'customers', 'financial_data', 
                    'orders', 'users', 'backups', 'analytics', 'reports'])
        
        # Canary token configuration
        self.canary_tokens = config.getVal('mongodb.ransom_trap.canary_tokens', default={})
        
        # Synthetic data configuration
        self.docs_per_collection = config.getVal('mongodb.ransom_trap.documents_per_collection', default=1000)
        self.doc_size_kb = config.getVal('mongodb.ransom_trap.document_size_kb', default=2)
    
    def buildProtocol(self, addr):
        """Factory method to build protocol instances"""
        return MongoDBProtocol(self)
    
    def get_fake_databases(self):
        """Generate fake database list for bait"""
        fake_dbs = []
        for db_name in self.fake_db_names:
            # Assign realistic sizes
            if db_name in ['admin', 'config', 'local']:
                size = random.randint(32768, 131072)  # 32KB - 128KB
            elif db_name in ['backups', 'analytics']:
                size = random.randint(4194304, 10485760)  # 4MB - 10MB
            else:
                size = random.randint(262144, 2097152)  # 256KB - 2MB
            
            fake_dbs.append({
                'name': db_name,
                'sizeOnDisk': size,
                'empty': False
            })
        
        return fake_dbs
    
    def generate_synthetic_data(self, collection_name, limit, exfil_stats):
        """Generate synthetic encrypted data with embedded canary tokens"""
        documents = []
        canary_count = 0
        
        # Get canary tokens from config
        canary_ccs = self.canary_tokens.get('credit_cards', [])
        canary_emails = self.canary_tokens.get('emails', [])
        canary_web_bugs = self.canary_tokens.get('web_bugs', [])
        canary_dns = self.canary_tokens.get('dns_tokens', [])
        canary_aws = self.canary_tokens.get('aws_tokens', [])
        canary_saml = self.canary_tokens.get('saml_tokens', [])
        
        # Normalize collection name (handle both 'customers' and 'records' for customers data)
        coll_lower = collection_name.lower()
        
        for i in range(min(limit, self.docs_per_collection)):
            doc = {
                '_id': str(ObjectId()),
                'record_id': i,
                'collection_source': collection_name,
                'encrypted_at': datetime.utcnow().isoformat()
            }
            
            # Collection-specific data generation
            # Match on partial names to be flexible
            if 'customer' in coll_lower or 'record' in coll_lower or coll_lower == 'customers':
                doc['customer_id'] = f'CUST-{i:06d}'
                doc['name'] = self.generate_fake_name()
                
                # 5% chance of canary email
                if canary_emails and random.random() < 0.05:
                    doc['email'] = random.choice(canary_emails)
                    canary_count += 1
                else:
                    doc['email'] = self.generate_fake_email()
                
                # 5% chance of canary credit card
                if canary_ccs and random.random() < 0.05:
                    doc['payment_card'] = {
                        'number_encrypted': random.choice(canary_ccs),
                        'last_four': random.choice(canary_ccs)[-4:] if canary_ccs else '0000'
                    }
                    canary_count += 1
                else:
                    fake_cc = self.generate_fake_cc()
                    doc['payment_card'] = {
                        'number_encrypted': fake_cc,
                        'last_four': fake_cc[-4:]
                    }
                
                # 3% chance of web bug URL
                if canary_web_bugs and random.random() < 0.03:
                    doc['profile_picture'] = random.choice(canary_web_bugs)
                    canary_count += 1
            
            elif 'financial' in coll_lower or 'transaction' in coll_lower:
                doc['transaction_id'] = f'TXN-{i:08d}'
                doc['amount'] = round(random.uniform(10, 50000), 2)
                
                # 10% chance of canary credit card in transactions
                if canary_ccs and random.random() < 0.10:
                    doc['card_number'] = random.choice(canary_ccs)
                    canary_count += 1
                
                # 5% chance of web bug as receipt URL
                if canary_web_bugs and random.random() < 0.05:
                    doc['receipt_url'] = random.choice(canary_web_bugs)
                    canary_count += 1
            
            elif 'user' in coll_lower:
                doc['username'] = f'user_{i:05d}'
                
                # 5% chance of canary email
                if canary_emails and random.random() < 0.05:
                    doc['email'] = random.choice(canary_emails)
                    canary_count += 1
                
                doc['password_hash'] = os.urandom(32).hex()
                doc['created_at'] = (datetime.utcnow() - timedelta(days=random.randint(1, 365))).isoformat()
            
            elif 'api' in coll_lower or 'credential' in coll_lower or 'key' in coll_lower:
                # High-value target: embed AWS and SAML tokens
                if canary_aws and i < len(canary_aws):
                    token = canary_aws[i]
                    doc['service'] = 'aws_production'
                    doc['access_key'] = token.get('access_key', '')
                    doc['secret_key'] = token.get('secret_key', '')
                    doc['session_token'] = token.get('session_token', '')
                    doc['region'] = 'us-east-1'
                    doc['permissions'] = 'admin'
                    canary_count += 1
                elif canary_saml and i < len(canary_saml):
                    doc['service'] = 'corporate_sso'
                    doc['saml_token'] = canary_saml[i]
                    if canary_dns:
                        doc['identity_provider'] = f'https://{random.choice(canary_dns)}/saml/idp'
                        canary_count += 1
                    canary_count += 1
                else:
                    doc['service'] = random.choice(['github', 'gitlab', 'slack', 'stripe'])
                    doc['api_key'] = f'fake_key_{os.urandom(16).hex()}'
            
            elif 'backup' in coll_lower:
                # 10% chance of MySQL dump URL canary
                if canary_web_bugs and random.random() < 0.10:
                    doc['backup_url'] = random.choice(canary_web_bugs)
                    doc['backup_type'] = 'mysql_dump'
                    doc['backup_size'] = f'{random.randint(1, 10)} GB'
                    canary_count += 1
                
                # DNS canary as backup server
                if canary_dns and random.random() < 0.05:
                    doc['backup_server'] = f'{random.choice(canary_dns)}:3306'
                    canary_count += 1
            
            # Add encrypted blob to all documents
            blob_size = self.doc_size_kb * 1024
            doc['encrypted_data'] = os.urandom(blob_size // 2).hex()  # Half size in hex
            
            documents.append(doc)
        
        # Update exfiltration stats
        exfil_stats['documents_sent'] += len(documents)
        exfil_stats['bytes_sent'] += sum(len(json.dumps(doc)) for doc in documents)
        exfil_stats['canary_tokens_sent'] += canary_count
        
        return documents
    
    def generate_fake_name(self):
        """Generate fake name"""
        first_names = ['John', 'Jane', 'Michael', 'Emily', 'David', 'Sarah', 'Robert', 'Lisa']
        last_names = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis']
        return f'{random.choice(first_names)} {random.choice(last_names)}'
    
    def generate_fake_email(self):
        """Generate fake email"""
        domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'company.com', 'example.com']
        username = f'user{random.randint(1000, 9999)}'
        return f'{username}@{random.choice(domains)}'
    
    def generate_fake_cc(self):
        """Generate fake credit card number"""
        return f'{random.randint(4000, 5999)}{random.randint(1000, 9999):04d}{random.randint(1000, 9999):04d}{random.randint(1000, 9999):04d}'
    
    def log_connection(self, transport):
        """Log new connection"""
        logdata = {'action': 'mongodb.connection'}
        self.log(logdata, transport=transport)
    
    def log_auth_attempt(self, transport, username, mechanism, auth_doc):
        """Log authentication attempt"""
        logdata = {
            'action': 'mongodb.auth_attempt',
            'username': username,
            'mechanism': mechanism,
            'auth_data': str(auth_doc)
        }
        self.log(logdata, transport=transport)
    
    def log_command(self, transport, command, query):
        """Log MongoDB command"""
        logdata = {
            'action': 'mongodb.command',
            'command': command,
            'query': str(query)
        }
        self.log(logdata, transport=transport)
    
    def log_database_drop(self, transport, db_name, total_deleted):
        """Log database drop attempt"""
        logdata = {
            'action': 'mongodb.database_drop',
            'database': db_name,
            'total_deleted': total_deleted
        }
        self.log(logdata, transport=transport)
    
    def log_ransom_deployment(self, transport, db_name, collection, note_content, 
                              note_length, crypto_addresses, contact_info, deleted_dbs):
        """Log ransom note deployment - the golden event!"""
        logdata = {
            'action': 'mongodb.ransomware_detected',
            'ransom_db': db_name,
            'ransom_collection': collection,
            'ransom_note': note_content,
            'note_length': note_length,
            'bitcoin_addresses': crypto_addresses.get('bitcoin', []),
            'ethereum_addresses': crypto_addresses.get('ethereum', []),
            'monero_addresses': crypto_addresses.get('monero', []),
            'email_addresses': contact_info.get('emails', []),
            'telegram_handles': contact_info.get('telegram', []),
            'other_contacts': contact_info.get('other', []),
            'databases_deleted': deleted_dbs
        }
        self.log(logdata, transport=transport)
    
    def log_data_exfiltration(self, transport, db_name, collection, exfil_stats):
        """Log data exfiltration attempt"""
        logdata = {
            'action': 'mongodb.data_exfiltration',
            'database': db_name,
            'collection': collection,
            'documents_sent': exfil_stats['documents_sent'],
            'bytes_sent': exfil_stats['bytes_sent'],
            'canary_tokens_sent': exfil_stats['canary_tokens_sent']
        }
        self.log(logdata, transport=transport)
    
    def log_final_exfiltration_stats(self, transport, exfil_stats, duration):
        """Log final exfiltration statistics on disconnect"""
        logdata = {
            'action': 'mongodb.exfiltration_complete',
            'total_documents': exfil_stats['documents_sent'],
            'total_bytes': exfil_stats['bytes_sent'],
            'total_canary_tokens': exfil_stats['canary_tokens_sent'],
            'duration_seconds': duration
        }
        self.log(logdata, transport=transport)
    
    def log_error(self, transport, error):
        """Log protocol error"""
        logdata = {
            'action': 'mongodb.error',
            'error': error
        }
        self.log(logdata, transport=transport)
    
    def log_disconnect(self, transport):
        """Log disconnection"""
        logdata = {'action': 'mongodb.disconnect'}
        self.log(logdata, transport=transport)


CanaryServiceFactory = CanaryMongoDB
