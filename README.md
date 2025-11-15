# End-to-End Encrypted Chat Application

A secure chat application implementing **Signal Protocol-inspired encryption** with real-time messaging over WebSocket. Features both CLI and web interfaces with local encrypted message history.

## Features

- **End-to-End Encryption**: Messages encrypted using Signal Protocol-inspired cryptography
- **X3DH Key Exchange**: Secure key agreement for establishing encrypted sessions
- **Double Ratchet Algorithm**: Forward secrecy and post-compromise security
- **Real-time Messaging**: WebSocket-based instant message delivery
- **User Authentication**: JWT-based secure authentication
- **Encrypted Local Storage**: Message history encrypted with password-derived keys
- **Dual Interface**: Both CLI and web-based clients
- **Zero-Knowledge Server**: Server never sees plaintext messages

## Security Features

### Cryptographic Primitives

- **Curve25519 (X25519)**: Elliptic curve Diffie-Hellman key exchange
- **Ed25519**: Digital signatures for identity keys
- **AES-256-GCM**: Authenticated encryption for messages
- **HKDF-SHA256**: Key derivation for ratchets
- **PBKDF2-SHA256**: Password-based encryption for local storage

### Security Properties

- **Forward Secrecy**: Compromise of current keys doesn't affect past messages
- **Post-Compromise Security**: Security restored after key compromise
- **Message Unlinkability**: Messages cannot be correlated
- **Deniability**: No cryptographic proof of message authorship
- **Replay Protection**: Each message encrypted with unique key

## Architecture

```
.
├── crypto/                    # Cryptographic implementations
│   ├── primitives.py         # Core crypto operations
│   ├── x3dh.py              # X3DH key exchange
│   └── double_ratchet.py    # Double Ratchet algorithm
├── server/                   # FastAPI server
│   ├── main.py              # Server entry point
│   ├── auth.py              # JWT authentication
│   └── database.py          # User and prekey storage
├── client/                   # Client implementations
│   ├── cli_client.py        # CLI interface
│   └── storage.py           # Encrypted local storage
├── web/                      # Web interface
│   ├── index.html           # Web UI
│   └── static/
│       ├── app.js           # Web client logic
│       └── style.css        # Styling
└── docs/                     # Documentation
    ├── SECURITY_ARCHITECTURE.md
    └── THREAT_MODEL.md
```

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/Secure-Chat-Applications.git
   cd Secure-Chat-Applications
   ```

2. **Create a virtual environment** (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Starting the Server

Run the FastAPI server:

```bash
python -m uvicorn server.main:app --host 0.0.0.0 --port 8000
```

The server will start on `http://localhost:8000`

### Using the CLI Client

Run the CLI client:

```bash
python -m client.cli_client
```

#### CLI Commands

Once connected:

- `/chat <username>` - Start encrypted chat with user
- `/exit` - Exit current chat
- `/users` - List all registered users
- `/online` - List currently online users
- `/history` - Show conversation list
- `/help` - Show help message
- `/quit` - Quit application

#### CLI Workflow

1. **Register or Login**:
   ```
   1. Register
   2. Login
   3. Quit
   Choose an option: 1
   Username: alice
   Password: ********
   ```

2. **Start a Chat**:
   ```
   > /chat bob
   Initialized encrypted session with bob
   [bob] > Hello!
   ```

3. **Send Messages**:
   ```
   [bob] > Hi there! This message is encrypted!
   ```

### Using the Web Client

1. Open your browser and navigate to:
   ```
   http://localhost:8000
   ```

2. **Register or Login** using the web interface

3. **Select a user** from the sidebar to start chatting

4. **Send messages** - all messages are encrypted end-to-end

**Note**: The web client is a simplified implementation. For maximum security, use the CLI client.

## Configuration

### Server Configuration

Edit `server/auth.py` to configure:

```python
SECRET_KEY = "your-secret-key-change-this-in-production"  # Change in production!
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # Token lifetime
```

### Database

By default, the application uses SQLite:
- Server database: `chat.db`
- Client database: `client_data/<username>.db`

For production, consider using PostgreSQL or MySQL by modifying the database URL in `server/database.py`.

## Security Considerations

### For Maximum Security

1. **Use the CLI Client**: The web client has inherent JavaScript limitations
2. **Verify Identity Keys**: Manually verify keys with contacts out-of-band
3. **Use Strong Passwords**: For both account and local storage
4. **Enable TLS**: Use HTTPS/WSS in production
5. **Network Privacy**: Consider using Tor or VPN for metadata protection

### Known Limitations

- **Metadata Leakage**: Server sees who talks to whom and when
- **Trust On First Use**: No automatic key verification
- **Single Device**: No multi-device synchronization
- **Endpoint Security**: Application cannot protect against compromised devices

See [THREAT_MODEL.md](docs/THREAT_MODEL.md) for detailed security analysis.

## Testing

### Manual Testing

1. **Start the server** in one terminal
2. **Open two CLI clients** in separate terminals
3. **Register two different users**
4. **Start a chat** between them
5. **Verify messages** are delivered and decrypted correctly

### Example Test Session

Terminal 1 (Server):
```bash
python -m uvicorn server.main:app --reload
```

Terminal 2 (Alice):
```bash
python -m client.cli_client
# Register as "alice"
# /chat bob
# Send: "Hello Bob!"
```

Terminal 3 (Bob):
```bash
python -m client.cli_client
# Register as "bob"
# /chat alice
# Receive: "Hello Bob!"
# Send: "Hi Alice!"
```

## Development

### Project Structure

```
Secure-Chat-Applications/
├── crypto/              # Cryptographic layer
├── server/              # Server-side application
├── client/              # Client-side applications
├── web/                 # Web interface
├── docs/                # Documentation
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

### Running in Development Mode

```bash
# Server with auto-reload
uvicorn server.main:app --reload

# CLI client with debug output
python -m client.cli_client
```

## API Documentation

Once the server is running, access interactive API documentation:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Main Endpoints

- `POST /api/register` - Register new user
- `POST /api/login` - Authenticate user
- `POST /api/prekeys/{username}` - Upload prekey bundle
- `GET /api/prekeys/{username}` - Retrieve prekey bundle
- `GET /api/users` - List all users
- `GET /api/users/online` - List online users
- `WS /ws` - WebSocket connection for real-time messaging

## Deployment

### Production Checklist

- [ ] Change `SECRET_KEY` in `server/auth.py`
- [ ] Enable HTTPS/TLS (use nginx or Caddy as reverse proxy)
- [ ] Use WSS for WebSocket connections
- [ ] Configure proper database (PostgreSQL/MySQL)
- [ ] Set up rate limiting
- [ ] Configure CORS properly
- [ ] Enable logging and monitoring
- [ ] Set up backups
- [ ] Implement DDoS protection
- [ ] Review security documentation

### Example nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name chat.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /ws {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## Documentation

- [Security Architecture](docs/SECURITY_ARCHITECTURE.md) - Detailed cryptographic design
- [Threat Model](docs/THREAT_MODEL.md) - Security analysis and risk assessment

## Troubleshooting

### Common Issues

**Issue**: `ModuleNotFoundError: No module named 'crypto'`
```bash
# Make sure you're in the project root directory
cd Secure-Chat-Applications
python -m client.cli_client
```

**Issue**: Database locked errors
```bash
# Close all other instances of the client
# Delete the database file if corrupted
rm client_data/<username>.db
```

**Issue**: WebSocket connection failed
```bash
# Ensure server is running
# Check firewall settings
# Verify the URL is correct (ws:// for HTTP, wss:// for HTTPS)
```

**Issue**: Cannot decrypt messages
```bash
# This may indicate:
# - Session was reset (re-initialize with /chat <user>)
# - Database corruption (backup and recreate)
# - Out-of-order message delivery (should auto-recover)
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Security Issues

**DO NOT** open public issues for security vulnerabilities. Instead:
- Email security concerns to: [security contact]
- Use responsible disclosure practices
- Allow reasonable time for fixes before disclosure

## License

This project is provided for educational purposes. See LICENSE file for details.

## Disclaimer

This is an educational implementation of end-to-end encrypted chat. While it implements industry-standard cryptographic protocols:

- It has not undergone professional security audit
- It should not be used for life-critical communications
- Users should understand the threat model and limitations
- Always use additional security measures for high-risk scenarios

## References

- [Signal Protocol Documentation](https://signal.org/docs/)
- [X3DH Specification](https://signal.org/docs/specifications/x3dh/)
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [Cryptography Library](https://cryptography.io/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

## Acknowledgments

This project is inspired by:
- Signal's cryptographic protocols
- Open Whisper Systems
- The cryptography community

## Support

For questions, issues, or suggestions:
- Open an issue on GitHub
- Check existing documentation
- Review the threat model and security architecture

## Roadmap

Future enhancements:
- [ ] Group chat support
- [ ] Multi-device synchronization
- [ ] Voice/video calling
- [ ] File transfer with encryption
- [ ] Post-quantum cryptography
- [ ] Mobile clients (iOS/Android)
- [ ] Key verification UI with QR codes
- [ ] Disappearing messages
- [ ] Message reactions and editing

---

**Built with security and privacy in mind.**
