# Quick Start Guide

## Installation

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

   **Note**: If you encounter issues with the `cryptography` package, you may need to install system dependencies:

   **On Ubuntu/Debian**:
   ```bash
   sudo apt-get install build-essential libssl-dev libffi-dev python3-dev
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

   **On macOS**:
   ```bash
   brew install openssl
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

   **On Windows**:
   - Install Visual Studio Build Tools
   - Then run: `pip install -r requirements.txt`

2. **Test the installation**:
   ```bash
   python test_crypto.py
   ```

   You should see:
   ```
   ==================================================
   Running Cryptographic Tests
   ==================================================

   Testing DH exchange...
   ✓ DH exchange works
   Testing encryption...
   ✓ Encryption/decryption works
   Testing KDF...
   ✓ KDF works
   Testing X3DH...
   ✓ X3DH works
   Testing Double Ratchet...
   ✓ Double Ratchet works
   Testing state export/import...
   ✓ State export/import works

   ==================================================
   ✓ All tests passed!
   ==================================================
   ```

## Running the Application

### Terminal 1: Start the Server

```bash
python -m uvicorn server.main:app --host 0.0.0.0 --port 8000
```

You should see:
```
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
Database initialized
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Terminal 2: First Client (Alice)

```bash
python -m client.cli_client
```

Then:
1. Choose `1` to register
2. Username: `alice`
3. Password: `alicepass`
4. Wait for registration to complete

You should see:
```
Registration successful! Welcome, alice
Connected to server
Online users: alice
```

### Terminal 3: Second Client (Bob)

```bash
python -m client.cli_client
```

Then:
1. Choose `1` to register
2. Username: `bob`
3. Password: `bobpass`
4. Wait for registration to complete

### Start Chatting

In Alice's terminal:
```
> /chat bob
Initialized encrypted session with bob
[bob] > Hello Bob!
```

In Bob's terminal:
```
> /chat alice
[12:34] alice: Hello Bob!
[alice] > Hi Alice! This is encrypted!
```

In Alice's terminal, you should see:
```
[12:34] bob: Hi Alice! This is encrypted!
```

## Web Interface

1. Open your browser to: `http://localhost:8000`
2. Register or login
3. Select a user from the sidebar
4. Start chatting!

## Troubleshooting

**Problem**: Server won't start
- Check if port 8000 is already in use: `lsof -i :8000` (Linux/Mac) or `netstat -ano | findstr :8000` (Windows)
- Try a different port: `python -m uvicorn server.main:app --port 8001`

**Problem**: Client can't connect
- Make sure the server is running
- Check the server URL in the client (default: `http://localhost:8000`)
- Check firewall settings

**Problem**: "Module not found" errors
- Make sure you're in the project root directory
- Activate virtual environment if you created one
- Reinstall dependencies: `pip install -r requirements.txt`

**Problem**: Cryptography installation fails
- Install system dependencies (see Installation section above)
- Update pip: `pip install --upgrade pip`
- Try installing cryptography separately: `pip install cryptography`

## Next Steps

- Read the [Security Architecture](docs/SECURITY_ARCHITECTURE.md)
- Review the [Threat Model](docs/THREAT_MODEL.md)
- Check the full [README](README.md) for more details
