# OceanFriends Code Snippets - Authentication Hack
Demo:


https://github.com/user-attachments/assets/e2c7e2eb-0c45-41c5-8d5f-58d375163e98




## Core Problem: Bypassing Anvil's Login Limitations

**Challenge**: Anvil's `login_with_email()` only works within Anvil environment, not via Uplink from Flask.

---

## Hack #1: Reverse-Engineering Anvil Authentication

### Flask Login Route - The Core Hack
```python
import bcrypt
import secrets
import anvil.server
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify

auth_bp = Blueprint('auth', __name__)
session_store = {}  # In-memory token storage

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    
    try:
        # Fetch bcrypt hash from Anvil via Uplink
        anvil_response = anvil.server.call('get_user_by_email', email)
        
        if not anvil_response.get('success'):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        user_data = anvil_response.get('user_data', {})
        stored_hash = user_data.get('password_hash')
        
        # Key Innovation: Verify password in Flask (not possible in Anvil)
        password_correct = bcrypt.checkpw(
            password.encode('utf-8'), 
            stored_hash.encode('utf-8')
        )
        
        if password_correct:
            # Generate custom secure token
            token = secrets.token_hex(32)
            
            # Store token with expiration
            session_store[token] = {
                'user_email': email,
                'user_type': user_data.get('user_type', ''),
                'created_at': datetime.now(),
                'expires_at': datetime.now() + timedelta(hours=24)
            }
            
            clean_user_data = {
                "email": user_data["email"],
                "user_type": user_data.get("user_type", "")
            }
            
            return jsonify({
                'token': token,
                'user': clean_user_data,
                'message': 'Login successful'
            }), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'error': 'Authentication failed'}), 500

@auth_bp.route('/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token in session_store:
        del session_store[token]
    return jsonify({'message': 'Logged out successfully'}), 200
```

### Anvil Server Function (Fetches Hash via Uplink)
```python
import anvil.server
from anvil.tables import app_tables

@anvil.server.callable
def get_user_by_email(email):
    """Called from Flask to get bcrypt hash and user data"""
    try:
        user_row = app_tables.users.get(email=email)
        if user_row:
            return {
                'success': True,
                'user_data': {
                    'email': user_row['email'],
                    'password_hash': user_row['password_hash'],
                    'user_type': user_row['user_type']
                }
            }
        return {'success': False}
    except Exception as e:
        return {'success': False}

@anvil.server.callable
def get_sponsor_details(user_email):
    """Fetch sponsor company information"""
    try:
        sponsor_row = app_tables.sponsors.get(email=user_email)
        if sponsor_row:
            return {
                'success': True,
                'sponsor_data': {
                    'name': sponsor_row['name'],
                    'display_name': sponsor_row['display_name'],
                    'website': sponsor_row['website'],
                    'logo': sponsor_row['logo']
                }
            }
        return {'success': False}
    except Exception as e:
        return {'success': False}
```

---

## Hack #2: Custom Token System (No JWT Required)

### Token Authentication Decorator
```python
from functools import wraps
from flask import request, jsonify

def token_required(f):
    """Custom authentication decorator - replaces JWT"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token missing'}), 401
        
        # Handle Bearer token format
        if token.startswith('Bearer '):
            token = token[7:]
        
        # Check if token exists and is valid
        token_data = session_store.get(token)
        if not token_data:
            return jsonify({'error': 'Invalid token'}), 401
        
        # Check token expiration
        if datetime.now() > token_data['expires_at']:
            del session_store[token]  # Clean up expired token
            return jsonify({'error': 'Token expired'}), 401
        
        # Add user info to request for use in protected routes
        request.user = {
            'email': token_data['user_email'],
            'user_type': token_data['user_type']
        }
        
        return f(*args, **kwargs)
    return decorated

@auth_bp.route('/me', methods=['GET'])
@token_required
def get_current_user():
    """Get current user info using custom token"""
    return jsonify({"user": request.user}), 200
```

### Protected Routes Using Custom Auth
```python
from flask import Blueprint
sponsors_bp = Blueprint('sponsors', __name__)

@sponsors_bp.route("/company", methods=["GET"])
@token_required
def get_company_details():
    """Protected endpoint using custom token system"""
    user_email = request.user.get("email")
    
    try:
        # Fetch sponsor data from Anvil via Uplink
        anvil_response = anvil.server.call('get_sponsor_details', user_email)
        
        if not anvil_response.get('success'):
            return jsonify({'error': 'Sponsor not found'}), 404
        
        sponsor_data = anvil_response.get('sponsor_data', {})
        
        return jsonify({
            "company": {
                "name": sponsor_data.get('name', ''),
                "display_name": sponsor_data.get('display_name', ''),
                "website": sponsor_data.get('website', ''),
                "logo": sponsor_data.get('logo')
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch company details'}), 500

@sponsors_bp.route("/projects", methods=["GET"])
@token_required
def get_sponsor_projects():
    """Get projects sponsored by current user"""
    user_email = request.user.get("email")
    
    try:
        anvil_response = anvil.server.call('get_sponsored_projects', user_email)
        
        if anvil_response.get('success'):
            return jsonify({
                "sponsored_projects": anvil_response.get('projects', [])
            }), 200
        else:
            return jsonify({"sponsored_projects": []}), 200
            
    except Exception as e:
        return jsonify({'error': 'Failed to fetch sponsored projects'}), 500
```

---

## Frontend Integration

### React Auth Service
```javascript
export class AnvilAuthService {
  constructor() {
    this.baseURL = process.env.REACT_APP_API_URL || 'http://localhost:5000';
    this.tokenKey = "anvil_session_token";
  }

  // Store and retrieve tokens
  storeToken(token) {
    localStorage.setItem(this.tokenKey, token);
  }

  getStoredToken() {
    return localStorage.getItem(this.tokenKey);
  }

  clearToken() {
    localStorage.removeItem(this.tokenKey);
  }

  // Auth headers for all API calls
  getAuthHeaders() {
    const token = this.getStoredToken();
    return {
      "Content-Type": "application/json",
      ...(token && { 'Authorization': `Bearer ${token}` }),
    };
  }

  // Main login method using custom auth
  async login({ email, password }) {
    try {
      const response = await fetch(`${this.baseURL}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Login failed");
      }

      const data = await response.json();
      
      // Store custom token
      this.storeToken(data.token);
      
      return data.user;
    } catch (error) {
      throw new Error(error.message || "Login failed");
    }
  }

  // Check authentication status
  isAuthenticated() {
    return !!this.getStoredToken();
  }

  // Protected API call example
  async getCompanyDetails() {
    try {
      const response = await fetch(`${this.baseURL}/api/sponsors/company`, {
        method: "GET",
        headers: this.getAuthHeaders(),
      });

      if (!response.ok) {
        throw new Error("Failed to fetch company details");
      }

      return await response.json();
    } catch (error) {
      throw new Error(error.message || "Failed to fetch company details");
    }
  }
}

// Usage in React components
const authService = new AnvilAuthService();

// Login component usage
const handleLogin = async (formData) => {
  try {
    const userData = await authService.login(formData);
    dispatch(authLogin(userData)); // Redux action
    navigate("/dashboard");
  } catch (error) {
    setError(error.message);
  }
};
```

---

## Key Innovation Points

1. **Bypassed Anvil Limitation**: Used Uplink to fetch bcrypt hashes, verified passwords in Flask
2. **Custom Token System**: Built secure session management without JWT dependencies using Python's `secrets` module
3. **Zero Refactoring**: Preserved existing Anvil signup flow and user database
4. **24-Hour Implementation**: Complete auth system built and integrated in one day
5. **Seamless Integration**: React frontend communicates with Flask backend while maintaining Anvil as data source

## Impact
- **Unblocked Development**: Sponsor platform could proceed independently without waiting for Anvil auth solutions
- **Maintained Security**: bcrypt password verification + secure token generation with expiration
- **Preserved Infrastructure**: No migration of 1500+ user records required
- **Enabled Role-Based Features**: Sponsor-specific actions like project creation and sponsorship management
- **Scalable Architecture**: Custom token system can easily be replaced with JWT if needed later

**Tech Stack**: Flask + bcrypt + Python secrets + Anvil Uplink +
