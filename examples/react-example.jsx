// ===================================
// EXAMPLE: React App with SDK Simple Auth
// ===================================

import React, { useState, useEffect } from 'react';
import { AuthSDK } from 'sdk-simple-auth';

// SDK Configuration
const auth = new AuthSDK({
  authServiceUrl: process.env.REACT_APP_API_URL || 'http://localhost:3000',
  tokenRefresh: {
    enabled: true,
    bufferTime: 300 // 5 minutes before expiry
  }
});

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Login form
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  useEffect(() => {
    initializeAuth();
  }, []);

  const initializeAuth = async () => {
    try {
      // Check if there's an existing session
      const isAuthenticated = await auth.isAuthenticated();
      
      if (isAuthenticated) {
        setUser(auth.getCurrentUser());
      }

      // Listen to authentication state changes
      auth.onAuthStateChanged((state) => {
        setUser(state.user);
        setLoading(state.loading);
        setError(state.error);
      });

    } catch (err) {
      console.error('Error initializing auth:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const userData = await auth.login({
        email,
        password
      });

      console.log('Login successful:', userData);
      // State updates automatically via onAuthStateChanged

    } catch (err) {
      setError(err.message);
      console.error('Login error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await auth.logout();
      setEmail('');
      setPassword('');
      // State updates automatically via onAuthStateChanged
    } catch (err) {
      console.error('Logout error:', err);
    }
  };

  const makeAuthenticatedRequest = async () => {
    try {
      const headers = await auth.getAuthHeaders();
      
      const response = await fetch('/api/protected-data', {
        headers: {
          'Content-Type': 'application/json',
          ...headers
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();
      console.log('Protected data:', data);

    } catch (err) {
      console.error('Error in authenticated request:', err);
    }
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: '2rem' }}>
        <div>Loading...</div>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: '400px', margin: '2rem auto', padding: '1rem' }}>
      <h1>SDK Simple Auth - Demo</h1>

      {user ? (
        // Authenticated user
        <div>
          <div style={{ 
            background: '#e8f5e8', 
            padding: '1rem', 
            borderRadius: '8px',
            marginBottom: '1rem'
          }}>
            <h2>Hello, {user.name || user.email}!</h2>
            <p><strong>ID:</strong> {user.id}</p>
            <p><strong>Email:</strong> {user.email}</p>
            {user.role && <p><strong>Role:</strong> {user.role}</p>}
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', flexDirection: 'column' }}>
            <button 
              onClick={makeAuthenticatedRequest}
              style={{
                padding: '0.75rem',
                backgroundColor: '#007bff',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              Make Authenticated Request
            </button>

            <button 
              onClick={handleLogout}
              style={{
                padding: '0.75rem',
                backgroundColor: '#dc3545',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              Logout
            </button>
          </div>
        </div>
      ) : (
        // Login form
        <form onSubmit={handleLogin}>
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem' }}>
              Email:
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              style={{
                width: '100%',
                padding: '0.75rem',
                border: '1px solid #ddd',
                borderRadius: '4px',
                fontSize: '1rem'
              }}
              placeholder="user@example.com"
            />
          </div>

          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem' }}>
              Password:
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              style={{
                width: '100%',
                padding: '0.75rem',
                border: '1px solid #ddd',
                borderRadius: '4px',
                fontSize: '1rem'
              }}
              placeholder="••••••••"
            />
          </div>

          {error && (
            <div style={{
              backgroundColor: '#f8d7da',
              color: '#721c24',
              padding: '0.75rem',
              borderRadius: '4px',
              marginBottom: '1rem'
            }}>
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            style={{
              width: '100%',
              padding: '0.75rem',
              backgroundColor: loading ? '#6c757d' : '#28a745',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: loading ? 'not-allowed' : 'pointer',
              fontSize: '1rem'
            }}
          >
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
      )}

      <div style={{ 
        marginTop: '2rem', 
        padding: '1rem', 
        backgroundColor: '#f8f9fa',
        borderRadius: '4px',
        fontSize: '0.875rem'
      }}>
        <h3>Debug Info:</h3>
        <button 
          onClick={() => auth.debugSession()}
          style={{
            padding: '0.5rem',
            backgroundColor: '#6c757d',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '0.875rem'
          }}
        >
          Debug Session (check console)
        </button>
      </div>
    </div>
  );
}

export default App;
