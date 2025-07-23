// ===================================
// EJEMPLO: Vanilla JavaScript con SDK Simple Auth
// ===================================

import { AuthSDK } from 'sdk-simple-auth';

// Configuración del SDK
const auth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000'
});

// Referencias a elementos del DOM
const loginForm = document.getElementById('loginForm');
const logoutBtn = document.getElementById('logoutBtn');
const userInfo = document.getElementById('userInfo');
const errorDiv = document.getElementById('error');
const loadingDiv = document.getElementById('loading');

// Estado de la aplicación
let currentUser = null;

// Inicializar la aplicación
async function initApp() {
  showLoading(true);

  try {
    // Verificar sesión existente
    const isAuthenticated = await auth.isAuthenticated();
    
    if (isAuthenticated) {
      currentUser = auth.getCurrentUser();
      showUserInterface();
    } else {
      showLoginInterface();
    }

    // Escuchar cambios de estado
    auth.onAuthStateChanged((state) => {
      currentUser = state.user;
      
      if (state.user) {
        showUserInterface();
      } else {
        showLoginInterface();
      }

      if (state.error) {
        showError(state.error);
      }
    });

  } catch (error) {
    showError('Error inicializando aplicación: ' + error.message);
  } finally {
    showLoading(false);
  }
}

// Manejo del formulario de login
async function handleLogin(event) {
  event.preventDefault();
  
  const formData = new FormData(event.target);
  const email = formData.get('email');
  const password = formData.get('password');

  showLoading(true);
  clearError();

  try {
    const user = await auth.login({ email, password });
    console.log('Login exitoso:', user);
    
    // El estado se actualiza automáticamente vía onAuthStateChanged
    
  } catch (error) {
    showError('Error de login: ' + error.message);
  } finally {
    showLoading(false);
  }
}

// Manejo del logout
async function handleLogout() {
  showLoading(true);
  
  try {
    await auth.logout();
    console.log('Logout exitoso');
    
    // El estado se actualiza automáticamente vía onAuthStateChanged
    
  } catch (error) {
    showError('Error de logout: ' + error.message);
  } finally {
    showLoading(false);
  }
}

// Hacer una request autenticada
async function makeAuthenticatedRequest() {
  try {
    const headers = await auth.getAuthHeaders();
    
    const response = await fetch('/api/protected-endpoint', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        ...headers
      }
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    console.log('Datos obtenidos:', data);
    
    // Mostrar datos en la UI
    document.getElementById('apiData').innerHTML = `
      <h3>Datos de la API:</h3>
      <pre>${JSON.stringify(data, null, 2)}</pre>
    `;

  } catch (error) {
    showError('Error en request: ' + error.message);
  }
}

// Funciones de UI
function showUserInterface() {
  document.getElementById('loginSection').style.display = 'none';
  document.getElementById('userSection').style.display = 'block';
  
  if (currentUser) {
    document.getElementById('userName').textContent = currentUser.name || currentUser.email;
    document.getElementById('userEmail').textContent = currentUser.email;
    document.getElementById('userId').textContent = currentUser.id;
  }
}

function showLoginInterface() {
  document.getElementById('loginSection').style.display = 'block';
  document.getElementById('userSection').style.display = 'none';
  
  // Limpiar formulario
  document.getElementById('loginForm').reset();
}

function showLoading(show) {
  loadingDiv.style.display = show ? 'block' : 'none';
}

function showError(message) {
  errorDiv.textContent = message;
  errorDiv.style.display = 'block';
  
  // Auto-ocultar después de 5 segundos
  setTimeout(() => {
    clearError();
  }, 5000);
}

function clearError() {
  errorDiv.style.display = 'none';
  errorDiv.textContent = '';
}

// Debug functions
function debugToken() {
  auth.debugToken();
  console.log('Ver información del token en la consola');
}

async function debugSession() {
  const sessionInfo = await auth.getExtendedSessionInfo();
  console.log('Información de sesión:', sessionInfo);
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
  // Inicializar app
  initApp();

  // Event listeners
  if (loginForm) {
    loginForm.addEventListener('submit', handleLogin);
  }

  if (logoutBtn) {
    logoutBtn.addEventListener('click', handleLogout);
  }

  // Botón para request autenticada
  const apiRequestBtn = document.getElementById('apiRequestBtn');
  if (apiRequestBtn) {
    apiRequestBtn.addEventListener('click', makeAuthenticatedRequest);
  }

  // Botones de debug
  const debugTokenBtn = document.getElementById('debugTokenBtn');
  if (debugTokenBtn) {
    debugTokenBtn.addEventListener('click', debugToken);
  }

  const debugSessionBtn = document.getElementById('debugSessionBtn');
  if (debugSessionBtn) {
    debugSessionBtn.addEventListener('click', debugSession);
  }
});

// Exportar funciones para uso global
window.authApp = {
  auth,
  handleLogin,
  handleLogout,
  makeAuthenticatedRequest,
  debugToken,
  debugSession
};
