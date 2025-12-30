import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Upload, FileText, CheckCircle, XCircle, TrendingUp, DollarSign, Activity, LogOut, Menu, X, ChevronRight, Download, Search, Filter, Users, Shield, Eye, EyeOff, Copy, RefreshCw, Key, AlertTriangle, Clock } from 'lucide-react';

// ==================== CONFIGURATION ====================
// API Configuration - Use environment variables in production
const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'https://cipher.thepaytrix.com/api';
const API_AUTH_URL = process.env.REACT_APP_API_AUTH_URL || 'https://testing.thepaytrix.com/api';

// Configuration constants
const CONFIG = {
  NOTIFICATION_DURATION: 5000,
  PASSWORD_MIN_LENGTH: 6,
  MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
  ALLOWED_FILE_EXTENSIONS: ['.csv', '.xls', '.xlsx', '.pdf'],
  AUTO_REFRESH_THRESHOLD: 120000, // 2 minutes before expiry (as requested)
  TOKEN_CHECK_INTERVAL: 60000, // Check every 1 minute
};

// ==================== UTILITY FUNCTIONS ====================

/**
 * Check if token has expired based on expiration timestamp
 */
const isTokenExpired = (tokenExpiry) => {
  if (!tokenExpiry) return true;
  const now = Date.now();
  return now >= tokenExpiry;
};

/**
 * Check if token is about to expire (within threshold)
 */
const isTokenNearExpiry = (tokenExpiry, threshold = CONFIG.AUTO_REFRESH_THRESHOLD) => {
  if (!tokenExpiry) return false;
  const now = Date.now();
  const timeUntilExpiry = tokenExpiry - now;
  return timeUntilExpiry > 0 && timeUntilExpiry <= threshold;
};

/**
 * Format time remaining until expiry
 */
const formatTimeRemaining = (tokenExpiry) => {
  if (!tokenExpiry) return 'Unknown';
  const now = Date.now();
  const diff = tokenExpiry - now;

  if (diff <= 0) return 'Expired';

  const minutes = Math.floor(diff / 60000);
  const seconds = Math.floor((diff % 60000) / 1000);

  if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  }
  return `${seconds}s`;
};

/**
 * Clear session data and redirect to login
 */
const clearSessionAndRedirect = (setCurrentView, setUser, setToken, setTokenExpiry, showNotification, currentView) => {
  localStorage.removeItem('cipherbank_token');
  localStorage.removeItem('cipherbank_user');
  localStorage.removeItem('cipherbank_token_expiry');
  localStorage.removeItem('cipherbank_credentials'); // Clear stored credentials

  setToken(null);
  setUser(null);
  setTokenExpiry(null);
  setCurrentView('login');

  if (showNotification && currentView !== 'login') {
    showNotification('Session expired. Please login again.', 'error');
  }
};

/**
 * Validate file before upload
 */
const validateFile = (file) => {
  const errors = [];

  if (!file) {
    errors.push('No file selected');
    return { valid: false, errors };
  }

  if (file.size > CONFIG.MAX_FILE_SIZE) {
    errors.push(`File size must be less than ${CONFIG.MAX_FILE_SIZE / 1024 / 1024}MB`);
  }

  const fileName = file.name.toLowerCase();
  const hasValidExtension = CONFIG.ALLOWED_FILE_EXTENSIONS.some(ext => fileName.endsWith(ext));

  if (!hasValidExtension) {
    errors.push(`File type not supported. Allowed: ${CONFIG.ALLOWED_FILE_EXTENSIONS.join(', ')}`);
  }

  return {
    valid: errors.length === 0,
    errors
  };
};

/**
 * Secure password generator using crypto API
 */
const generateSecurePassword = (length = 16) => {
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const numbers = '0123456789';
  const special = '!@#$%^&*';
  const allChars = lowercase + uppercase + numbers + special;

  const array = new Uint32Array(length);
  window.crypto.getRandomValues(array);

  let password = '';
  password += lowercase[array[0] % lowercase.length];
  password += uppercase[array[1] % uppercase.length];
  password += numbers[array[2] % numbers.length];
  password += special[array[3] % special.length];

  for (let i = 4; i < length; i++) {
    password += allChars[array[i] % allChars.length];
  }

  const passwordArray = password.split('');
  for (let i = passwordArray.length - 1; i > 0; i--) {
    const j = array[i] % (i + 1);
    [passwordArray[i], passwordArray[j]] = [passwordArray[j], passwordArray[i]];
  }

  return passwordArray.join('');
};

/**
 * Sanitize user input to prevent XSS
 */
const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;

  return input
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
};

// ==================== ERROR BOUNDARY ====================
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Error caught by boundary:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 p-4">
          <div className="max-w-md w-full bg-white rounded-2xl shadow-xl p-8 text-center">
            <XCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
            <h1 className="text-2xl font-bold text-gray-900 mb-2">Something went wrong</h1>
            <p className="text-gray-600 mb-6">
              An unexpected error occurred. Please refresh the page and try again.
            </p>
            <button
              onClick={() => window.location.reload()}
              className="px-6 py-3 bg-blue-600 text-white rounded-xl hover:bg-blue-700 transition-colors"
            >
              Refresh Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// ==================== MAIN APP COMPONENT ====================
const CipherBankUI = () => {
  const [currentView, setCurrentView] = useState('login');
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [tokenExpiry, setTokenExpiry] = useState(null);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [notification, setNotification] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [sessionWarningShown, setSessionWarningShown] = useState(false);
  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Use ref to store credentials for auto-refresh (only if user enables it)
  const credentialsRef = useRef(null);

  // Check for existing session on mount
  useEffect(() => {
    const savedToken = localStorage.getItem('cipherbank_token');
    const savedUser = localStorage.getItem('cipherbank_user');
    const savedExpiry = localStorage.getItem('cipherbank_token_expiry');
    const savedCredentials = localStorage.getItem('cipherbank_credentials');

    if (savedToken && savedUser && savedExpiry) {
      const expiryTime = parseInt(savedExpiry, 10);

      // Check if token is still valid
      if (!isTokenExpired(expiryTime)) {
        try {
          const userData = JSON.parse(savedUser);
          setToken(savedToken);
          setUser(userData);
          setTokenExpiry(expiryTime);
          setCurrentView('dashboard');

          // Restore credentials if auto-refresh was enabled
          if (savedCredentials) {
            try {
              credentialsRef.current = JSON.parse(atob(savedCredentials));
              setAutoRefreshEnabled(true);
            } catch (e) {
              localStorage.removeItem('cipherbank_credentials');
            }
          }
        } catch (error) {
          // Clear corrupted data
          clearSessionAndRedirect(setCurrentView, setUser, setToken, setTokenExpiry, null, 'login');
        }
      } else {
        // Token expired
        clearSessionAndRedirect(setCurrentView, setUser, setToken, setTokenExpiry, null, 'login');
      }
    }
  }, []);

  // Token expiry monitoring and auto-refresh
  useEffect(() => {
    if (!token || !tokenExpiry || currentView === 'login') return;

    const checkTokenExpiry = () => {
      const now = Date.now();

      // Check if token has expired
      if (isTokenExpired(tokenExpiry)) {
        clearSessionAndRedirect(setCurrentView, setUser, setToken, setTokenExpiry, showNotification, currentView);
        return;
      }

      // Check if token is near expiry and show warning
      if (isTokenNearExpiry(tokenExpiry) && !sessionWarningShown) {
        const timeRemaining = formatTimeRemaining(tokenExpiry);
        showNotification(
          `Your session will expire in ${timeRemaining}. ${autoRefreshEnabled ? 'Auto-refresh is enabled.' : 'Please save your work.'}`,
          'warning'
        );
        setSessionWarningShown(true);
      }
    };

    // Check immediately
    checkTokenExpiry();

    // Check every minute
    const intervalId = setInterval(checkTokenExpiry, CONFIG.TOKEN_CHECK_INTERVAL);

    return () => clearInterval(intervalId);
  }, [token, tokenExpiry, currentView, sessionWarningShown, autoRefreshEnabled]);

  // Auto-refresh token function
  const refreshToken = useCallback(async () => {
    if (!autoRefreshEnabled || !credentialsRef.current || isRefreshing) {
      return false;
    }

    setIsRefreshing(true);

    try {
      const response = await fetch(`${API_AUTH_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(credentialsRef.current),
      });

      if (response.ok) {
        const data = await response.json();

        if (data.token && data.tokenExpirationMillis) {
          // Update token and expiry
          setToken(data.token);
          setTokenExpiry(data.tokenExpirationMillis);
          localStorage.setItem('cipherbank_token', data.token);
          localStorage.setItem('cipherbank_token_expiry', data.tokenExpirationMillis.toString());

          // Update user data
          const userData = {
            username: data.username,
            name: data.name,
            roles: data.roles || ['ROLE_USER']
          };
          setUser(userData);
          localStorage.setItem('cipherbank_user', JSON.stringify(userData));

          // Reset warning flag
          setSessionWarningShown(false);

          showNotification('Token refreshed successfully', 'success');
          return true;
        }
      }

      return false;
    } catch (error) {
      console.error('Token refresh failed:', error);
      return false;
    } finally {
      setIsRefreshing(false);
    }
  }, [autoRefreshEnabled, isRefreshing]);

  // Function to check and refresh token before API calls
  const checkAndRefreshToken = useCallback(async () => {
    if (!tokenExpiry) return true;

    // If token is near expiry and auto-refresh is enabled, refresh it
    if (isTokenNearExpiry(tokenExpiry) && autoRefreshEnabled) {
      return await refreshToken();
    }

    // If token is expired, redirect to login
    if (isTokenExpired(tokenExpiry)) {
      clearSessionAndRedirect(setCurrentView, setUser, setToken, setTokenExpiry, showNotification, currentView);
      return false;
    }

    return true;
  }, [tokenExpiry, autoRefreshEnabled, refreshToken, currentView]);

  const showNotification = (message, type = 'success') => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), CONFIG.NOTIFICATION_DURATION);
  };

  const handleLogout = () => {
    setUser(null);
    setToken(null);
    setTokenExpiry(null);
    setSessionWarningShown(false);
    setAutoRefreshEnabled(false);
    credentialsRef.current = null;

    localStorage.removeItem('cipherbank_token');
    localStorage.removeItem('cipherbank_user');
    localStorage.removeItem('cipherbank_token_expiry');
    localStorage.removeItem('cipherbank_credentials');

    setCurrentView('login');
    showNotification('Logged out successfully', 'info');
  };

  return (
    <ErrorBoundary>
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
        {/* Notification Toast */}
        {notification && (
          <div className="fixed top-4 right-4 z-50 animate-slideInRight">
            <div className={`flex items-center gap-3 px-6 py-4 rounded-xl shadow-2xl backdrop-blur-md ${
              notification.type === 'success' ? 'bg-emerald-500' :
              notification.type === 'error' ? 'bg-red-500' :
              notification.type === 'warning' ? 'bg-yellow-500' : 'bg-blue-500'
            } text-white max-w-md`}>
              {notification.type === 'success' && <CheckCircle className="w-5 h-5 flex-shrink-0" />}
              {notification.type === 'error' && <XCircle className="w-5 h-5 flex-shrink-0" />}
              {notification.type === 'warning' && <AlertTriangle className="w-5 h-5 flex-shrink-0" />}
              <span className="font-medium">{notification.message}</span>
            </div>
          </div>
        )}

        {/* Token Expiry Indicator (shown when logged in) */}
        {token && tokenExpiry && currentView !== 'login' && (
          <div className="fixed bottom-4 right-4 z-40">
            <div className="bg-white rounded-xl shadow-lg p-3 flex items-center gap-3 border border-gray-200">
              <Clock className="w-4 h-4 text-gray-600" />
              <div className="text-sm">
                <span className="text-gray-600">Session expires in: </span>
                <span className={`font-semibold ${
                  isTokenNearExpiry(tokenExpiry) ? 'text-red-600' : 'text-gray-900'
                }`}>
                  {formatTimeRemaining(tokenExpiry)}
                </span>
              </div>
              {autoRefreshEnabled && (
                <div className="flex items-center gap-1 ml-2 px-2 py-1 bg-green-100 rounded-lg">
                  <RefreshCw className="w-3 h-3 text-green-600" />
                  <span className="text-xs text-green-700 font-medium">Auto-refresh ON</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Main Content */}
        {currentView === 'login' && (
          <LoginView
            setCurrentView={setCurrentView}
            setUser={setUser}
            setToken={setToken}
            setTokenExpiry={setTokenExpiry}
            showNotification={showNotification}
            setIsLoading={setIsLoading}
            setSessionWarningShown={setSessionWarningShown}
            setAutoRefreshEnabled={setAutoRefreshEnabled}
            credentialsRef={credentialsRef}
          />
        )}

        {(currentView === 'dashboard' || currentView === 'upload' || currentView === 'statements' || currentView === 'users' || currentView === 'changepassword') && (
          <DashboardLayout
            currentView={currentView}
            setCurrentView={setCurrentView}
            user={user}
            token={token}
            tokenExpiry={tokenExpiry}
            setUser={setUser}
            setToken={setToken}
            setTokenExpiry={setTokenExpiry}
            handleLogout={handleLogout}
            showNotification={showNotification}
            isMenuOpen={isMenuOpen}
            setIsMenuOpen={setIsMenuOpen}
            checkAndRefreshToken={checkAndRefreshToken}
            autoRefreshEnabled={autoRefreshEnabled}
            setAutoRefreshEnabled={setAutoRefreshEnabled}
            credentialsRef={credentialsRef}
          />
        )}

        {/* Loading Overlay */}
        {(isLoading || isRefreshing) && (
          <div className="fixed inset-0 bg-black/20 backdrop-blur-sm z-50 flex items-center justify-center">
            <div className="bg-white rounded-2xl p-8 shadow-2xl">
              <div className="w-16 h-16 border-4 border-blue-200 border-t-blue-600 rounded-full animate-spin mx-auto"></div>
              <p className="mt-4 text-gray-600 font-medium">
                {isRefreshing ? 'Refreshing session...' : 'Processing...'}
              </p>
            </div>
          </div>
        )}

        {/* Styles */}
        <style>{`
          @keyframes slideInRight {
            from {
              transform: translateX(100%);
              opacity: 0;
            }
            to {
              transform: translateX(0);
              opacity: 1;
            }
          }

          @keyframes fadeInUp {
            from {
              transform: translateY(20px);
              opacity: 0;
            }
            to {
              transform: translateY(0);
              opacity: 1;
            }
          }

          .animate-slideInRight {
            animation: slideInRight 0.4s ease-out;
          }

          .animate-fadeInUp {
            animation: fadeInUp 0.6s ease-out;
          }

          .hover-lift {
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
          }

          .hover-lift:hover {
            transform: translateY(-4px);
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
          }

          .glass-effect {
            background: rgba(255, 255, 255, 0.9);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.5);
          }

          .gradient-text {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
          }
        `}</style>
      </div>
    </ErrorBoundary>
  );
};

// ==================== LOGIN VIEW ====================
const LoginView = ({ setCurrentView, setUser, setToken, setTokenExpiry, showNotification, setIsLoading, setSessionWarningShown, setAutoRefreshEnabled, credentialsRef }) => {
  const [formData, setFormData] = useState({
    username: '',
    password: ''
  });
  const [rememberMe, setRememberMe] = useState(false);
  const [enableAutoRefresh, setEnableAutoRefresh] = useState(false);

  const validateForm = () => {
    if (!formData.username || formData.username.trim().length < 3) {
      showNotification('Username must be at least 3 characters long', 'error');
      return false;
    }

    if (!formData.password || formData.password.length < CONFIG.PASSWORD_MIN_LENGTH) {
      showNotification(`Password must be at least ${CONFIG.PASSWORD_MIN_LENGTH} characters long`, 'error');
      return false;
    }

    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setIsLoading(true);

    try {
      const credentials = {
        username: sanitizeInput(formData.username),
        password: formData.password
      };

      const response = await fetch(`${API_AUTH_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(credentials),
      });

      let data = null;

      if (response.ok || response.headers.get('content-type')?.includes('application/json')) {
        try {
          data = await response.json();
        } catch (jsonError) {
          data = { message: 'Invalid response from server' };
        }
      }

      if (response.ok && data) {
        if (!data.token) {
          showNotification('No token received from server', 'error');
          return;
        }

        // Use actual token expiration from backend
        const tokenExpirationMillis = data.tokenExpirationMillis || (Date.now() + (data.tokenValidityMillis || 7200000));

        // Set token, expiry, and user
        setToken(data.token);
        setTokenExpiry(tokenExpirationMillis);
        localStorage.setItem('cipherbank_token', data.token);
        localStorage.setItem('cipherbank_token_expiry', tokenExpirationMillis.toString());

        // Store user data including name field
        const userData = {
          username: data.username || formData.username,
          name: data.name || data.username, // Use 'name' field from response
          roles: data.roles || ['ROLE_USER']
        };
        setUser(userData);
        localStorage.setItem('cipherbank_user', JSON.stringify(userData));

        // Handle auto-refresh setup
        if (enableAutoRefresh) {
          credentialsRef.current = credentials;
          localStorage.setItem('cipherbank_credentials', btoa(JSON.stringify(credentials)));
          setAutoRefreshEnabled(true);
        } else {
          credentialsRef.current = null;
          localStorage.removeItem('cipherbank_credentials');
          setAutoRefreshEnabled(false);
        }

        setSessionWarningShown(false);

        showNotification(`Welcome ${data.name || data.username}! Session valid for ${Math.round((data.tokenValidityMillis || 7200000) / 60000)} minutes.`, 'success');
        setCurrentView('dashboard');
      } else {
        let errorMessage;

        switch (response.status) {
          case 400:
            errorMessage = data?.message || 'Invalid request. Please check your input.';
            break;
          case 401:
            errorMessage = 'Invalid username or password. Please try again.';
            break;
          case 403:
            errorMessage = 'Access forbidden. IP not whitelisted or account inactive.';
            break;
          case 404:
            errorMessage = 'Service not found. Please contact support.';
            break;
          case 500:
            errorMessage = 'Server error. Please try again later.';
            break;
          default:
            errorMessage = data?.message || `Authentication failed (Error ${response.status})`;
        }

        showNotification(errorMessage, 'error');
      }
    } catch (error) {
      showNotification('Connection error. Please check your internet connection and try again.', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      {/* Animated Background */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute w-96 h-96 bg-blue-200/30 rounded-full blur-3xl -top-48 -left-48 animate-pulse"></div>
        <div className="absolute w-96 h-96 bg-purple-200/30 rounded-full blur-3xl -bottom-48 -right-48 animate-pulse" style={{animationDelay: '1s'}}></div>
      </div>

      <div className="w-full max-w-md relative animate-fadeInUp">
        {/* Logo/Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-2xl shadow-xl mb-4 hover-lift">
            <Shield className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-4xl font-bold gradient-text mb-2">Cipher Bank</h1>
          <p className="text-gray-600">Secure & Automated Statement Parsing</p>
        </div>

        {/* Login Card */}
        <div className="glass-effect rounded-3xl shadow-2xl p-8 hover-lift">
          <div className="mb-8">
            <div className="text-center py-3">
              <h2 className="text-xl font-semibold text-gray-800">Sign In to CipherBank</h2>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="relative">
              <input
                type="text"
                placeholder="Username"
                value={formData.username}
                onChange={(e) => setFormData({...formData, username: e.target.value})}
                className="w-full px-4 py-4 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300 bg-white/50"
                required
                minLength={3}
                maxLength={50}
              />
            </div>

            <div className="relative">
              <input
                type="password"
                placeholder="Password"
                value={formData.password}
                onChange={(e) => setFormData({...formData, password: e.target.value})}
                className="w-full px-4 py-4 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300 bg-white/50"
                required
                minLength={CONFIG.PASSWORD_MIN_LENGTH}
              />
            </div>

            {/* Auto-Refresh Option */}
            <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
              <div className="flex items-start gap-3">
                <input
                  type="checkbox"
                  id="autoRefresh"
                  checked={enableAutoRefresh}
                  onChange={(e) => setEnableAutoRefresh(e.target.checked)}
                  className="mt-1 w-4 h-4 text-blue-600 rounded focus:ring-2 focus:ring-blue-500"
                />
                <div className="flex-1">
                  <label htmlFor="autoRefresh" className="text-sm font-semibold text-gray-900 cursor-pointer flex items-center gap-2">
                    <RefreshCw className="w-4 h-4" />
                    Enable Auto Token Refresh
                  </label>
                  <p className="text-xs text-gray-600 mt-1">
                    Remember this session
                  </p>
                  <p className="text-xs text-yellow-700 mt-2 flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" />
                    Use only on trusted devices!
                  </p>
                </div>
              </div>
            </div>

            <button
              type="submit"
              className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 text-white py-4 rounded-xl font-semibold shadow-lg hover:shadow-xl transition-all duration-300 transform hover:scale-105"
            >
              Sign In
            </button>
          </form>

          <div className="mt-6 text-center text-sm text-gray-600">
            <p>BETA V1</p>
          </div>
        </div>
      </div>
    </div>
  );
};

// ==================== DASHBOARD LAYOUT ====================
const DashboardLayout = ({ currentView, setCurrentView, user, token, tokenExpiry, setUser, setToken, setTokenExpiry, handleLogout, showNotification, isMenuOpen, setIsMenuOpen, checkAndRefreshToken, autoRefreshEnabled, setAutoRefreshEnabled, credentialsRef }) => {
  // Validate token on protected pages
  useEffect(() => {
    if (!token || !tokenExpiry) {
      setCurrentView('login');
      return;
    }

    // Check if token is expired
    if (isTokenExpired(tokenExpiry)) {
      clearSessionAndRedirect(setCurrentView, setUser, setToken, setTokenExpiry, showNotification, currentView);
    }
  }, [currentView, token, tokenExpiry]);

  // Function to toggle auto-refresh
  const toggleAutoRefresh = () => {
    if (autoRefreshEnabled) {
      // Disable auto-refresh
      setAutoRefreshEnabled(false);
      credentialsRef.current = null;
      localStorage.removeItem('cipherbank_credentials');
      showNotification('Auto-refresh disabled', 'info');
    } else {
      showNotification('Please re-login to enable auto-refresh', 'info');
    }
  };

  return (
    <div className="min-h-screen flex">
      <Sidebar
        currentView={currentView}
        setCurrentView={setCurrentView}
        user={user}
        handleLogout={handleLogout}
        isMenuOpen={isMenuOpen}
        setIsMenuOpen={setIsMenuOpen}
        autoRefreshEnabled={autoRefreshEnabled}
        toggleAutoRefresh={toggleAutoRefresh}
      />

      <div className="flex-1 lg:ml-72">
        <Header user={user} setIsMenuOpen={setIsMenuOpen} tokenExpiry={tokenExpiry} />
        <main className="p-6 lg:p-8">
          {currentView === 'dashboard' && <Dashboard token={token} showNotification={showNotification} checkAndRefreshToken={checkAndRefreshToken} />}
          {currentView === 'upload' && <UploadView token={token} showNotification={showNotification} setCurrentView={setCurrentView} setUser={setUser} setToken={setToken} setTokenExpiry={setTokenExpiry} user={user} checkAndRefreshToken={checkAndRefreshToken} />}
          {currentView === 'statements' && <StatementsView token={token} showNotification={showNotification} checkAndRefreshToken={checkAndRefreshToken} />}
          {currentView === 'users' && <UserManagementView token={token} showNotification={showNotification} setCurrentView={setCurrentView} setUser={setUser} setToken={setToken} setTokenExpiry={setTokenExpiry} checkAndRefreshToken={checkAndRefreshToken} />}
          {currentView === 'changepassword' && <ChangePasswordView token={token} user={user} showNotification={showNotification} setCurrentView={setCurrentView} setUser={setUser} setToken={setToken} setTokenExpiry={setTokenExpiry} checkAndRefreshToken={checkAndRefreshToken} />}
        </main>
      </div>
    </div>
  );
};

// ==================== SIDEBAR COMPONENT ====================
const Sidebar = ({ currentView, setCurrentView, user, handleLogout, isMenuOpen, setIsMenuOpen, autoRefreshEnabled, toggleAutoRefresh }) => {
  const isAdmin = user?.roles?.includes('ROLE_ADMIN') || false;

  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'upload', label: 'Upload Statement', icon: Upload },
    { id: 'statements', label: 'Statements', icon: FileText },
    ...(isAdmin ? [{ id: 'users', label: 'User Management', icon: Users }] : []),
    { id: 'changepassword', label: 'Change Password', icon: Key },
  ];

  return (
    <>
      {/* Mobile Overlay */}
      {isMenuOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setIsMenuOpen(false)}
        ></div>
      )}

      {/* Sidebar */}
      <aside className={`fixed top-0 left-0 h-full w-72 bg-gradient-to-b from-slate-900 to-slate-800 text-white p-6 z-50 transition-transform duration-300 ${
        isMenuOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
      }`}>
        {/* Close button for mobile */}
        <button
          onClick={() => setIsMenuOpen(false)}
          className="lg:hidden absolute top-6 right-6 text-white"
        >
          <X className="w-6 h-6" />
        </button>

        {/* Logo */}
        <div className="flex items-center gap-3 mb-10">
          <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-xl flex items-center justify-center">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold">CipherBank</h2>
            <p className="text-xs text-gray-400">Automated Parsing</p>
          </div>
        </div>

        {/* User Info */}
        <div className="bg-white/10 rounded-xl p-4 mb-6 backdrop-blur-sm">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 bg-gradient-to-br from-blue-400 to-indigo-500 rounded-full flex items-center justify-center">
              <Users className="w-5 h-5" />
            </div>
            <div className="flex-1">
              <p className="font-semibold truncate">{user?.name || user?.username || 'User'}</p>
              <p className="text-xs text-gray-400">
                {isAdmin ? 'Administrator' : 'User'}
              </p>
            </div>
          </div>

          {/* Auto-Refresh Toggle */}
          <button
            onClick={toggleAutoRefresh}
            className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs transition-colors ${
              autoRefreshEnabled
                ? 'bg-green-500/20 text-green-300 hover:bg-green-500/30'
                : 'bg-white/5 text-gray-400 hover:bg-white/10'
            }`}
          >
            <span className="flex items-center gap-2">
              <RefreshCw className="w-3 h-3" />
              Auto-Refresh
            </span>
            <span className="font-semibold">{autoRefreshEnabled ? 'ON' : 'OFF'}</span>
          </button>
        </div>

        {/* Navigation */}
        <nav className="space-y-2">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentView === item.id;

            return (
              <button
                key={item.id}
                onClick={() => {
                  setCurrentView(item.id);
                  setIsMenuOpen(false);
                }}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300 ${
                  isActive
                    ? 'bg-gradient-to-r from-blue-500 to-indigo-600 shadow-lg'
                    : 'hover:bg-white/10'
                }`}
              >
                <Icon className="w-5 h-5" />
                <span className="font-medium">{item.label}</span>
                {isActive && <ChevronRight className="w-4 h-4 ml-auto" />}
              </button>
            );
          })}
        </nav>

        {/* Logout Button */}
        <button
          onClick={handleLogout}
          className="absolute bottom-6 left-6 right-6 flex items-center justify-center gap-3 px-4 py-3 rounded-xl bg-red-500/20 hover:bg-red-500/30 transition-all duration-300"
        >
          <LogOut className="w-5 h-5" />
          <span className="font-medium">Logout</span>
        </button>
      </aside>
    </>
  );
};

// ==================== HEADER COMPONENT ====================
const Header = ({ user, setIsMenuOpen, tokenExpiry }) => {
  return (
    <header className="bg-white border-b border-gray-200 px-6 py-4 lg:px-8">
      <div className="flex items-center justify-between">
        <button
          onClick={() => setIsMenuOpen(true)}
          className="lg:hidden text-gray-600 hover:text-gray-900"
        >
          <Menu className="w-6 h-6" />
        </button>

        <div className="flex-1 lg:flex-none">
          <h1 className="text-2xl font-bold text-gray-900">
            Welcome back, {user?.name || user?.username}!
          </h1>
          <p className="text-sm text-gray-600 mt-1">Manage your bank statements efficiently</p>
        </div>
      </div>
    </header>
  );
};

// ==================== DASHBOARD VIEW ====================
const Dashboard = ({ token, showNotification, checkAndRefreshToken }) => {
  const [stats, setStats] = useState({
    totalUploads: 0,
    totalTransactions: 0,
    totalAmount: 0,
    recentUploads: []
  });

  useEffect(() => {
    // TODO: Replace with actual API call
    setStats({
      totalUploads: 127,
      totalTransactions: 1543,
      totalAmount: 2847563.50,
      recentUploads: [
        { id: 1, bank: 'IOB', filename: 'statement_nov_2024.csv', date: '2024-11-28', rows: 45, status: 'success' },
        { id: 2, bank: 'KGB', filename: 'kerala_gramin_oct.xlsx', date: '2024-11-27', rows: 89, status: 'success' },
        { id: 3, bank: 'Indian Bank', filename: 'indianbank_sep.xlsx', date: '2024-11-26', rows: 67, status: 'success' },
      ]
    });
  }, [token]);

  const statCards = [
    {
      title: 'Total Uploads',
      value: stats.totalUploads,
      icon: Upload,
      color: 'from-blue-500 to-blue-600',
      bgColor: 'bg-blue-50'
    },
    {
      title: 'Transactions',
      value: stats.totalTransactions,
      icon: Activity,
      color: 'from-purple-500 to-purple-600',
      bgColor: 'bg-purple-50'
    },
    {
      title: 'Total Amount',
      value: `₹${stats.totalAmount.toLocaleString('en-IN')}`,
      icon: DollarSign,
      color: 'from-emerald-500 to-emerald-600',
      bgColor: 'bg-emerald-50'
    },
    {
      title: 'Success Rate',
      value: '98.5%',
      icon: TrendingUp,
      color: 'from-orange-500 to-orange-600',
      bgColor: 'bg-orange-50'
    },
  ];

  return (
    <div className="space-y-6 animate-fadeInUp">
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statCards.map((stat, index) => {
          const Icon = stat.icon;
          return (
            <div
              key={stat.title}
              className="glass-effect rounded-2xl p-6 hover-lift"
              style={{ animationDelay: `${index * 0.1}s` }}
            >
              <div className="flex items-center justify-between mb-4">
                <div className={`w-12 h-12 ${stat.bgColor} rounded-xl flex items-center justify-center`}>
                  <Icon className="w-6 h-6 text-blue-600" />
                </div>
                <span className="text-xs font-semibold text-emerald-600">+12.5%</span>
              </div>
              <h3 className="text-gray-600 text-sm mb-1">{stat.title}</h3>
              <p className="text-2xl font-bold text-gray-900">{stat.value}</p>
            </div>
          );
        })}
      </div>

      {/* Recent Uploads */}
      <div className="glass-effect rounded-2xl p-6 lg:p-8">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-gray-900">Recent Uploads</h2>
          <button className="text-blue-600 hover:text-blue-700 font-medium text-sm flex items-center gap-2">
            View All
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Bank</th>
                <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Filename</th>
                <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Date</th>
                <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Rows</th>
                <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Status</th>
              </tr>
            </thead>
            <tbody>
              {stats.recentUploads.map((upload, index) => (
                <tr
                  key={upload.id}
                  className="border-b border-gray-100 hover:bg-gray-50 transition-colors duration-200"
                  style={{ animation: `fadeInUp 0.4s ease-out ${index * 0.1}s backwards` }}
                >
                  <td className="py-4 px-4">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center">
                        <FileText className="w-4 h-4 text-blue-600" />
                      </div>
                      <span className="font-medium text-gray-900">{upload.bank}</span>
                    </div>
                  </td>
                  <td className="py-4 px-4 text-gray-600">{upload.filename}</td>
                  <td className="py-4 px-4 text-gray-600">{upload.date}</td>
                  <td className="py-4 px-4 text-gray-600">{upload.rows}</td>
                  <td className="py-4 px-4">
                    <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full bg-emerald-100 text-emerald-700 text-sm font-medium">
                      <CheckCircle className="w-4 h-4" />
                      Success
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

// ==================== UPLOAD VIEW ====================
const UploadView = ({ token, showNotification, setCurrentView, setUser, setToken, setTokenExpiry, user, checkAndRefreshToken }) => {
  const [isDragging, setIsDragging] = useState(false);
  const [uploadData, setUploadData] = useState({
    parserKey: 'iob',
    username: user?.username || 'admin',
    accountNo: '',
    file: null
  });
  const [uploading, setUploading] = useState(false);

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) {
      const validation = validateFile(file);
      if (validation.valid) {
        setUploadData({ ...uploadData, file });
      } else {
        validation.errors.forEach(error => showNotification(error, 'error'));
      }
    }
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file) {
      const validation = validateFile(file);
      if (validation.valid) {
        setUploadData({ ...uploadData, file });
      } else {
        validation.errors.forEach(error => showNotification(error, 'error'));
      }
    }
  };

  const handleUpload = async () => {
    if (!uploadData.file) {
      showNotification('Please select a file', 'error');
      return;
    }

    const validation = validateFile(uploadData.file);
    if (!validation.valid) {
      validation.errors.forEach(error => showNotification(error, 'error'));
      return;
    }

    if (uploadData.parserKey === 'iob' && !uploadData.accountNo) {
      showNotification('Account number is required for IOB statements', 'error');
      return;
    }

    // ✅ CHECK AND REFRESH TOKEN BEFORE API CALL
    const tokenValid = await checkAndRefreshToken();
    if (!tokenValid) {
      return; // Token refresh failed or expired
    }

    setUploading(true);

    try {
      const formData = new FormData();
      formData.append('file', uploadData.file);
      formData.append('parserKey', uploadData.parserKey);
      formData.append('username', uploadData.username);
      if (uploadData.accountNo) {
        formData.append('accountNo', uploadData.accountNo);
      }

      const response = await fetch(`${API_BASE_URL}/statements/upload`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: formData
      });

      if (response.status === 401 || response.status === 403) {
        showNotification('Session expired. Please login again.', 'error');
        setTimeout(() => {
          clearSessionAndRedirect(setCurrentView, setUser, setToken, setTokenExpiry, null, 'upload');
        }, 1500);
        return;
      }

      const data = await response.json();

      if (response.ok) {
        showNotification(
          `Upload successful! Processed ${data.rowsParsed} rows (${data.rowsInserted} new, ${data.rowsDeduped} duplicates)`,
          'success'
        );
        setUploadData({ ...uploadData, file: null, accountNo: '' });
      } else {
        showNotification(data.message || 'Upload failed', 'error');
      }
    } catch (error) {
      showNotification('Upload failed. Please try again.', 'error');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto animate-fadeInUp">
      <div className="glass-effect rounded-2xl p-8 lg:p-10">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Upload Bank Statement</h2>
        <p className="text-gray-600 mb-8">
          Upload CSV, XLS, XLSX, or PDF bank statements for processing (Max {CONFIG.MAX_FILE_SIZE / 1024 / 1024}MB)
        </p>

        <div className="mb-6">
          <label className="block text-sm font-semibold text-gray-700 mb-3">Select Bank</label>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {['iob', 'kgb', 'indianbank'].map((bank) => (
              <button
                key={bank}
                onClick={() => setUploadData({ ...uploadData, parserKey: bank })}
                className={`p-4 rounded-xl border-2 transition-all duration-300 ${
                  uploadData.parserKey === bank
                    ? 'border-blue-500 bg-blue-50 shadow-lg transform scale-105'
                    : 'border-gray-200 hover:border-blue-300'
                }`}
              >
                <div className="font-semibold text-gray-900">
                  {bank === 'iob' && 'Indian Overseas Bank'}
                  {bank === 'kgb' && 'Kerala Gramin Bank'}
                  {bank === 'indianbank' && 'Indian Bank'}
                </div>
                <div className="text-sm text-gray-600 mt-1">
                  {bank === 'iob' && 'CSV Format'}
                  {bank === 'kgb' && 'XLS/XLSX Format'}
                  {bank === 'indianbank' && 'XLS/XLSX Format'}
                </div>
              </button>
            ))}
          </div>
        </div>

        {uploadData.parserKey === 'iob' && (
          <div className="mb-6">
            <label className="block text-sm font-semibold text-gray-700 mb-3">
              Account Number <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={uploadData.accountNo}
              onChange={(e) => setUploadData({ ...uploadData, accountNo: e.target.value })}
              placeholder="Enter account number"
              className="w-full px-4 py-3 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300"
              required
            />
            <p className="text-sm text-gray-600 mt-2">Required for IOB statements</p>
          </div>
        )}

        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-2xl p-12 text-center transition-all duration-300 ${
            isDragging
              ? 'border-blue-500 bg-blue-50 scale-105'
              : 'border-gray-300 hover:border-blue-400'
          }`}
        >
          <div className="flex flex-col items-center">
            <div className={`w-16 h-16 rounded-full flex items-center justify-center mb-4 transition-all duration-300 ${
              uploadData.file ? 'bg-emerald-100' : 'bg-blue-100'
            }`}>
              {uploadData.file ? (
                <CheckCircle className="w-8 h-8 text-emerald-600" />
              ) : (
                <Upload className="w-8 h-8 text-blue-600" />
              )}
            </div>

            {uploadData.file ? (
              <>
                <p className="text-lg font-semibold text-gray-900 mb-2">{uploadData.file.name}</p>
                <p className="text-sm text-gray-600 mb-4">
                  {(uploadData.file.size / 1024).toFixed(2)} KB
                </p>
                <button
                  onClick={() => setUploadData({ ...uploadData, file: null })}
                  className="text-red-600 hover:text-red-700 font-medium text-sm"
                >
                  Remove file
                </button>
              </>
            ) : (
              <>
                <p className="text-lg font-semibold text-gray-900 mb-2">
                  Drag and drop your file here
                </p>
                <p className="text-sm text-gray-600 mb-4">or</p>
                <label className="cursor-pointer">
                  <span className="px-6 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 text-white rounded-xl font-semibold hover:shadow-lg transition-all duration-300 inline-block">
                    Browse Files
                  </span>
                  <input
                    type="file"
                    onChange={handleFileSelect}
                    accept={CONFIG.ALLOWED_FILE_EXTENSIONS.join(',')}
                    className="hidden"
                  />
                </label>
                <p className="text-xs text-gray-500 mt-4">
                  Supported formats: CSV, XLS, XLSX, PDF (Max {CONFIG.MAX_FILE_SIZE / 1024 / 1024}MB)
                </p>
              </>
            )}
          </div>
        </div>

        <button
          onClick={handleUpload}
          disabled={!uploadData.file || uploading}
          className={`w-full mt-6 py-4 rounded-xl font-semibold text-white transition-all duration-300 ${
            uploadData.file && !uploading
              ? 'bg-gradient-to-r from-blue-600 to-indigo-600 hover:shadow-xl transform hover:scale-105'
              : 'bg-gray-300 cursor-not-allowed'
          }`}
        >
          {uploading ? (
            <span className="flex items-center justify-center gap-3">
              <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
              Processing...
            </span>
          ) : (
            'Upload Statement'
          )}
        </button>
      </div>
    </div>
  );
};

// ==================== STATEMENTS VIEW ====================
const StatementsView = ({ token, showNotification, checkAndRefreshToken }) => {
  const [statements, setStatements] = useState([]);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // TODO: Replace with actual API call to fetch statements
    setTimeout(() => {
      setStatements([
        { id: 1, date: '2024-11-28', bank: 'IOB', filename: 'statement_nov.csv', transactions: 45, amount: 125000, status: 'processed' },
        { id: 2, date: '2024-11-27', bank: 'KGB', filename: 'kerala_oct.xlsx', transactions: 89, amount: 287500, status: 'processed' },
        { id: 3, date: '2024-11-26', bank: 'Indian Bank', filename: 'indianbank_sep.xlsx', transactions: 67, amount: 198750, status: 'processed' },
        { id: 4, date: '2024-11-25', bank: 'IOB', filename: 'statement_aug.csv', transactions: 52, amount: 164320, status: 'pending' },
        { id: 5, date: '2024-11-24', bank: 'KGB', filename: 'kerala_jul.xlsx', transactions: 78, amount: 234650, status: 'processed' },
      ]);
      setLoading(false);
    }, 500);
  }, [token]);

  const filteredStatements = statements.filter(stmt => {
    const matchesFilter = filter === 'all' || stmt.status === filter;
    const matchesSearch = stmt.filename.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         stmt.bank.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  return (
    <div className="animate-fadeInUp">
      <div className="glass-effect rounded-2xl p-6 lg:p-8">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between mb-6 gap-4">
          <div>
            <h2 className="text-2xl font-bold text-gray-900">Statement History</h2>
            <p className="text-gray-600 mt-1">View and manage all uploaded statements</p>
          </div>

          <div className="flex gap-3">
            <div className="relative flex-1 lg:flex-none">
              <Search className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search statements..."
                className="pl-10 pr-4 py-2 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 w-full lg:w-64"
              />
            </div>
          </div>
        </div>

        <div className="flex gap-3 mb-6 overflow-x-auto pb-2">
          {['all', 'processed', 'pending'].map((status) => (
            <button
              key={status}
              onClick={() => setFilter(status)}
              className={`px-4 py-2 rounded-xl font-medium transition-all duration-300 whitespace-nowrap ${
                filter === status
                  ? 'bg-blue-600 text-white shadow-lg'
                  : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              }`}
            >
              {status.charAt(0).toUpperCase() + status.slice(1)}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="text-center py-12">
            <div className="w-12 h-12 border-4 border-blue-200 border-t-blue-600 rounded-full animate-spin mx-auto mb-4"></div>
            <p className="text-gray-600">Loading statements...</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-200">
                    <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Date</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Bank</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Filename</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Transactions</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Amount</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Status</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredStatements.map((stmt, index) => (
                    <tr
                      key={stmt.id}
                      className="border-b border-gray-100 hover:bg-gray-50 transition-colors duration-200"
                      style={{ animation: `fadeInUp 0.4s ease-out ${index * 0.1}s backwards` }}
                    >
                      <td className="py-4 px-4 text-gray-600">{stmt.date}</td>
                      <td className="py-4 px-4">
                        <span className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-blue-100 text-blue-700 text-sm font-medium">
                          <FileText className="w-4 h-4" />
                          {stmt.bank}
                        </span>
                      </td>
                      <td className="py-4 px-4 text-gray-900 font-medium">{stmt.filename}</td>
                      <td className="py-4 px-4 text-gray-600">{stmt.transactions}</td>
                      <td className="py-4 px-4 text-gray-900 font-semibold">₹{stmt.amount.toLocaleString('en-IN')}</td>
                      <td className="py-4 px-4">
                        <span className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-sm font-medium ${
                          stmt.status === 'processed'
                            ? 'bg-emerald-100 text-emerald-700'
                            : 'bg-yellow-100 text-yellow-700'
                        }`}>
                          {stmt.status === 'processed' ? (
                            <CheckCircle className="w-4 h-4" />
                          ) : (
                            <Activity className="w-4 h-4 animate-spin" />
                          )}
                          {stmt.status.charAt(0).toUpperCase() + stmt.status.slice(1)}
                        </span>
                      </td>
                      <td className="py-4 px-4">
                        <button
                          className="text-blue-600 hover:text-blue-700 transition-colors duration-200"
                          onClick={() => showNotification('Download feature coming soon!', 'info')}
                        >
                          <Download className="w-5 h-5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {filteredStatements.length === 0 && (
              <div className="text-center py-12">
                <FileText className="w-16 h-16 text-gray-300 mx-auto mb-4" />
                <p className="text-gray-600">No statements found</p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

// ==================== USER MANAGEMENT VIEW ====================
const UserManagementView = ({ token, showNotification, setCurrentView, setUser, setToken, setTokenExpiry, checkAndRefreshToken }) => {
  const [newUser, setNewUser] = useState({
    username: '',
    password: '',
    confirmPassword: '',
    roleIds: [2],
    selectedRole: 'user'
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [creating, setCreating] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState(0);

  const calculatePasswordStrength = (password) => {
    let strength = 0;
    if (password.length >= 8) strength += 25;
    if (password.length >= 12) strength += 15;
    if (/[a-z]/.test(password)) strength += 15;
    if (/[A-Z]/.test(password)) strength += 15;
    if (/[0-9]/.test(password)) strength += 15;
    if (/[^a-zA-Z0-9]/.test(password)) strength += 15;
    return Math.min(strength, 100);
  };

  const getStrengthColor = (strength) => {
    if (strength < 40) return 'bg-red-500';
    if (strength < 70) return 'bg-yellow-500';
    return 'bg-emerald-500';
  };

  const getStrengthText = (strength) => {
    if (strength < 40) return 'Weak';
    if (strength < 70) return 'Medium';
    return 'Strong';
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    showNotification('Password copied to clipboard!', 'success');
  };

  useEffect(() => {
    setPasswordStrength(calculatePasswordStrength(newUser.password));
  }, [newUser.password]);

  const requirements = [
    { label: 'At least 8 characters', met: newUser.password.length >= 8 },
    { label: 'Uppercase letter', met: /[A-Z]/.test(newUser.password) },
    { label: 'Lowercase letter', met: /[a-z]/.test(newUser.password) },
    { label: 'Number', met: /[0-9]/.test(newUser.password) },
    { label: 'Special character', met: /[^a-zA-Z0-9]/.test(newUser.password) },
  ];

  const handleCreateUser = async (e) => {
    e.preventDefault();

    if (!token) {
      showNotification('Session expired. Please login again.', 'error');
      setTimeout(() => {
        clearSessionAndRedirect(setCurrentView, setUser, setToken, setTokenExpiry, null);
      }, 2000);
      return;
    }

    if (newUser.username.length < 3) {
      showNotification('Username must be at least 3 characters long', 'error');
      return;
    }

    if (newUser.password.length < CONFIG.PASSWORD_MIN_LENGTH) {
      showNotification(`Password must be at least ${CONFIG.PASSWORD_MIN_LENGTH} characters long`, 'error');
      return;
    }

    if (newUser.password !== newUser.confirmPassword) {
      showNotification('Passwords do not match', 'error');
      return;
    }

    if (passwordStrength < 40) {
      showNotification('Password is too weak. Please use a stronger password.', 'error');
      return;
    }

    // ✅ CHECK AND REFRESH TOKEN BEFORE API CALL
    const tokenValid = await checkAndRefreshToken();
    if (!tokenValid) {
      return;
    }

    setCreating(true);

    try {
      const response = await fetch(`${API_AUTH_URL}/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          username: sanitizeInput(newUser.username),
          password: newUser.password,
          roleIds: newUser.roleIds
        }),
      });

      let data = null;
      if (response.ok || response.headers.get('content-type')?.includes('application/json')) {
        try {
          data = await response.json();
        } catch (jsonError) {
          data = { message: 'Invalid response from server' };
        }
      }

      if (response.ok) {
        const roleText = newUser.selectedRole === 'admin' ? 'Administrator' : 'User';
        showNotification(`${roleText} "${newUser.username}" created successfully!`, 'success');

        setNewUser({
          username: '',
          password: '',
          confirmPassword: '',
          roleIds: [2],
          selectedRole: 'user'
        });
        setPasswordStrength(0);
      } else {
        if (response.status === 403) {
          showNotification('Access denied. Only administrators can create users.', 'error');
        } else if (response.status === 401) {
          showNotification('Session expired. Please login again.', 'error');
          setTimeout(() => {
            clearSessionAndRedirect(setCurrentView, setUser, setToken, setTokenExpiry, null);
          }, 1500);
        } else if (response.status === 409 || (data?.message && data.message.includes('already exists'))) {
          showNotification('Username already exists. Please choose a different username.', 'error');
        } else {
          showNotification(data?.message || 'Failed to create user', 'error');
        }
      }
    } catch (error) {
      showNotification('Failed to create user. Please try again.', 'error');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto animate-fadeInUp">
      <div className="glass-effect rounded-2xl p-8 lg:p-10">
        <div className="flex items-center gap-4 mb-8">
          <div className="w-16 h-16 bg-gradient-to-br from-purple-500 to-indigo-600 rounded-2xl flex items-center justify-center">
            <Users className="w-8 h-8 text-white" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-gray-900">User Management</h2>
            <p className="text-gray-600">Create new user accounts with secure credentials</p>
          </div>
        </div>

        <form onSubmit={handleCreateUser} className="space-y-6">
          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-3">
              Username <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={newUser.username}
              onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
              placeholder="Enter username"
              className="w-full px-4 py-3 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300"
              required
              minLength={3}
              maxLength={50}
            />
          </div>

          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-3">
              Role <span className="text-red-500">*</span>
            </label>
            <div className="grid grid-cols-2 gap-4">
              <button
                type="button"
                onClick={() => setNewUser({ ...newUser, selectedRole: 'user', roleIds: [2] })}
                className={`p-4 rounded-xl border-2 transition-all duration-300 ${
                  newUser.selectedRole === 'user'
                    ? 'border-blue-500 bg-blue-50 shadow-lg'
                    : 'border-gray-200 hover:border-blue-300'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                    newUser.selectedRole === 'user' ? 'bg-blue-500' : 'bg-gray-300'
                  }`}>
                    <Users className="w-5 h-5 text-white" />
                  </div>
                  <div className="text-left">
                    <div className="font-semibold text-gray-900">User</div>
                    <div className="text-sm text-gray-600">Standard access</div>
                  </div>
                </div>
              </button>

              <button
                type="button"
                onClick={() => setNewUser({ ...newUser, selectedRole: 'admin', roleIds: [1, 2] })}
                className={`p-4 rounded-xl border-2 transition-all duration-300 ${
                  newUser.selectedRole === 'admin'
                    ? 'border-purple-500 bg-purple-50 shadow-lg'
                    : 'border-gray-200 hover:border-purple-300'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                    newUser.selectedRole === 'admin' ? 'bg-purple-500' : 'bg-gray-300'
                  }`}>
                    <Shield className="w-5 h-5 text-white" />
                  </div>
                  <div className="text-left">
                    <div className="font-semibold text-gray-900">Administrator</div>
                    <div className="text-sm text-gray-600">Full access</div>
                  </div>
                </div>
              </button>
            </div>
            <p className="text-sm text-gray-600 mt-2">
              {newUser.selectedRole === 'admin'
                ? '⚠️ Administrators can create users and access all features'
                : 'Users can upload statements and view their data'}
            </p>
          </div>

          <div>
            <div className="flex items-center justify-between mb-3">
              <label className="block text-sm font-semibold text-gray-700">
                Password <span className="text-red-500">*</span>
              </label>
              <button
                type="button"
                onClick={() => {
                  const password = generateSecurePassword();
                  setNewUser({ ...newUser, password, confirmPassword: password });
                  showNotification('Secure password generated!', 'success');
                }}
                className="flex items-center gap-2 text-sm text-blue-600 hover:text-blue-700 font-medium"
              >
                <RefreshCw className="w-4 h-4" />
                Generate Password
              </button>
            </div>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                placeholder="Enter password"
                className="w-full px-4 py-3 pr-24 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300"
                required
                minLength={CONFIG.PASSWORD_MIN_LENGTH}
              />
              <div className="absolute right-3 top-1/2 transform -translate-y-1/2 flex gap-2">
                <button
                  type="button"
                  onClick={() => copyToClipboard(newUser.password)}
                  className="text-gray-400 hover:text-gray-600"
                  disabled={!newUser.password}
                >
                  <Copy className="w-5 h-5" />
                </button>
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            {newUser.password && (
              <div className="mt-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-gray-600">Password Strength:</span>
                  <span className={`text-sm font-semibold ${
                    passwordStrength < 40 ? 'text-red-600' :
                    passwordStrength < 70 ? 'text-yellow-600' : 'text-emerald-600'
                  }`}>
                    {getStrengthText(passwordStrength)}
                  </span>
                </div>
                <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${getStrengthColor(passwordStrength)}`}
                    style={{ width: `${passwordStrength}%` }}
                  ></div>
                </div>
              </div>
            )}

            <div className="mt-4 space-y-2">
              {requirements.map((req, index) => (
                <div key={index} className="flex items-center gap-2">
                  <CheckCircle className={`w-4 h-4 ${req.met ? 'text-emerald-500' : 'text-gray-300'}`} />
                  <span className={`text-sm ${req.met ? 'text-gray-700' : 'text-gray-400'}`}>
                    {req.label}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-3">
              Confirm Password <span className="text-red-500">*</span>
            </label>
            <div className="relative">
              <input
                type={showConfirmPassword ? 'text' : 'password'}
                value={newUser.confirmPassword}
                onChange={(e) => setNewUser({ ...newUser, confirmPassword: e.target.value })}
                placeholder="Confirm password"
                className="w-full px-4 py-3 pr-12 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300"
                required
                minLength={CONFIG.PASSWORD_MIN_LENGTH}
              />
              <button
                type="button"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                {showConfirmPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
            {newUser.confirmPassword && (
              <div className="mt-2 flex items-center gap-2">
                {newUser.password === newUser.confirmPassword ? (
                  <>
                    <CheckCircle className="w-4 h-4 text-emerald-500" />
                    <span className="text-sm text-emerald-600">Passwords match</span>
                  </>
                ) : (
                  <>
                    <XCircle className="w-4 h-4 text-red-500" />
                    <span className="text-sm text-red-600">Passwords do not match</span>
                  </>
                )}
              </div>
            )}
          </div>

          <button
            type="submit"
            disabled={creating || passwordStrength < 40}
            className={`w-full py-4 rounded-xl font-semibold text-white transition-all duration-300 ${
              !creating && passwordStrength >= 40
                ? 'bg-gradient-to-r from-purple-600 to-indigo-600 hover:shadow-xl transform hover:scale-105'
                : 'bg-gray-300 cursor-not-allowed'
            }`}
          >
            {creating ? (
              <span className="flex items-center justify-center gap-3">
                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                Creating User...
              </span>
            ) : (
              'Create User'
            )}
          </button>
        </form>
      </div>
    </div>
  );
};

// ==================== CHANGE PASSWORD VIEW ====================
const ChangePasswordView = ({ token, user, showNotification, setCurrentView, setUser, setToken, setTokenExpiry, checkAndRefreshToken }) => {
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmNewPassword: ''
  });
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [changing, setChanging] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState(0);

  const calculatePasswordStrength = (password) => {
    let strength = 0;
    if (password.length >= 8) strength += 25;
    if (password.length >= 12) strength += 15;
    if (/[a-z]/.test(password)) strength += 15;
    if (/[A-Z]/.test(password)) strength += 15;
    if (/[0-9]/.test(password)) strength += 15;
    if (/[^a-zA-Z0-9]/.test(password)) strength += 15;
    return Math.min(strength, 100);
  };

  const getStrengthColor = (strength) => {
    if (strength < 40) return 'bg-red-500';
    if (strength < 70) return 'bg-yellow-500';
    return 'bg-emerald-500';
  };

  const getStrengthText = (strength) => {
    if (strength < 40) return 'Weak';
    if (strength < 70) return 'Medium';
    return 'Strong';
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    showNotification('Password copied to clipboard!', 'success');
  };

  useEffect(() => {
    setPasswordStrength(calculatePasswordStrength(passwordData.newPassword));
  }, [passwordData.newPassword]);

  const requirements = [
    { label: 'At least 8 characters', met: passwordData.newPassword.length >= 8 },
    { label: 'Uppercase letter', met: /[A-Z]/.test(passwordData.newPassword) },
    { label: 'Lowercase letter', met: /[a-z]/.test(passwordData.newPassword) },
    { label: 'Number', met: /[0-9]/.test(passwordData.newPassword) },
    { label: 'Special character', met: /[^a-zA-Z0-9]/.test(passwordData.newPassword) },
  ];

  const handleChangePassword = async (e) => {
    e.preventDefault();

    if (!token) {
      showNotification('Session expired. Please login again.', 'error');
      setTimeout(() => {
        clearSessionAndRedirect(setCurrentView, setUser, setToken, setTokenExpiry, null);
      }, 2000);
      return;
    }

    if (!passwordData.currentPassword) {
      showNotification('Please enter your current password', 'error');
      return;
    }

    if (passwordData.newPassword.length < CONFIG.PASSWORD_MIN_LENGTH) {
      showNotification(`New password must be at least ${CONFIG.PASSWORD_MIN_LENGTH} characters long`, 'error');
      return;
    }

    if (passwordData.newPassword !== passwordData.confirmNewPassword) {
      showNotification('New passwords do not match', 'error');
      return;
    }

    if (passwordStrength < 40) {
      showNotification('New password is too weak. Please use a stronger password.', 'error');
      return;
    }

    if (passwordData.currentPassword === passwordData.newPassword) {
      showNotification('New password must be different from current password', 'error');
      return;
    }

    // ✅ CHECK AND REFRESH TOKEN BEFORE API CALL
    const tokenValid = await checkAndRefreshToken();
    if (!tokenValid) {
      return;
    }

    setChanging(true);

    try {
      const response = await fetch(`${API_AUTH_URL}/auth/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          currentPassword: passwordData.currentPassword,
          newPassword: passwordData.newPassword
        }),
      });

      let data = null;
      if (response.ok || response.headers.get('content-type')?.includes('application/json')) {
        try {
          data = await response.json();
        } catch (jsonError) {
          data = { message: 'Invalid response from server' };
        }
      }

      if (response.ok) {
        showNotification('Password changed successfully!', 'success');
        setPasswordData({
          currentPassword: '',
          newPassword: '',
          confirmNewPassword: ''
        });
        setPasswordStrength(0);
      } else {
        if (response.status === 401) {
          showNotification('Session expired or current password incorrect. Please try again.', 'error');
        } else {
          showNotification(data?.message || 'Failed to change password', 'error');
        }
      }
    } catch (error) {
      showNotification('Failed to change password. Please try again.', 'error');
    } finally {
      setChanging(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto animate-fadeInUp">
      <div className="glass-effect rounded-2xl p-8 lg:p-10">
        <div className="flex items-center gap-4 mb-8">
          <div className="w-16 h-16 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-2xl flex items-center justify-center">
            <Key className="w-8 h-8 text-white" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-gray-900">Change Password</h2>
            <p className="text-gray-600">Update your account password securely</p>
          </div>
        </div>

        <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-500 rounded-full flex items-center justify-center">
              <Users className="w-5 h-5 text-white" />
            </div>
            <div>
              <p className="text-sm text-gray-600">Changing password for</p>
              <p className="font-semibold text-gray-900">{user?.name || user?.username}</p>
            </div>
          </div>
        </div>

        <form onSubmit={handleChangePassword} className="space-y-6">
          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-3">
              Current Password <span className="text-red-500">*</span>
            </label>
            <div className="relative">
              <input
                type={showCurrentPassword ? 'text' : 'password'}
                value={passwordData.currentPassword}
                onChange={(e) => setPasswordData({ ...passwordData, currentPassword: e.target.value })}
                placeholder="Enter current password"
                className="w-full px-4 py-3 pr-12 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300"
                required
              />
              <button
                type="button"
                onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                {showCurrentPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-3">
              <label className="block text-sm font-semibold text-gray-700">
                New Password <span className="text-red-500">*</span>
              </label>
              <button
                type="button"
                onClick={() => {
                  const password = generateSecurePassword();
                  setPasswordData({ ...passwordData, newPassword: password, confirmNewPassword: password });
                  showNotification('Secure password generated!', 'success');
                }}
                className="flex items-center gap-2 text-sm text-blue-600 hover:text-blue-700 font-medium"
              >
                <RefreshCw className="w-4 h-4" />
                Generate Password
              </button>
            </div>
            <div className="relative">
              <input
                type={showNewPassword ? 'text' : 'password'}
                value={passwordData.newPassword}
                onChange={(e) => setPasswordData({ ...passwordData, newPassword: e.target.value })}
                placeholder="Enter new password"
                className="w-full px-4 py-3 pr-24 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300"
                required
                minLength={CONFIG.PASSWORD_MIN_LENGTH}
              />
              <div className="absolute right-3 top-1/2 transform -translate-y-1/2 flex gap-2">
                <button
                  type="button"
                  onClick={() => copyToClipboard(passwordData.newPassword)}
                  className="text-gray-400 hover:text-gray-600"
                  disabled={!passwordData.newPassword}
                >
                  <Copy className="w-5 h-5" />
                </button>
                <button
                  type="button"
                  onClick={() => setShowNewPassword(!showNewPassword)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  {showNewPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            {passwordData.newPassword && (
              <div className="mt-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-gray-600">Password Strength:</span>
                  <span className={`text-sm font-semibold ${
                    passwordStrength < 40 ? 'text-red-600' :
                    passwordStrength < 70 ? 'text-yellow-600' : 'text-emerald-600'
                  }`}>
                    {getStrengthText(passwordStrength)}
                  </span>
                </div>
                <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${getStrengthColor(passwordStrength)}`}
                    style={{ width: `${passwordStrength}%` }}
                  ></div>
                </div>
              </div>
            )}

            <div className="mt-4 space-y-2">
              {requirements.map((req, index) => (
                <div key={index} className="flex items-center gap-2">
                  <CheckCircle className={`w-4 h-4 ${req.met ? 'text-emerald-500' : 'text-gray-300'}`} />
                  <span className={`text-sm ${req.met ? 'text-gray-700' : 'text-gray-400'}`}>
                    {req.label}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-3">
              Confirm New Password <span className="text-red-500">*</span>
            </label>
            <div className="relative">
              <input
                type={showConfirmPassword ? 'text' : 'password'}
                value={passwordData.confirmNewPassword}
                onChange={(e) => setPasswordData({ ...passwordData, confirmNewPassword: e.target.value })}
                placeholder="Confirm new password"
                className="w-full px-4 py-3 pr-12 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300"
                required
                minLength={CONFIG.PASSWORD_MIN_LENGTH}
              />
              <button
                type="button"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                {showConfirmPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
            {passwordData.confirmNewPassword && (
              <div className="mt-2 flex items-center gap-2">
                {passwordData.newPassword === passwordData.confirmNewPassword ? (
                  <>
                    <CheckCircle className="w-4 h-4 text-emerald-500" />
                    <span className="text-sm text-emerald-600">Passwords match</span>
                  </>
                ) : (
                  <>
                    <XCircle className="w-4 h-4 text-red-500" />
                    <span className="text-sm text-red-600">Passwords do not match</span>
                  </>
                )}
              </div>
            )}
          </div>

          <button
            type="submit"
            disabled={changing || passwordStrength < 40}
            className={`w-full py-4 rounded-xl font-semibold text-white transition-all duration-300 ${
              !changing && passwordStrength >= 40
                ? 'bg-gradient-to-r from-indigo-600 to-purple-600 hover:shadow-xl transform hover:scale-105'
                : 'bg-gray-300 cursor-not-allowed'
            }`}
          >
            {changing ? (
              <span className="flex items-center justify-center gap-3">
                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                Changing Password...
              </span>
            ) : (
              'Change Password'
            )}
          </button>
        </form>

        <div className="mt-6 bg-yellow-50 border border-yellow-200 rounded-xl p-4">
          <div className="flex gap-3">
            <Shield className="w-5 h-5 text-yellow-600 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-semibold text-yellow-800 mb-1">Security Tips</p>
              <ul className="text-sm text-yellow-700 space-y-1">
                <li>• Use a unique password you don't use anywhere else</li>
                <li>• Consider using a password manager</li>
                <li>• Change your password regularly</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CipherBankUI;