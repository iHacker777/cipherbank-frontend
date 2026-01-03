import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Upload, FileText, CheckCircle, XCircle, TrendingUp, DollarSign, Activity, LogOut, Menu, X, ChevronRight, Download, Search, Filter, Users, Shield, Eye, EyeOff, Copy, RefreshCw, Key, AlertTriangle, Clock, ArrowUpDown, Calendar, Sun, Moon, Smartphone, Palette, Info, User } from 'lucide-react';
import IOSInstallPrompt from './components/IOSInstallPrompt';
import BottomTabBar from './components/BottomTabBar';
import './ios26-liquid-glass.css';
import './ios26-mobile-fixes.css'; // NEW: Mobile layout fixes and theme support
import haptics from './utils/ios-haptics';


// ==================== CONFIGURATION ====================
const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'https://cipher.thepaytrix.com/api';
const API_AUTH_URL = process.env.REACT_APP_API_AUTH_URL || 'https://testing.thepaytrix.com/api';

const CONFIG = {
  NOTIFICATION_DURATION: 5000,
  PASSWORD_MIN_LENGTH: 6,
  MAX_FILE_SIZE: 10 * 1024 * 1024,
  ALLOWED_FILE_EXTENSIONS: ['.csv', '.xls', '.xlsx', '.pdf'],
  AUTO_REFRESH_THRESHOLD: 120000,
  TOKEN_CHECK_INTERVAL: 60000,
};

// ==================== UTILITY FUNCTIONS ====================
const isTokenExpired = (tokenExpiry) => {
  if (!tokenExpiry) return true;
  return Date.now() >= tokenExpiry;
};

const isTokenNearExpiry = (tokenExpiry, threshold = CONFIG.AUTO_REFRESH_THRESHOLD) => {
  if (!tokenExpiry) return false;
  const timeUntilExpiry = tokenExpiry - Date.now();
  return timeUntilExpiry > 0 && timeUntilExpiry <= threshold;
};

const formatTimeRemaining = (tokenExpiry) => {
  if (!tokenExpiry) return 'Unknown';
  const diff = tokenExpiry - Date.now();
  if (diff <= 0) return 'Expired';
  const minutes = Math.floor(diff / 60000);
  const seconds = Math.floor((diff % 60000) / 1000);
  return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
};

const clearSessionAndRedirect = (setCurrentView, setUser, setToken, setTokenExpiry, showNotification, currentView) => {
  localStorage.removeItem('cipherbank_token');
  localStorage.removeItem('cipherbank_user');
  localStorage.removeItem('cipherbank_token_expiry');
  localStorage.removeItem('cipherbank_credentials');
  setToken(null);
  setUser(null);
  setTokenExpiry(null);
  setCurrentView('login');
  if (showNotification && currentView !== 'login') {
    showNotification('Session expired. Please login again.', 'error');
  }
};

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
  return { valid: errors.length === 0, errors };
};

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
          <div className="max-w-md w-full lg-card p-8 text-center">
            <XCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
            <h1 className="text-2xl font-bold text-gray-900 mb-2">Something went wrong</h1>
            <p className="text-gray-600 mb-6">
              An unexpected error occurred. Please refresh the page and try again.
            </p>
            <button
              onClick={() => window.location.reload()}
              className="lg-btn lg-btn-primary"
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
  const credentialsRef = useRef(null);

  // ==================== THEME STATE ====================
  const [theme, setTheme] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('cipherbank_theme') || 'system';
    }
    return 'system';
  });

  // Apply theme effect
  useEffect(() => {
    const applyTheme = () => {
      const root = document.documentElement;
      root.removeAttribute('data-theme');

      if (theme === 'light') {
        root.setAttribute('data-theme', 'light');
      } else if (theme === 'dark') {
        root.setAttribute('data-theme', 'dark');
      }
      // For 'system', no data-theme attribute - CSS media queries handle it

      // Update meta theme-color for browser chrome
      const metaThemeColor = document.querySelector('meta[name="theme-color"]');
      if (metaThemeColor) {
        const isDark = theme === 'dark' ||
          (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
        metaThemeColor.setAttribute('content', isDark ? '#0A84FF' : '#007AFF');
      }
    };

    applyTheme();

    // Listen for system theme changes
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = () => {
      if (theme === 'system') applyTheme();
    };
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, [theme]);

  // Handle theme change
  const handleThemeChange = (newTheme) => {
    setTheme(newTheme);
    localStorage.setItem('cipherbank_theme', newTheme);
    haptics.selection();
  };

  // iOS Detection and Setup
  useEffect(() => {
    const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
    const isStandalone = window.navigator.standalone ||
                        window.matchMedia('(display-mode: standalone)').matches;

    if (isIOS) {
      document.documentElement.classList.add('ios-device');

      if (isStandalone) {
        document.documentElement.classList.add('ios-standalone');
        console.log('📱 Running in iOS standalone mode');
      }

      const setVH = () => {
        const vh = window.innerHeight * 0.01;
        document.documentElement.style.setProperty('--vh', `${vh}px`);
      };

      setVH();
      window.addEventListener('resize', setVH);
      window.addEventListener('orientationchange', setVH);

      return () => {
        window.removeEventListener('resize', setVH);
        window.removeEventListener('orientationchange', setVH);
      };
    }
  }, []);

  useEffect(() => {
    const savedToken = localStorage.getItem('cipherbank_token');
    const savedUser = localStorage.getItem('cipherbank_user');
    const savedExpiry = localStorage.getItem('cipherbank_token_expiry');
    const savedCredentials = localStorage.getItem('cipherbank_credentials');

    if (savedToken && savedUser && savedExpiry) {
      const expiryTime = parseInt(savedExpiry, 10);
      if (!isTokenExpired(expiryTime)) {
        try {
          const userData = JSON.parse(savedUser);
          setToken(savedToken);
          setUser(userData);
          setTokenExpiry(expiryTime);
          setCurrentView('dashboard');
          if (savedCredentials) {
            try {
              credentialsRef.current = JSON.parse(atob(savedCredentials));
              setAutoRefreshEnabled(true);
            } catch (e) {
              localStorage.removeItem('cipherbank_credentials');
            }
          }
        } catch (error) {
          clearSessionAndRedirect(setCurrentView, setUser, setToken, setTokenExpiry, null, 'login');
        }
      } else {
        clearSessionAndRedirect(setCurrentView, setUser, setToken, setTokenExpiry, null, 'login');
      }
    }
  }, []);

  useEffect(() => {
    if (!token || !tokenExpiry || currentView === 'login') return;

    const checkTokenExpiry = () => {
      if (isTokenExpired(tokenExpiry)) {
        clearSessionAndRedirect(setCurrentView, setUser, setToken, setTokenExpiry, showNotification, currentView);
        return;
      }

      if (isTokenNearExpiry(tokenExpiry) && !sessionWarningShown) {
        haptics.warning();
        const timeRemaining = formatTimeRemaining(tokenExpiry);
        showNotification(
          `Your session will expire in ${timeRemaining}. ${autoRefreshEnabled ? 'Auto-refresh is enabled.' : 'Please save your work.'}`,
          'warning'
        );
        setSessionWarningShown(true);
      }
    };

    checkTokenExpiry();
    const intervalId = setInterval(checkTokenExpiry, CONFIG.TOKEN_CHECK_INTERVAL);
    return () => clearInterval(intervalId);
  }, [token, tokenExpiry, currentView, sessionWarningShown, autoRefreshEnabled]);

  const refreshToken = useCallback(async () => {
    if (!autoRefreshEnabled || !credentialsRef.current || isRefreshing) return false;

    setIsRefreshing(true);

    try {
      const response = await fetch(`${API_AUTH_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentialsRef.current),
      });

      if (response.ok) {
        const data = await response.json();
        if (data.token && data.tokenExpirationMillis) {
          setToken(data.token);
          setTokenExpiry(data.tokenExpirationMillis);
          localStorage.setItem('cipherbank_token', data.token);
          localStorage.setItem('cipherbank_token_expiry', data.tokenExpirationMillis.toString());
          const userData = {
            username: data.username,
            name: data.name,
            roles: data.roles || ['ROLE_USER']
          };
          setUser(userData);
          localStorage.setItem('cipherbank_user', JSON.stringify(userData));
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

  const checkAndRefreshToken = useCallback(async () => {
    if (!tokenExpiry) return true;
    if (isTokenNearExpiry(tokenExpiry) && autoRefreshEnabled) {
      return await refreshToken();
    }
    if (isTokenExpired(tokenExpiry)) {
      clearSessionAndRedirect(setCurrentView, setUser, setToken, setTokenExpiry, showNotification, currentView);
      return false;
    }
    return true;
  }, [tokenExpiry, autoRefreshEnabled, refreshToken, currentView]);

  const showNotification = (message, type = 'success') => {
    setNotification({ message, type });

    if (type === 'success') {
      haptics.success();
    } else if (type === 'error') {
      haptics.error();
    } else if (type === 'warning') {
      haptics.warning();
    } else {
      haptics.light();
    }

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
      <div className="app-container">
        <IOSInstallPrompt />

        {/* Notification Toast - iOS 26 Liquid Glass Style */}
        {notification && (
          <div className={`notification notification-${notification.type}`}>
            <div className="notification-content">
              <div className="notification-icon">
                {notification.type === 'success' && <CheckCircle size={20} />}
                {notification.type === 'error' && <XCircle size={20} />}
                {notification.type === 'warning' && <AlertTriangle size={20} />}
                {notification.type === 'info' && <Clock size={20} />}
              </div>
              <span className="notification-text">{notification.message}</span>
            </div>
          </div>
        )}

        {/* Session Expiry Indicator */}
        {token && tokenExpiry && currentView !== 'login' && (
          <div className="session-indicator desktop-only">
            <Clock className="w-4 h-4" />
            <div className="text-sm">
              <span>Session: </span>
              <span className={isTokenNearExpiry(tokenExpiry) ? 'text-red-500 font-semibold' : ''}>
                {formatTimeRemaining(tokenExpiry)}
              </span>
            </div>
            {autoRefreshEnabled && (
              <div className="auto-refresh-badge">
                <RefreshCw className="w-3 h-3" />
                <span>Auto</span>
              </div>
            )}
          </div>
        )}

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
            theme={theme}
            setTheme={handleThemeChange}
          />
        )}

        {/* Bottom Tab Bar - iOS 26 Floating Style */}
        {currentView !== 'login' && (
          <BottomTabBar
            currentView={currentView}
            setCurrentView={setCurrentView}
            user={user}
          />
        )}

        {/* Loading Overlay */}
        {(isLoading || isRefreshing) && (
          <div className="loading-overlay">
            <div className="loading-card lg-card">
              <div className="loading-spinner"></div>
              <p className="loading-text">
                {isRefreshing ? 'Refreshing session...' : 'Processing...'}
              </p>
            </div>
          </div>
        )}
      </div>
    </ErrorBoundary>
  );
};

// ==================== LOGIN VIEW ====================
const LoginView = ({ setCurrentView, setUser, setToken, setTokenExpiry, showNotification, setIsLoading, setSessionWarningShown, setAutoRefreshEnabled, credentialsRef }) => {
  const [formData, setFormData] = useState({ username: '', password: '' });
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
      haptics.error();
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
        headers: { 'Content-Type': 'application/json' },
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
          haptics.error();
          showNotification('No token received from server', 'error');
          return;
        }

        haptics.success();
        const tokenExpirationMillis = data.tokenExpirationMillis || (Date.now() + (data.tokenValidityMillis || 7200000));
        setToken(data.token);
        setTokenExpiry(tokenExpirationMillis);
        localStorage.setItem('cipherbank_token', data.token);
        localStorage.setItem('cipherbank_token_expiry', tokenExpirationMillis.toString());

        const userData = {
          username: data.username || formData.username,
          name: data.name || data.username,
          roles: data.roles || ['ROLE_USER']
        };
        setUser(userData);
        localStorage.setItem('cipherbank_user', JSON.stringify(userData));

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
        showNotification(`Welcome ${data.name || data.username}!`, 'success');
        setCurrentView('dashboard');
      } else {
        haptics.error();
        let errorMessage;
        switch (response.status) {
          case 400: errorMessage = data?.message || 'Invalid request. Please check your input.'; break;
          case 401: errorMessage = 'Invalid username or password. Please try again.'; break;
          case 403: errorMessage = 'Access forbidden. IP not whitelisted or account inactive.'; break;
          case 404: errorMessage = 'Service not found. Please contact support.'; break;
          case 500: errorMessage = 'Server error. Please try again later.'; break;
          default: errorMessage = data?.message || `Authentication failed (Error ${response.status})`;
        }
        showNotification(errorMessage, 'error');
      }
    } catch (error) {
      haptics.error();
      showNotification('Connection error. Please check your internet connection and try again.', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="login-container">
      {/* Background Effects */}
      <div className="login-background">
        <div className="bg-orb bg-orb-1"></div>
        <div className="bg-orb bg-orb-2"></div>
      </div>

      <div className="login-content">
        {/* Logo */}
        <div className="login-logo">
          <div className="logo-icon">
            <Shield className="w-10 h-10 text-white" />
          </div>
          <h1 className="logo-title">CipherBank</h1>
          <p className="logo-subtitle">Secure Statement Parsing</p>
        </div>

        {/* Login Card */}
        <div className="lg-card login-card">
          <h2 className="login-heading">Sign In</h2>

          <form onSubmit={handleSubmit} className="login-form">
            <div className="form-group">
              <input
                type="text"
                placeholder="Username"
                value={formData.username}
                onChange={(e) => setFormData({...formData, username: e.target.value})}
                onFocus={() => haptics.light()}
                className="lg-input"
                required
                minLength={3}
                maxLength={50}
              />
            </div>

            <div className="form-group">
              <input
                type="password"
                placeholder="Password"
                value={formData.password}
                onChange={(e) => setFormData({...formData, password: e.target.value})}
                onFocus={() => haptics.light()}
                className="lg-input"
                required
                minLength={CONFIG.PASSWORD_MIN_LENGTH}
              />
            </div>

            <div className="auto-refresh-option">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={enableAutoRefresh}
                  onChange={(e) => {
                    haptics.selection();
                    setEnableAutoRefresh(e.target.checked);
                  }}
                  className="checkbox-input"
                />
                <div className="checkbox-content">
                  <span className="checkbox-title">
                    <RefreshCw className="w-4 h-4" />
                    Remember Session
                  </span>
                  <span className="checkbox-warning">
                    <AlertTriangle className="w-3 h-3" />
                    Trusted devices only
                  </span>
                </div>
              </label>
            </div>

            <button type="submit" className="lg-btn lg-btn-primary w-full">
              Sign In
            </button>
          </form>

          <div className="login-footer">
            <p>CipherBank v3.0</p>
          </div>
        </div>
      </div>
    </div>
  );
};

// ==================== DASHBOARD LAYOUT ====================
const DashboardLayout = ({ currentView, setCurrentView, user, token, tokenExpiry, setUser, setToken, setTokenExpiry, handleLogout, showNotification, isMenuOpen, setIsMenuOpen, checkAndRefreshToken, autoRefreshEnabled, setAutoRefreshEnabled, credentialsRef, theme, setTheme }) => {
  useEffect(() => {
    if (!token || !tokenExpiry) {
      setCurrentView('login');
      return;
    }
    if (isTokenExpired(tokenExpiry)) {
      clearSessionAndRedirect(setCurrentView, setUser, setToken, setTokenExpiry, showNotification, currentView);
    }
  }, [currentView, token, tokenExpiry]);

  const toggleAutoRefresh = () => {
    if (autoRefreshEnabled) {
      setAutoRefreshEnabled(false);
      credentialsRef.current = null;
      localStorage.removeItem('cipherbank_credentials');
      showNotification('Auto-refresh disabled', 'info');
    } else {
      showNotification('Please re-login to enable auto-refresh', 'info');
    }
  };

  return (
    <div className="dashboard-layout">
      {/* Desktop Sidebar */}
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

      {/* Main Content */}
      <div className="main-content">
        <Header user={user} setIsMenuOpen={setIsMenuOpen} currentView={currentView} />
        <main className="content-area">
          {currentView === 'dashboard' && <Dashboard token={token} user={user} showNotification={showNotification} checkAndRefreshToken={checkAndRefreshToken} />}
          {currentView === 'upload' && <UploadView token={token} showNotification={showNotification} setCurrentView={setCurrentView} setUser={setUser} setToken={setToken} setTokenExpiry={setTokenExpiry} user={user} checkAndRefreshToken={checkAndRefreshToken} />}
          {currentView === 'statements' && <StatementsView token={token} showNotification={showNotification} checkAndRefreshToken={checkAndRefreshToken} />}
          {currentView === 'users' && <UserManagementView token={token} showNotification={showNotification} setCurrentView={setCurrentView} setUser={setUser} setToken={setToken} setTokenExpiry={setTokenExpiry} checkAndRefreshToken={checkAndRefreshToken} />}
          {currentView === 'changepassword' && (
            <SettingsView
              token={token}
              user={user}
              showNotification={showNotification}
              setCurrentView={setCurrentView}
              setUser={setUser}
              setToken={setToken}
              setTokenExpiry={setTokenExpiry}
              checkAndRefreshToken={checkAndRefreshToken}
              autoRefreshEnabled={autoRefreshEnabled}
              setAutoRefreshEnabled={setAutoRefreshEnabled}
              handleLogout={handleLogout}
              credentialsRef={credentialsRef}
              theme={theme}
              setTheme={setTheme}
            />
          )}
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
    { id: 'upload', label: 'Upload', icon: Upload },
    { id: 'statements', label: 'Statements', icon: FileText },
    ...(isAdmin ? [{ id: 'users', label: 'Users', icon: Users }] : []),
    { id: 'changepassword', label: 'Settings', icon: Key },
  ];

  return (
    <>
      {/* Mobile Overlay */}
      {isMenuOpen && (
        <div
          className="sidebar-overlay"
          onClick={() => setIsMenuOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Sidebar */}
      <aside
        className={`sidebar ${isMenuOpen ? 'sidebar-open' : ''}`}
        role="navigation"
        aria-label="Main navigation"
      >
        <button
          className="sidebar-close"
          onClick={() => setIsMenuOpen(false)}
          aria-label="Close navigation menu"
          type="button"
        >
          <X className="w-6 h-6" />
        </button>

        {/* Logo */}
        <div className="sidebar-logo">
          <div className="sidebar-logo-icon">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h2 className="sidebar-logo-title">CipherBank</h2>
            <p className="sidebar-logo-subtitle">Automated Parsing</p>
          </div>
        </div>

        {/* User Info */}
        <div className="sidebar-user">
          <div className="sidebar-user-info">
            <div className="sidebar-user-avatar">
              <Users className="w-5 h-5" />
            </div>
            <div className="sidebar-user-details">
              <p className="sidebar-user-name">{user?.name || user?.username || 'User'}</p>
              <p className="sidebar-user-role">{isAdmin ? 'Administrator' : 'User'}</p>
            </div>
          </div>

          <button
            onClick={() => { haptics.light(); toggleAutoRefresh(); }}
            className={`auto-refresh-toggle ${autoRefreshEnabled ? 'active' : ''}`}
            type="button"
            aria-pressed={autoRefreshEnabled}
          >
            <span className="toggle-label">
              <RefreshCw className="w-3 h-3" />
              Auto-Refresh
            </span>
            <span className="toggle-status">{autoRefreshEnabled ? 'ON' : 'OFF'}</span>
          </button>
        </div>

        {/* Navigation */}
        <nav className="sidebar-nav" role="menubar">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentView === item.id;

            return (
              <button
                key={item.id}
                onClick={() => {
                  haptics.light();
                  setCurrentView(item.id);
                  setIsMenuOpen(false);
                }}
                className={`nav-item ${isActive ? 'nav-item-active' : ''}`}
                role="menuitem"
                aria-current={isActive ? 'page' : undefined}
                type="button"
              >
                <Icon className="nav-item-icon" />
                <span className="nav-item-label">{item.label}</span>
                {isActive && <ChevronRight className="nav-item-arrow" />}
              </button>
            );
          })}
        </nav>

        {/* Logout */}
        <button
          onClick={() => { haptics.medium(); handleLogout(); }}
          className="sidebar-logout"
          type="button"
        >
          <LogOut className="w-5 h-5" />
          <span>Logout</span>
        </button>
      </aside>
    </>
  );
};

// ==================== HEADER COMPONENT ====================
// NOTE: This header is HIDDEN on mobile via CSS (ios26-mobile-fixes.css)
// On mobile, the welcome card serves as the header, navigation is via bottom tab bar
const Header = ({ user, setIsMenuOpen, currentView }) => {
  // Get the current page title based on view
  const getPageTitle = () => {
    const titles = {
      dashboard: 'Dashboard',
      upload: 'Upload Statement',
      statements: 'Statements',
      users: 'User Management',
      changepassword: 'Settings'
    };
    return titles[currentView] || 'Dashboard';
  };

  return (
    <header className="header">
      <button
        onClick={() => { haptics.light(); setIsMenuOpen(true); }}
        className="header-menu-btn"
        aria-label="Open navigation menu"
        type="button"
      >
        <Menu className="w-6 h-6" />
      </button>
      <div className="header-content">
        <h1 className="header-title">{getPageTitle()}</h1>
        <p className="header-subtitle">
          {user?.roles?.includes('ROLE_ADMIN') ? 'Administrator' : 'User'} • {user?.name || user?.username}
        </p>
      </div>
    </header>
  );
};

// ==================== DASHBOARD VIEW ====================
const Dashboard = ({ token, user, showNotification, checkAndRefreshToken }) => {
  const [stats, setStats] = useState({
    totalUploads: 0,
    totalTransactions: 0,
    successRate: '0%',
    thisMonth: 0,
    recentUploads: []
  });

  useEffect(() => {
    setStats({
      totalUploads: 127,
      totalTransactions: 1543,
      successRate: '98.5%',
      thisMonth: 45,
      recentUploads: [
        { id: 1, bank: 'IOB', filename: 'statement_nov_2024.csv', date: '2024-11-28', rows: 45, status: 'success' },
        { id: 2, bank: 'KGB', filename: 'kerala_gramin_oct.xlsx', date: '2024-11-27', rows: 89, status: 'success' },
        { id: 3, bank: 'Indian Bank', filename: 'indianbank_sep.xlsx', date: '2024-11-26', rows: 67, status: 'success' },
      ]
    });
  }, [token]);

  // Get time-based greeting
  const getGreeting = () => {
    const hour = new Date().getHours();
    if (hour < 12) return 'Good Morning';
    if (hour < 17) return 'Good Afternoon';
    return 'Good Evening';
  };

  // Get user's display name (capitalize properly)
  const getDisplayName = () => {
    const name = user?.name || user?.username || 'User';
    return name.charAt(0).toUpperCase() + name.slice(1).toLowerCase();
  };

  return (
    <div className="dashboard">
      {/* Welcome Header - iOS 26 Style */}
      <div className="welcome-header">
        <div className="welcome-orb" aria-hidden="true"></div>
        <h1 className="welcome-title">{getGreeting()}, {getDisplayName()}</h1>
        <p className="welcome-subtitle">Your statement processing overview at a glance</p>
      </div>

      {/* Stats Grid - 2 cols mobile, 4 cols desktop */}
      <div className="stats-grid">
        {[
          { title: 'Uploads', value: stats.totalUploads, icon: Upload, color: 'blue' },
          { title: 'Transactions', value: stats.totalTransactions, icon: ArrowUpDown, color: 'purple' },
          { title: 'Success Rate', value: stats.successRate, icon: TrendingUp, color: 'green' },
          { title: 'This Month', value: stats.thisMonth, icon: Calendar, color: 'orange' }
        ].map((stat, index) => {
          const Icon = stat.icon;
          return (
            <div key={stat.title} className="stat-card" style={{ animationDelay: `${index * 0.1}s` }}>
              <div className={`stat-icon stat-icon-${stat.color}`}>
                <Icon className="w-6 h-6" />
              </div>
              <div className="stat-content">
                <p className="stat-title">{stat.title}</p>
                <p className="stat-value">{stat.value}</p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Recent Uploads Table */}
      <div className="lg-card">
        <div className="card-header">
          <h2 className="card-title">Recent Uploads</h2>
          <button className="card-action">
            View All <ChevronRight className="w-4 h-4" />
          </button>
        </div>

        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Bank</th>
                <th>Filename</th>
                <th>Date</th>
                <th>Rows</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {stats.recentUploads.map((upload) => (
                <tr key={upload.id}>
                  <td>
                    <div className="table-cell-with-icon">
                      <div className="table-icon">
                        <FileText className="w-4 h-4" />
                      </div>
                      <span>{upload.bank}</span>
                    </div>
                  </td>
                  <td>{upload.filename}</td>
                  <td>{upload.date}</td>
                  <td>{upload.rows}</td>
                  <td>
                    <span className="badge badge-success">
                      <CheckCircle className="w-3 h-3" />
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

  const handleDragOver = (e) => { e.preventDefault(); setIsDragging(true); };
  const handleDragLeave = () => { setIsDragging(false); };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) {
      haptics.medium();
      const validation = validateFile(file);
      if (validation.valid) {
        haptics.success();
        setUploadData({ ...uploadData, file });
      } else {
        haptics.error();
        validation.errors.forEach(error => showNotification(error, 'error'));
      }
    }
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file) {
      haptics.medium();
      const validation = validateFile(file);
      if (validation.valid) {
        haptics.success();
        setUploadData({ ...uploadData, file });
      } else {
        haptics.error();
        validation.errors.forEach(error => showNotification(error, 'error'));
      }
    }
  };

  const handleUpload = async () => {
    if (!uploadData.file) {
      haptics.warning();
      showNotification('Please select a file', 'error');
      return;
    }

    if (uploadData.parserKey === 'iob' && !uploadData.accountNo) {
      haptics.warning();
      showNotification('Account number is required for IOB statements', 'error');
      return;
    }

    const tokenValid = await checkAndRefreshToken();
    if (!tokenValid) return;

    haptics.medium();
    setUploading(true);

    try {
      const formData = new FormData();
      formData.append('file', uploadData.file);
      formData.append('parserKey', uploadData.parserKey);
      formData.append('username', uploadData.username);
      if (uploadData.accountNo) formData.append('accountNo', uploadData.accountNo);

      const response = await fetch(`${API_BASE_URL}/statements/upload`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
        body: formData
      });

      if (response.status === 401 || response.status === 403) {
        haptics.error();
        showNotification('Session expired. Please login again.', 'error');
        setTimeout(() => clearSessionAndRedirect(setCurrentView, setUser, setToken, setTokenExpiry, null, 'upload'), 1500);
        return;
      }

      const data = await response.json();

      if (response.ok) {
        haptics.success();
        showNotification(`Upload successful! ${data.rowsParsed} rows processed`, 'success');
        setUploadData({ ...uploadData, file: null, accountNo: '' });
      } else {
        haptics.error();
        showNotification(data.message || 'Upload failed', 'error');
      }
    } catch (error) {
      haptics.error();
      showNotification('Upload failed. Please try again.', 'error');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="upload-view">
      <div className="lg-card">
        <h2 className="card-title-lg">Upload Bank Statement</h2>
        <p className="card-subtitle">Upload CSV, XLS, XLSX, or PDF (Max 10MB)</p>

        {/* Bank Selection */}
        <div className="form-section">
          <label className="form-label">Select Bank</label>
          <div className="bank-grid">
            {['iob', 'kgb', 'indianbank'].map((bank) => (
              <button
                key={bank}
                onClick={() => { haptics.selection(); setUploadData({ ...uploadData, parserKey: bank }); }}
                className={`bank-option ${uploadData.parserKey === bank ? 'bank-option-active' : ''}`}
              >
                <span className="bank-name">
                  {bank === 'iob' && 'Indian Overseas Bank'}
                  {bank === 'kgb' && 'Kerala Gramin Bank'}
                  {bank === 'indianbank' && 'Indian Bank'}
                </span>
                <span className="bank-format">
                  {bank === 'iob' && 'CSV Format'}
                  {bank === 'kgb' && 'XLS/XLSX'}
                  {bank === 'indianbank' && 'XLS/XLSX'}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Account Number for IOB */}
        {uploadData.parserKey === 'iob' && (
          <div className="form-section">
            <label className="form-label">Account Number <span className="required">*</span></label>
            <input
              type="text"
              value={uploadData.accountNo}
              onChange={(e) => setUploadData({ ...uploadData, accountNo: e.target.value })}
              onFocus={() => haptics.light()}
              placeholder="Enter account number"
              className="lg-input"
              required
            />
          </div>
        )}

        {/* File Drop Zone */}
        <div
          className={`file-drop-zone ${uploadData.file ? 'has-file' : ''} ${isDragging ? 'dragging' : ''}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          <div className={`drop-icon ${uploadData.file ? 'success' : ''}`}>
            {uploadData.file ? <CheckCircle className="w-8 h-8" /> : <Upload className="w-8 h-8" />}
          </div>

          {uploadData.file ? (
            <>
              <p className="file-name">{uploadData.file.name}</p>
              <p className="file-size">{(uploadData.file.size / 1024).toFixed(2)} KB</p>
              <button onClick={() => { haptics.light(); setUploadData({ ...uploadData, file: null }); }} className="remove-file">
                Remove file
              </button>
            </>
          ) : (
            <>
              <p className="drop-text">Drop your file here</p>
              <p className="drop-or">or</p>
              <label className="browse-btn">
                <span className="lg-btn lg-btn-secondary">Browse Files</span>
                <input type="file" onChange={handleFileSelect} accept={CONFIG.ALLOWED_FILE_EXTENSIONS.join(',')} className="hidden" />
              </label>
              <p className="drop-hint">CSV, XLS, XLSX, PDF (Max 10MB)</p>
            </>
          )}
        </div>

        {/* Upload Button */}
        <button
          onClick={() => { haptics.medium(); handleUpload(); }}
          disabled={!uploadData.file || uploading}
          className={`lg-btn lg-btn-primary w-full ${(!uploadData.file || uploading) ? 'disabled' : ''}`}
        >
          {uploading ? (
            <span className="btn-loading">
              <span className="spinner"></span>
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
    <div className="statements-view">
      <div className="lg-card">
        <div className="card-header-complex">
          <div>
            <h2 className="card-title-lg">Statement History</h2>
            <p className="card-subtitle">View and manage uploaded statements</p>
          </div>
          <div className="search-box">
            <Search className="search-icon" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              onFocus={() => haptics.light()}
              placeholder="Search..."
              className="search-input"
            />
          </div>
        </div>

        {/* Filter Tabs */}
        <div className="filter-tabs">
          {['all', 'processed', 'pending'].map((status) => (
            <button
              key={status}
              onClick={() => { haptics.selection(); setFilter(status); }}
              className={`filter-tab ${filter === status ? 'active' : ''}`}
            >
              {status.charAt(0).toUpperCase() + status.slice(1)}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="loading-state">
            <div className="loading-spinner"></div>
            <p>Loading statements...</p>
          </div>
        ) : (
          <div className="table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Bank</th>
                  <th>Filename</th>
                  <th>Transactions</th>
                  <th>Amount</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredStatements.map((stmt) => (
                  <tr key={stmt.id}>
                    <td>{stmt.date}</td>
                    <td>
                      <span className="badge badge-info">
                        <FileText className="w-3 h-3" />
                        {stmt.bank}
                      </span>
                    </td>
                    <td className="font-medium">{stmt.filename}</td>
                    <td>{stmt.transactions}</td>
                    <td className="font-semibold">₹{stmt.amount.toLocaleString('en-IN')}</td>
                    <td>
                      <span className={`badge ${stmt.status === 'processed' ? 'badge-success' : 'badge-warning'}`}>
                        {stmt.status === 'processed' ? <CheckCircle className="w-3 h-3" /> : <Activity className="w-3 h-3" />}
                        {stmt.status}
                      </span>
                    </td>
                    <td>
                      <button onClick={() => { haptics.light(); showNotification('Download coming soon!', 'info'); }} className="action-btn">
                        <Download className="w-5 h-5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {!loading && filteredStatements.length === 0 && (
          <div className="empty-state">
            <FileText className="empty-icon" />
            <p>No statements found</p>
          </div>
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

  useEffect(() => {
    setPasswordStrength(calculatePasswordStrength(newUser.password));
  }, [newUser.password]);

  const handleCreateUser = async (e) => {
    e.preventDefault();

    if (newUser.username.length < 3) {
      showNotification('Username must be at least 3 characters', 'error');
      return;
    }
    if (newUser.password.length < CONFIG.PASSWORD_MIN_LENGTH) {
      showNotification(`Password must be at least ${CONFIG.PASSWORD_MIN_LENGTH} characters`, 'error');
      return;
    }
    if (newUser.password !== newUser.confirmPassword) {
      showNotification('Passwords do not match', 'error');
      return;
    }
    if (passwordStrength < 40) {
      showNotification('Password is too weak', 'error');
      return;
    }

    const tokenValid = await checkAndRefreshToken();
    if (!tokenValid) return;

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

      const data = await response.json().catch(() => ({}));

      if (response.ok) {
        showNotification(`User "${newUser.username}" created successfully!`, 'success');
        setNewUser({ username: '', password: '', confirmPassword: '', roleIds: [2], selectedRole: 'user' });
      } else {
        showNotification(data?.message || 'Failed to create user', 'error');
      }
    } catch (error) {
      showNotification('Failed to create user', 'error');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="user-management-view">
      <div className="lg-card">
        <div className="card-header-with-icon">
          <div className="header-icon purple">
            <Users className="w-8 h-8" />
          </div>
          <div>
            <h2 className="card-title-lg">User Management</h2>
            <p className="card-subtitle">Create new user accounts</p>
          </div>
        </div>

        <form onSubmit={handleCreateUser} className="user-form">
          <div className="form-section">
            <label className="form-label">Username <span className="required">*</span></label>
            <input
              type="text"
              value={newUser.username}
              onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
              placeholder="Enter username"
              className="lg-input"
              required
              minLength={3}
            />
          </div>

          <div className="form-section">
            <label className="form-label">Role <span className="required">*</span></label>
            <div className="role-grid">
              <button
                type="button"
                onClick={() => { haptics.selection(); setNewUser({ ...newUser, selectedRole: 'user', roleIds: [2] }); }}
                className={`role-option ${newUser.selectedRole === 'user' ? 'active' : ''}`}
              >
                <div className="role-icon blue"><Users className="w-5 h-5" /></div>
                <div className="role-info">
                  <span className="role-name">User</span>
                  <span className="role-desc">Standard access</span>
                </div>
              </button>
              <button
                type="button"
                onClick={() => { haptics.selection(); setNewUser({ ...newUser, selectedRole: 'admin', roleIds: [1, 2] }); }}
                className={`role-option ${newUser.selectedRole === 'admin' ? 'active' : ''}`}
              >
                <div className="role-icon purple"><Shield className="w-5 h-5" /></div>
                <div className="role-info">
                  <span className="role-name">Admin</span>
                  <span className="role-desc">Full access</span>
                </div>
              </button>
            </div>
          </div>

          <div className="form-section">
            <div className="form-label-row">
              <label className="form-label">Password <span className="required">*</span></label>
              <button type="button" onClick={() => {
                const pwd = generateSecurePassword();
                setNewUser({ ...newUser, password: pwd, confirmPassword: pwd });
                showNotification('Password generated!', 'success');
              }} className="generate-btn">
                <RefreshCw className="w-4 h-4" /> Generate
              </button>
            </div>
            <div className="input-with-actions">
              <input
                type={showPassword ? 'text' : 'password'}
                value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                placeholder="Enter password"
                className="lg-input"
                required
              />
              <button type="button" onClick={() => { haptics.light(); navigator.clipboard.writeText(newUser.password); showNotification('Copied!', 'success'); }} className="input-action"><Copy className="w-5 h-5" /></button>
              <button type="button" onClick={() => { haptics.light(); setShowPassword(!showPassword); }} className="input-action">
                {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
            {newUser.password && (
              <div className="password-strength">
                <div className="strength-bar">
                  <div className={`strength-fill ${passwordStrength < 40 ? 'weak' : passwordStrength < 70 ? 'medium' : 'strong'}`} style={{ width: `${passwordStrength}%` }}></div>
                </div>
                <span className={`strength-text ${passwordStrength < 40 ? 'weak' : passwordStrength < 70 ? 'medium' : 'strong'}`}>
                  {passwordStrength < 40 ? 'Weak' : passwordStrength < 70 ? 'Medium' : 'Strong'}
                </span>
              </div>
            )}
          </div>

          <div className="form-section">
            <label className="form-label">Confirm Password <span className="required">*</span></label>
            <div className="input-with-actions">
              <input
                type={showConfirmPassword ? 'text' : 'password'}
                value={newUser.confirmPassword}
                onChange={(e) => setNewUser({ ...newUser, confirmPassword: e.target.value })}
                placeholder="Confirm password"
                className="lg-input"
                required
              />
              <button type="button" onClick={() => { haptics.light(); setShowConfirmPassword(!showConfirmPassword); }} className="input-action">
                {showConfirmPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
            {newUser.confirmPassword && (
              <div className={`password-match ${newUser.password === newUser.confirmPassword ? 'match' : 'no-match'}`}>
                {newUser.password === newUser.confirmPassword ? <><CheckCircle className="w-4 h-4" /> Passwords match</> : <><XCircle className="w-4 h-4" /> Passwords don't match</>}
              </div>
            )}
          </div>

          <button type="submit" disabled={creating || passwordStrength < 40} className={`lg-btn lg-btn-primary w-full ${creating || passwordStrength < 40 ? 'disabled' : ''}`}>
            {creating ? <><span className="spinner"></span> Creating...</> : 'Create User'}
          </button>
        </form>
      </div>
    </div>
  );
};

// ==================== SETTINGS VIEW (iOS 26 STYLE) ====================
// Replaces ChangePasswordView with full settings including Appearance
const SettingsView = ({
  token,
  user,
  showNotification,
  setCurrentView,
  setUser,
  setToken,
  setTokenExpiry,
  checkAndRefreshToken,
  autoRefreshEnabled,
  setAutoRefreshEnabled,
  handleLogout,
  credentialsRef,
  theme,
  setTheme
}) => {
  const [showAppearancePicker, setShowAppearancePicker] = useState(false);

  // Password change state
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

  // Haptics state
  const [hapticsEnabled, setHapticsEnabled] = useState(() => {
    const saved = localStorage.getItem('cipherbank_haptics');
    return saved !== 'false'; // Default to true
  });

  // Get resolved theme for display
  const resolvedTheme = theme === 'system'
    ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
    : theme;

  // Toggle haptics
  const toggleHaptics = (enabled) => {
    setHapticsEnabled(enabled);
    localStorage.setItem('cipherbank_haptics', enabled.toString());
    if (enabled) {
      haptics.enable();
      haptics.success();
    } else {
      haptics.disable();
    }
  };

  // Toggle auto-refresh
  const toggleAutoRefresh = () => {
    if (autoRefreshEnabled) {
      setAutoRefreshEnabled(false);
      if (credentialsRef) credentialsRef.current = null;
      localStorage.removeItem('cipherbank_credentials');
      showNotification('Auto-refresh disabled', 'info');
    } else {
      showNotification('Please re-login to enable auto-refresh', 'info');
    }
    haptics.selection();
  };

  // Password strength calculation
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

  useEffect(() => {
    setPasswordStrength(calculatePasswordStrength(passwordData.newPassword));
  }, [passwordData.newPassword]);

  // Handle password change
  const handleChangePassword = async (e) => {
    e.preventDefault();
    haptics.medium();

    if (!passwordData.currentPassword) {
      showNotification('Enter current password', 'error');
      haptics.error();
      return;
    }
    if (passwordData.newPassword.length < CONFIG.PASSWORD_MIN_LENGTH) {
      showNotification(`New password must be at least ${CONFIG.PASSWORD_MIN_LENGTH} characters`, 'error');
      haptics.error();
      return;
    }
    if (passwordData.newPassword !== passwordData.confirmNewPassword) {
      showNotification('Passwords do not match', 'error');
      haptics.error();
      return;
    }
    if (passwordStrength < 40) {
      showNotification('Password is too weak', 'error');
      haptics.error();
      return;
    }
    if (passwordData.currentPassword === passwordData.newPassword) {
      showNotification('New password must be different', 'error');
      haptics.error();
      return;
    }

    const tokenValid = await checkAndRefreshToken();
    if (!tokenValid) return;

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

      const data = await response.json().catch(() => ({}));

      if (response.ok) {
        haptics.success();
        showNotification('Password changed successfully!', 'success');
        setPasswordData({ currentPassword: '', newPassword: '', confirmNewPassword: '' });
      } else if (response.status === 401) {
        haptics.error();
        localStorage.removeItem('cipherbank_token');
        localStorage.removeItem('cipherbank_user');
        localStorage.removeItem('cipherbank_token_expiry');
        setToken(null);
        setUser(null);
        setTokenExpiry(null);
        setCurrentView('login');
        showNotification('Session expired. Please login again.', 'error');
      } else {
        haptics.error();
        showNotification(data.message || 'Failed to change password', 'error');
      }
    } catch (error) {
      haptics.error();
      showNotification('Network error. Please try again.', 'error');
    } finally {
      setChanging(false);
    }
  };

  const getStrengthClass = (strength) => {
    if (strength < 40) return 'weak';
    if (strength < 70) return 'medium';
    return 'strong';
  };

  const getStrengthText = (strength) => {
    if (strength < 40) return 'Weak';
    if (strength < 70) return 'Medium';
    return 'Strong';
  };

  const getThemeLabel = () => {
    switch (theme) {
      case 'light': return 'Light';
      case 'dark': return 'Dark';
      default: return 'System';
    }
  };

  return (
    <div className="settings-view" style={{ padding: 'var(--space-4, 16px)' }}>
      {/* User Info Banner */}
      <div className="user-info-banner" style={{ marginBottom: 'var(--space-6, 24px)' }}>
        <div className="user-avatar">
          <User className="w-5 h-5" />
        </div>
        <div>
          <p className="user-label">Signed in as</p>
          <p className="user-name">{user?.name || user?.username || 'User'}</p>
        </div>
      </div>

      {/* Appearance Section */}
      <div className="settings-section">
        <div className="settings-section-title">Appearance</div>
        <div className="settings-group">
          <button
            type="button"
            className="settings-item"
            onClick={() => {
              haptics.light();
              setShowAppearancePicker(true);
            }}
          >
            <div className="settings-item-left">
              <div className="settings-item-icon purple">
                <Palette className="w-5 h-5" />
              </div>
              <div className="settings-item-content">
                <div className="settings-item-title">Theme</div>
                <div className="settings-item-subtitle">
                  {theme === 'system'
                    ? `System (${resolvedTheme === 'dark' ? 'Dark' : 'Light'})`
                    : getThemeLabel()}
                </div>
              </div>
            </div>
            <div className="settings-item-right">
              <span className="settings-item-value">{getThemeLabel()}</span>
              <ChevronRight className="w-5 h-5 settings-item-chevron" />
            </div>
          </button>

          <div className="settings-item">
            <div className="settings-item-left">
              <div className="settings-item-icon orange">
                <Smartphone className="w-5 h-5" />
              </div>
              <div className="settings-item-content">
                <div className="settings-item-title">Haptic Feedback</div>
                <div className="settings-item-subtitle">Vibration on interactions</div>
              </div>
            </div>
            <div className="settings-item-right">
              <button
                type="button"
                role="switch"
                aria-checked={hapticsEnabled}
                className={`ios-toggle ${hapticsEnabled ? 'active' : ''}`}
                onClick={() => {
                  haptics.selection();
                  toggleHaptics(!hapticsEnabled);
                }}
              >
                <span className="ios-toggle-thumb" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Session Section */}
      <div className="settings-section">
        <div className="settings-section-title">Session</div>
        <div className="settings-group">
          <div className="settings-item">
            <div className="settings-item-left">
              <div className="settings-item-icon green">
                <RefreshCw className="w-5 h-5" />
              </div>
              <div className="settings-item-content">
                <div className="settings-item-title">Auto-Refresh Token</div>
                <div className="settings-item-subtitle">Stay signed in automatically</div>
              </div>
            </div>
            <div className="settings-item-right">
              <button
                type="button"
                role="switch"
                aria-checked={autoRefreshEnabled}
                className={`ios-toggle ${autoRefreshEnabled ? 'active' : ''}`}
                onClick={toggleAutoRefresh}
              >
                <span className="ios-toggle-thumb" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Security Section - Password Change */}
      <div className="settings-section">
        <div className="settings-section-title">Security</div>
        <div className="settings-group" style={{ padding: 'var(--space-5, 20px)' }}>
          <form onSubmit={handleChangePassword} className="password-form">
            {/* Current Password */}
            <div className="form-group">
              <label className="form-label">Current Password</label>
              <div className="input-wrapper">
                <div className="input-icon"><Key className="w-5 h-5" /></div>
                <input
                  type={showCurrentPassword ? 'text' : 'password'}
                  value={passwordData.currentPassword}
                  onChange={(e) => setPasswordData({ ...passwordData, currentPassword: e.target.value })}
                  placeholder="Enter current password"
                  className="lg-input"
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => {
                    haptics.light();
                    setShowCurrentPassword(!showCurrentPassword);
                  }}
                  className="input-action"
                  aria-label={showCurrentPassword ? 'Hide password' : 'Show password'}
                >
                  {showCurrentPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            {/* New Password */}
            <div className="form-group">
              <label className="form-label">New Password</label>
              <div className="input-wrapper">
                <div className="input-icon"><Shield className="w-5 h-5" /></div>
                <input
                  type={showNewPassword ? 'text' : 'password'}
                  value={passwordData.newPassword}
                  onChange={(e) => setPasswordData({ ...passwordData, newPassword: e.target.value })}
                  placeholder="Enter new password"
                  className="lg-input"
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  onClick={() => {
                    haptics.light();
                    setShowNewPassword(!showNewPassword);
                  }}
                  className="input-action"
                  aria-label={showNewPassword ? 'Hide password' : 'Show password'}
                >
                  {showNewPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>

              {/* Password Strength */}
              {passwordData.newPassword && (
                <div className="password-strength">
                  <div className="strength-bar">
                    <div
                      className={`strength-fill ${getStrengthClass(passwordStrength)}`}
                      style={{ width: `${passwordStrength}%` }}
                    />
                  </div>
                  <span className={`strength-text ${getStrengthClass(passwordStrength)}`}>
                    {getStrengthText(passwordStrength)}
                  </span>
                </div>
              )}
            </div>

            {/* Confirm Password */}
            <div className="form-group">
              <label className="form-label">Confirm New Password</label>
              <div className="input-wrapper">
                <div className="input-icon"><Shield className="w-5 h-5" /></div>
                <input
                  type={showConfirmPassword ? 'text' : 'password'}
                  value={passwordData.confirmNewPassword}
                  onChange={(e) => setPasswordData({ ...passwordData, confirmNewPassword: e.target.value })}
                  placeholder="Confirm new password"
                  className="lg-input"
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  onClick={() => {
                    haptics.light();
                    setShowConfirmPassword(!showConfirmPassword);
                  }}
                  className="input-action"
                  aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                >
                  {showConfirmPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>

              {/* Password Match Indicator */}
              {passwordData.confirmNewPassword && (
                <div className={`password-match ${passwordData.newPassword === passwordData.confirmNewPassword ? 'match' : 'no-match'}`}>
                  {passwordData.newPassword === passwordData.confirmNewPassword
                    ? <><CheckCircle className="w-4 h-4" /> Passwords match</>
                    : <><XCircle className="w-4 h-4" /> Passwords don't match</>
                  }
                </div>
              )}
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={changing || passwordStrength < 40}
              className={`lg-btn lg-btn-primary w-full ${changing || passwordStrength < 40 ? 'disabled' : ''}`}
            >
              {changing ? (
                <>
                  <span className="spinner"></span> Changing Password...
                </>
              ) : 'Change Password'}
            </button>
          </form>

          {/* Security Tips */}
          <div className="security-tips">
            <AlertTriangle className="tips-icon" />
            <div>
              <div className="tips-title">Security Tips</div>
              <ul className="tips-list">
                <li>• Use a unique password for each account</li>
                <li>• Include letters, numbers & symbols</li>
                <li>• Avoid personal information</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* About Section */}
      <div className="settings-section">
        <div className="settings-section-title">About</div>
        <div className="settings-group">
          <div className="settings-item">
            <div className="settings-item-left">
              <div className="settings-item-icon gray">
                <Info className="w-5 h-5" />
              </div>
              <div className="settings-item-content">
                <div className="settings-item-title">CipherBank</div>
                <div className="settings-item-subtitle">Version 3.0.0</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Sign Out Button */}
      <div className="settings-section" style={{ marginTop: 'var(--space-8, 32px)' }}>
        <button
          type="button"
          onClick={() => {
            haptics.medium();
            handleLogout();
          }}
          className="lg-btn w-full"
          style={{
            background: 'rgba(255, 59, 48, 0.1)',
            color: 'var(--system-red, #FF3B30)',
            border: 'none'
          }}
        >
          <LogOut className="w-5 h-5" />
          Sign Out
        </button>
      </div>

      {/* Appearance Picker Modal */}
      {showAppearancePicker && (
        <div className="appearance-picker">
          <div
            className="appearance-picker-backdrop"
            onClick={() => setShowAppearancePicker(false)}
            aria-hidden="true"
          />
          <div className="appearance-picker-content" role="dialog" aria-modal="true" aria-labelledby="appearance-title">
            <div className="appearance-picker-header">
              <h2 id="appearance-title" className="appearance-picker-title">Appearance</h2>
              <button
                className="appearance-picker-close"
                onClick={() => setShowAppearancePicker(false)}
                aria-label="Close"
                type="button"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="appearance-picker-options">
              {[
                { id: 'system', label: 'System', icon: Smartphone },
                { id: 'light', label: 'Light', icon: Sun },
                { id: 'dark', label: 'Dark', icon: Moon }
              ].map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  onClick={() => {
                    setTheme(id);
                    setShowAppearancePicker(false);
                  }}
                  className={`appearance-option ${theme === id ? 'selected' : ''}`}
                  type="button"
                  aria-pressed={theme === id}
                >
                  <div className={`appearance-option-icon ${id}`}>
                    <Icon className="w-6 h-6" />
                  </div>
                  <span className="appearance-option-label">{label}</span>
                  {theme === id && (
                    <CheckCircle className="w-5 h-5" style={{ color: 'var(--system-blue)' }} />
                  )}
                </button>
              ))}
            </div>
            <div style={{
              padding: 'var(--space-4, 16px)',
              paddingTop: 0,
              fontSize: '13px',
              color: 'var(--label-secondary)',
              textAlign: 'center'
            }}>
              {theme === 'system'
                ? 'Appearance will match your device settings'
                : `${theme.charAt(0).toUpperCase() + theme.slice(1)} mode is always on`
              }
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default CipherBankUI;